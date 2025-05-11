import os
import re
import logging
import requests
import uuid
from bs4 import BeautifulSoup
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .base import BaseWorker

logger = logging.getLogger(__name__)

class PacketStormWorker(BaseWorker):
    """Worker for fetching exploit data from PacketStorm Security."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.base_url = "http://dl.packetstormsecurity.net"
        self.source_url = "http://dl.packetstormsecurity.net"
        self.exploit_pattern = r"(\d{4})-exploits"  # Pattern for exploit directories (YYMM-exploits)
        
        # Configure requests session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=5, pool_maxsize=5)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # CVE pattern for extraction
        self.cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
        
        # State file for tracking last update
        self.state_file = os.path.join(self.cache_dir, "state.json")
        self.last_update = self._load_state()
    
    @property
    def name(self) -> str:
        return "packetstorm"
    
    def _load_state(self) -> datetime:
        """Load the last update time from state file."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, 'r') as f:
                    state = json.load(f)
                    return datetime.fromisoformat(state.get('last_update', '2000-01-01T00:00:00'))
        except Exception as e:
            logger.error(f"Error loading state: {e}")
        return datetime(2000, 1, 1)
    
    def _save_state(self, last_update: datetime):
        """Save the last update time to state file."""
        try:
            state = {
                'last_update': last_update.isoformat()
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def _make_request(self, url: str, timeout: int = 30) -> Optional[requests.Response]:
        """Make a rate-limited request with retries."""
        try:
            logger.info(f"Making request to {url}")
            time.sleep(2.0)  # Rate limiting delay
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            logger.debug(f"Request successful: {url}")
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def _get_exploit_directories(self) -> List[str]:
        """Fetch and parse the main index page to extract exploit directories."""
        try:
            logger.info(f"Fetching exploit directories from {self.base_url}")
            response = self._make_request(self.base_url)
            if not response:
                logger.error("Failed to fetch main index page")
                return []
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links that match the exploit directory pattern
            exploit_dirs = []
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and re.match(self.exploit_pattern, href):
                    exploit_dirs.append(href)
            
            if not exploit_dirs:
                logger.warning("No exploit directories found in the response")
                return []
            
            # Sort in reverse chronological order (newest first)
            exploit_dirs.sort(reverse=True)
            
            logger.info(f"Found {len(exploit_dirs)} exploit directories")
            return exploit_dirs
            
        except Exception as e:
            logger.error(f"Error fetching exploit directories: {e}")
            return []
    
    def _get_exploits_from_directory(self, directory_url: str) -> List[Dict[str, Any]]:
        """Fetch and parse exploits from a specific directory."""
        try:
            # Fetch the directory page
            full_url = f"{self.base_url}/{directory_url}"
            response = self._make_request(full_url)
            if not response:
                return []
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links that might be exploits
            exploits = []
            exploit_extensions = ['.txt', '.tgz', '.zip', '.tar.gz', '.html', '.pl', '.py', '.c', '.sh']
            
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and any(href.lower().endswith(ext) for ext in exploit_extensions):
                    exploits.append({
                        'url': f"{self.base_url}/{directory_url}/{href}",
                        'filename': href,
                        'directory': directory_url
                    })
            
            # Process exploits concurrently using a thread pool
            processed_exploits = []
            with ThreadPoolExecutor(max_workers=5) as executor:
                # Submit all exploit processing tasks
                future_to_exploit = {
                    executor.submit(self._process_exploit, exploit): exploit 
                    for exploit in exploits
                }
                
                # Process completed tasks as they finish
                total = len(future_to_exploit)
                completed = 0
                for future in as_completed(future_to_exploit):
                    exploit = future_to_exploit[future]
                    completed += 1
                    try:
                        exploit_info = future.result()
                        if exploit_info:
                            processed_exploits.append(exploit_info)
                            logger.info(f"Progress in {directory_url}: {completed}/{total} exploits processed")
                    except Exception as e:
                        logger.error(f"Error processing exploit {exploit['url']}: {e}")
            
            logger.info(f"Processed {len(processed_exploits)} exploits from {directory_url}")
            return processed_exploits
            
        except Exception as e:
            logger.error(f"Error fetching exploits from directory {directory_url}: {e}")
            return []
    
    def _generate_vrip_id(self) -> str:
        """Generate a unique VRIP identifier for vulnerabilities without CVE IDs."""
        unique_id = uuid.uuid4().hex[:15].upper()
        return f"VRIP-{unique_id}"
    
    def _process_exploit(self, exploit: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process an exploit to extract vulnerability information."""
        try:
            # If it's a text file, we can try to download and analyze it
            exploit_content = None
            if exploit['filename'].lower().endswith('.txt'):
                response = self._make_request(exploit['url'])
                if response:
                    content = response.text
                    exploit_content = content
                else:
                    content = exploit['filename']
            else:
                # For non-text files, we'll just use the filename for analysis
                content = exploit['filename']
            
            # Extract information from the content
            
            # Try to find a CVE ID
            cve_match = self.cve_pattern.search(content)
            cve_id = cve_match.group(0).upper() if cve_match else None
            
            # Try to extract a title, use filename if not found
            title_match = re.search(r"(?i)title:?\s*(.+?)(?:\n|$)", content)
            title = title_match.group(1).strip() if title_match else exploit['filename']
            
            # Extract all fields starting with * or @ for enriched description
            special_fields = []
            if exploit_content:
                for line in exploit_content.split('\n'):
                    line = line.strip()
                    if line.startswith('*') or line.startswith('@'):
                        special_fields.append(line)
            
            # Try to extract a description
            desc_match = re.search(r"(?i)description:?\s*(.+?)(?:\n\n|$)", content)
            base_description = desc_match.group(1).strip() if desc_match else f"Exploit for {title}"
            
            # Combine base description with special fields
            if special_fields:
                description = base_description + "\n\n" + "\n".join(special_fields)
            else:
                description = base_description
            
            # Try to extract affected product/version
            product_match = re.search(r"(?i)affected:?\s*(.+?)(?:\n|$)", content)
            product = product_match.group(1).strip() if product_match else None
            
            # If no product found, try to extract from title or filename
            if not product and title:
                # Common patterns: "Product Version Vulnerability Type"
                # Extract the first part before common vulnerability words
                vuln_keywords = ['vulnerability', 'exploit', 'overflow', 'injection', 'traversal', 
                               'xss', 'csrf', 'rce', 'remote', 'local', 'privilege', 'escalation']
                
                parts = re.split(r'\s+', title)
                product_parts = []
                for part in parts:
                    if any(keyword.lower() in part.lower() for keyword in vuln_keywords):
                        break
                    product_parts.append(part)
                
                if product_parts:
                    product = ' '.join(product_parts)
            
            # Determine the date from the directory name (format: YYMM-exploits)
            year_month = exploit['directory'].split('-')[0]
            if len(year_month) == 4:  # YYMM format
                year = int("20" + year_month[:2])  # Assuming 20xx
                month = int(year_month[2:])
                date_str = f"{year}-{month:02d}-01"  # Use first day of month as approximate date
            else:
                date_str = datetime.now().strftime("%Y-%m-%d")  # Fallback to today
            
            # Determine the primary ID for the vulnerability
            if cve_id:
                primary_id = cve_id
                packetstorm_id = f"PACKETSTORM-{exploit['directory']}-{exploit['filename']}"
            else:
                primary_id = self._generate_vrip_id()
                packetstorm_id = None
            
            # Create tags from the content and filename
            tags = []
            common_tags = ['overflow', 'injection', 'xss', 'csrf', 'rce', 'remote', 'local', 
                         'privilege', 'escalation', 'authentication', 'bypass', 'disclosure']
            
            for tag in common_tags:
                if tag.lower() in content.lower() or tag.lower() in exploit['filename'].lower():
                    tags.append(tag)
            
            # Add "exploit" tag by default
            if "exploit" not in tags:
                tags.append("exploit")
            
            # Determine severity (basic heuristic)
            severity = "MEDIUM"  # Default
            if any(tag in ["rce", "remote"] for tag in tags):
                severity = "HIGH"
            elif any(tag in ["local", "disclosure"] for tag in tags):
                severity = "MEDIUM"
            elif any(tag in ["xss", "csrf"] for tag in tags):
                severity = "LOW"
            
            # Create the vulnerability dictionary
            return {
                "id": primary_id,  # Primary identifier - CVE ID if available, otherwise VRIP ID
                "cve_id": cve_id,  # This can be None if no CVE found
                "packetstorm_id": packetstorm_id,  # PacketStorm specific ID for reference
                "title": title,
                "description": description,
                "severity": severity,
                "cvss_score": "0.0",  # PacketStorm doesn't provide CVSS
                "cvss_vector": "",  # PacketStorm doesn't provide CVSS vector
                "package": {
                    "name": product if product else "Unknown",
                    "ecosystem": "Unknown"
                },
                "vulnerable_version_range": "Unknown",  # PacketStorm doesn't provide version info
                "references": [exploit['url']],
                "published_at": date_str,
                "updated_at": date_str,
                "source": self.name,
                "url": exploit['url'],
                "tags": tags,
                "weaknesses": [],  # PacketStorm doesn't provide CWE info
                "exploit_content": exploit_content  # Store the full exploit content for reference
            }
            
        except Exception as e:
            logger.error(f"Error processing exploit {exploit['url']}: {e}")
            return None
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from PacketStorm."""
        try:
            logger.info("Getting all exploits from recent directories")
            
            # Get exploit directories
            directories = self._get_exploit_directories()
            if not directories:
                logger.error("No exploit directories found")
                return []
            
            # Process directories concurrently
            all_exploits = []
            with ThreadPoolExecutor(max_workers=5) as executor:
                # Submit all directory processing tasks
                future_to_dir = {
                    executor.submit(self._get_exploits_from_directory, dir_url): dir_url 
                    for dir_url in directories
                }
                
                # Process completed tasks as they finish
                total = len(future_to_dir)
                completed = 0
                for future in as_completed(future_to_dir):
                    dir_url = future_to_dir[future]
                    completed += 1
                    try:
                        exploits = future.result()
                        if exploits:
                            all_exploits.extend(exploits)
                        logger.info(f"Progress: {completed}/{total} directories processed")
                    except Exception as e:
                        logger.error(f"Error processing directory {dir_url}: {e}")
            
            # Sort by date (newest first)
            all_exploits.sort(key=lambda x: x.get("published_at", ""), reverse=True)
            
            # Update last update time
            if all_exploits:
                latest_date = max(datetime.fromisoformat(v["published_at"]) for v in all_exploits)
                if latest_date > self.last_update:
                    self._save_state(latest_date)
                    self.last_update = latest_date
            
            logger.info(f"Total exploits found: {len(all_exploits)}")
            return all_exploits
            
        except Exception as e:
            logger.error(f"Error getting all exploits: {e}")
            return [] 