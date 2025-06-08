"""
PacketStorm Security vulnerability worker.
Uses directory-based checkpoints for intelligent incremental processing.
"""

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
from src.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)


class PacketStormWorker(BaseWorker):
    """Worker for fetching exploit data from PacketStorm Security."""
    
    def __init__(self, config):
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
    
    @property
    def name(self) -> str:
        return "packetstorm"
    
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
    
    def get_unprocessed_directories(self) -> List[str]:
        """Get directories that haven't been processed yet using checkpoint system."""
        all_dirs = self._get_exploit_directories()
        if not all_dirs:
            return []
        
        # Get processed directory checkpoints
        processed_dirs = set(self.get_all_checkpoints("directory"))
        
        # Find unprocessed directories (keep original sort order - newest first)
        unprocessed = [d for d in all_dirs if d not in processed_dirs]
        
        logger.info(f"[{self.name}] Available: {len(all_dirs)}, "
                   f"Processed: {len(processed_dirs)}, "
                   f"Unprocessed: {len(unprocessed)}")
        
        return unprocessed
    
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
                    exploit_url = f"{self.base_url}/{directory_url}/{href}"
                    exploit_id = Vulnerability.create_id(exploit_url)
                    
                    # Skip if already processed using ID-based checking
                    if self.is_item_processed(exploit_id):
                        logger.debug(f"[{self.name}] Skipping already processed: {href}")
                        continue
                    
                    exploits.append({
                        'url': exploit_url,
                        'filename': href,
                        'directory': directory_url
                    })
            
            logger.info(f"Directory {directory_url}: processing {len(exploits)} new exploits")
            
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
                            # Save immediately (real-time saving)
                            self.save_vulnerability_realtime(exploit_info)
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
            
            # Create standardized vulnerability using the model
            vuln = Vulnerability.from_path_and_content(
                path_url=exploit['url'],
                content=exploit_content or content,
                source=self.name,
                source_id=f"PS-{exploit['directory']}-{exploit['filename']}",
                type=VulnerabilityType.EXPLOIT,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                published_at=date_str,
                tags=set(tags),
                affected_products=set([product]) if product else set()
            )
            
            return vuln.to_dict()
            
        except Exception as e:
            logger.error(f"Error processing exploit {exploit['url']}: {e}")
            return None
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from PacketStorm using smart directory checkpoints."""
        try:
            logger.info(f"[{self.name}] Starting PacketStorm vulnerability collection")
            
            # Get unprocessed directories using checkpoint system
            unprocessed_directories = self.get_unprocessed_directories()
            
            if not unprocessed_directories:
                logger.info(f"[{self.name}] All directories already processed")
                return []
            
            logger.info(f"[{self.name}] Processing {len(unprocessed_directories)} unprocessed directories")
            
            # Process all unprocessed directories (remove artificial limits)
            # max_dirs = self.worker_config.get('max_directories', 12)
            # if max_dirs > 0:
            #     unprocessed_directories = unprocessed_directories[:max_dirs]
            #     logger.info(f"[{self.name}] Limited to {len(unprocessed_directories)} directories")
            logger.info(f"[{self.name}] Processing ALL {len(unprocessed_directories)} unprocessed directories")
            
            # Process directories and collect vulnerabilities
            all_exploits = []
            
            for directory_url in unprocessed_directories:
                try:
                    logger.info(f"[{self.name}] Processing directory: {directory_url}")
                    exploits = self._get_exploits_from_directory(directory_url)
                    if exploits:
                        all_exploits.extend(exploits)
                    
                    # Mark directory as processed (checkpoint)
                    self.set_checkpoint("directory", directory_url)
                    logger.info(f"[{self.name}] Directory checkpoint set: {directory_url}")
                    
                    # Respectful delay between directories
                    time.sleep(1.0)
                    
                except Exception as e:
                    logger.error(f"Error processing directory {directory_url}: {e}")
                    continue
            
            # Sort by date (newest first)
            all_exploits.sort(key=lambda x: x.get("published_at", ""), reverse=True)
            
            logger.info(f"[{self.name}] Total exploits collected: {len(all_exploits)}")
            return all_exploits
            
        except Exception as e:
            logger.error(f"[{self.name}] Error in vulnerability collection: {e}")
            return [] 