import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .base import BaseWorker
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from src.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class EnisaWorker(BaseWorker):
    """Worker for fetching and caching ENISA EUVD data."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the ENISA EUVD worker."""
        super().__init__(config)  # This will call _init_cache() and set db_path
        
        self.source_url = "https://euvdservices.enisa.europa.eu"
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Headers required by the API
        self.headers = {
            "User-Agent": "VulnScout/1.0",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
    
    @property
    def name(self) -> str:
        """Return the name of the worker."""
        return "enisa"
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string from ENISA API."""
        if not date_str:
            return None
            
        try:
            # Try the format: "Oct 18, 2022, 2:46:41 AM"
            return datetime.strptime(date_str, "%b %d, %Y, %I:%M:%S %p")
        except ValueError:
            try:
                # Try the format: "October 18, 2022, 2:46:41 AM"
                return datetime.strptime(date_str, "%B %d, %Y, %I:%M:%S %p")
            except ValueError as e:
                logger.warning(f"Failed to parse date '{date_str}': {e}")
                return None
    
    def _normalize_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize vulnerability data to match expected format."""
        # Parse the date
        date = self._parse_date(vuln_data.get("datePublished"))
        date_str = date.isoformat() if date else datetime.now().isoformat()
        
        # Extract CVE ID from aliases
        cve_id = None
        if vuln_data.get("aliases"):
            for alias in vuln_data["aliases"].split("\n"):
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break
        
        # Extract references
        references = [ref.strip() for ref in vuln_data.get("references", "").split("\n") if ref.strip()]
        
        # Extract vulnerable components
        vulnerable_components = set()
        for product in vuln_data.get("enisaIdProduct", []):
            if product.get("product", {}).get("name"):
                vulnerable_components.add(product["product"]["name"])
        
        # Create vulnerability model
        vulnerability = Vulnerability(
            id=f"enisa-{vuln_data['id']}",  # Unique identifier
            cve_id=cve_id,  # CVE ID extracted from aliases
            source_id=vuln_data["id"],  # ENISA vulnerability ID
            title=f"ENISA: {vuln_data['id']}",
            description=vuln_data.get("description", ""),
            date=date_str,
            source=self.name,
            source_type="base",
            url=f"{self.source_url}/vulnerabilities/{vuln_data['id']}",
            base_score=str(vuln_data.get("baseScore", "0.0")),
            base_severity=self._get_severity(float(vuln_data.get("baseScore", 0))),
            reference_urls=set(references),
            vulnerable_components=vulnerable_components,
            tags={"enisa", "euvd"},
            weaknesses=set(),  # ENISA doesn't provide weaknesses
            patched_versions=None  # ENISA doesn't provide patched versions
        )
        
        return vulnerability.dict()
    
    def _get_severity(self, score: float) -> str:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "UNKNOWN"
    
    def _validate_response(self, response: requests.Response) -> bool:
        """Validate the API response."""
        try:
            # Check content type
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type.lower():
                logger.error(f"Invalid content type: {content_type}")
                return False
            
            # Try to parse JSON
            data = response.json()
            
            # Validate response structure
            if not isinstance(data, dict):
                logger.error(f"Invalid response structure: expected dict, got {type(data)}")
                return False
            
            # Handle both old and new response formats
            if "items" in data:
                return True
            elif "data" in data:
                return True
            else:
                logger.error(f"Invalid response format: missing 'items' or 'data' field")
                return False
                
        except Exception as e:
            logger.error(f"Error validating response: {e}")
            return False
    
    def _fetch_page(self, page: int, size: int) -> List[Dict[str, Any]]:
        """Fetch a single page of vulnerabilities."""
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                response = self.session.get(
                    f"{self.source_url}/api/vulnerabilities",
                    params={
                        "size": size,
                        "page": page,
                        "sort": "datePublished,desc"
                    },
                    headers=self.headers
                )
                
                # Handle 403 Forbidden
                if response.status_code == 403:
                    logger.warning(f"Received 403 Forbidden for page {page}, attempt {attempt + 1}/{max_retries}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                        continue
                    return []
                
                response.raise_for_status()
                
                # Validate response
                if not self._validate_response(response):
                    return []
                
                data = response.json()
                logger.info(f"API Response data (first 512 bytes): {str(data)[:512]}")
                
                # Handle both old and new response formats
                if "items" in data:
                    vulns = data["items"]
                elif "data" in data:
                    vulns = data["data"]
                else:
                    logger.error("Invalid response format: missing 'items' or 'data' field")
                    return []
                
                if not vulns:
                    logger.info(f"No vulnerabilities found on page {page}")
                    return []
                
                # Process vulnerabilities
                processed_vulns = []
                for vuln_data in vulns:
                    try:
                        vuln_date = self._parse_date(vuln_data.get("datePublished"))
                        
                        # Skip if older than last update and has a valid date
                        if vuln_date and vuln_date < self.last_update:
                            continue
                        
                        # Normalize and add vulnerability
                        normalized_vuln = self._normalize_vulnerability(vuln_data)
                        processed_vulns.append(normalized_vuln)
                        logger.info(f"Mapped vulnerability: id={normalized_vuln['id']}, cve_id={normalized_vuln.get('cve_id')}, source_id={normalized_vuln['source_id']}")
                        
                    except Exception as e:
                        logger.error(f"Error processing vulnerability: {e}")
                        continue
                
                return processed_vulns
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed for page {page}: {e}")
                if hasattr(e, 'response') and e.response is not None:
                    logger.error(f"Response status: {e.response.status_code}")
                    logger.error(f"Response headers: {e.response.headers}")
                    logger.error(f"Response content: {e.response.text[:500]}")
                
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                    continue
                return []
                
            except Exception as e:
                logger.error(f"Unexpected error during fetch for page {page}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                return []
        
        return []
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from ENISA EUVD."""
        logger.info(f"Fetching ENISA EUVD vulnerabilities (last update: {self.last_update.isoformat()})")
        
        size = 100  # Page size
        total_vulns = 0
        vulnerabilities = []
        latest_date = self.last_update
        page = 0
        consecutive_empty = 0
        max_consecutive_empty = 3  # Stop after 3 consecutive empty batches
        
        while consecutive_empty < max_consecutive_empty:
            # Add sleep between batches to avoid rate limiting
            if page > 0:
                logger.info(f"Sleeping for 2 seconds before fetching next batch (page {page})")
                time.sleep(2)
            
            # Fetch next batch of pages sequentially to maintain order
            batch_vulns = []
            batch_empty = True
            
            for i in range(10):
                current_page = page + i
                try:
                    page_vulns = self._fetch_page(current_page, size)
                    if page_vulns:
                        batch_vulns.extend(page_vulns)
                        batch_empty = False
                except Exception as e:
                    logger.error(f"Error fetching page {current_page}: {e}")
                    continue
            
            if batch_empty:
                consecutive_empty += 1
                logger.info(f"Empty batch {consecutive_empty}/{max_consecutive_empty}")
            else:
                consecutive_empty = 0
                vulnerabilities.extend(batch_vulns)
                total_vulns += len(batch_vulns)
                
                # Update latest date
                for vuln in batch_vulns:
                    try:
                        vuln_date = datetime.fromisoformat(vuln["date"])
                        if vuln_date > latest_date:
                            latest_date = vuln_date
                    except (ValueError, KeyError):
                        continue
            
            page += 10  # Move to next batch
        
        # Update last update time
        if latest_date > self.last_update:
            self._save_state(latest_date)
            self.last_update = latest_date
        
        logger.info(f"Fetched {total_vulns} vulnerabilities from ENISA EUVD")
        return vulnerabilities 