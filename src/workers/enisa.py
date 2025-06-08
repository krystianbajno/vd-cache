import re
import json
import logging
import requests
import time
import concurrent.futures
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import calendar
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .base import BaseWorker

from src.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)

class EnisaWorker(BaseWorker):
    """Worker for fetching vulnerability data from ENISA EU Vulnerability Database."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.base_url = "https://euvdservices.enisa.europa.eu"
        self.api_base_url = f"{self.base_url}/api"
        self.request_delay = 1.0  # 1 second between requests for rate limiting
        
        # Configure requests session with retries
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
        
        # Headers for the API
        self.headers = {
            "User-Agent": "VulnScout/1.0",
            "Accept": "application/json",
        }
        
        # CVE pattern for extraction
        self.cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    
    @property
    def name(self) -> str:
        return "enisa"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from ENISA using date-based monthly processing."""
        try:
            logger.info(f"[{self.name}] Starting ENISA vulnerability collection with comprehensive historical processing")
            
            # Get last processed date only for logging
            last_date_str = self.get_latest_checkpoint("last_processed_date")
            if last_date_str:
                logger.info(f"[{self.name}] Previous checkpoint: {last_date_str} (will process all available historical data)")
            else:
                logger.info(f"[{self.name}] No previous checkpoint found")
            
            logger.info(f"[{self.name}] Starting comprehensive historical collection (will scrape until no more vulnerabilities available)")
            
            # Process vulnerabilities by month from newest to oldest until API has no more data
            processed_count = self._fetch_vulnerabilities_by_date_ranges()
            
            logger.info(f"[{self.name}] Processing completed: {processed_count} vulnerabilities processed")
            return []  # Return empty list as vulnerabilities are saved real-time
            
        except Exception as e:
            logger.error(f"Error in ENISA vulnerability collection: {e}")
            raise
    
    def _fetch_vulnerabilities_by_date_ranges(self) -> int:
        """Fetch vulnerabilities by monthly date ranges from newest to oldest until no more data available."""
        processed_count = 0
        current_date = datetime.now()
        consecutive_empty_months = 0
        max_consecutive_empty_months = 6  # Stop after 6 consecutive months with no vulnerabilities
        
        # Process from current month backwards until API has no more data
        while True:
            try:
                # Calculate month range
                month_start = current_date.replace(day=1)
                # Get last day of the month
                if month_start.month == 12:
                    next_month = month_start.replace(year=month_start.year + 1, month=1)
                else:
                    next_month = month_start.replace(month=month_start.month + 1)
                month_end = next_month - timedelta(days=1)
                
                # Don't go beyond today for current month
                if month_end > datetime.now():
                    month_end = datetime.now()
                
                logger.info(f"[{self.name}] Processing month: {month_start.strftime('%Y-%m-%d')} to {month_end.strftime('%Y-%m-%d')}")
                
                # Process all pages for this month
                month_processed = self._process_month_vulnerabilities(month_start, month_end)
                processed_count += month_processed
                
                logger.info(f"[{self.name}] Month {month_start.strftime('%Y-%m')}: {month_processed} vulnerabilities processed")
                
                # Track consecutive empty months to know when to stop
                if month_processed == 0:
                    consecutive_empty_months += 1
                    logger.info(f"[{self.name}] Consecutive empty months: {consecutive_empty_months}/{max_consecutive_empty_months}")
                else:
                    consecutive_empty_months = 0  # Reset counter when we find data
                
                # Update checkpoint to current processing day (end of this month or today, whichever is earlier)
                checkpoint_date = min(month_end, datetime.now())
                self.set_checkpoint("last_processed_date", checkpoint_date.strftime("%Y-%m-%d"))
                
                # Stop if we've hit too many consecutive empty months (likely reached end of available data)
                if consecutive_empty_months >= max_consecutive_empty_months:
                    logger.info(f"[{self.name}] Reached {max_consecutive_empty_months} consecutive months with no vulnerabilities - stopping")
                    break
                
                # Move to previous month
                current_date = month_start - timedelta(days=1)
                
            except Exception as e:
                logger.error(f"Error processing month {current_date.strftime('%Y-%m')}: {e}")
                # Continue with next month
                current_date = current_date.replace(day=1) - timedelta(days=1)
                continue
        
        return processed_count
    
    def _process_month_vulnerabilities(self, from_date: datetime, to_date: datetime) -> int:
        """Process all vulnerabilities for a specific month with pagination."""
        processed_count = 0
        page = 0
        page_size = 100  # Maximum allowed by API
        batch_size = 2  # Process 5 pages at once
        
        from_date_str = from_date.strftime("%Y-%m-%d")
        to_date_str = to_date.strftime("%Y-%m-%d")
        
        while True:
            try:
                # Calculate page range for this batch
                start_page = page
                end_page = page + batch_size
                
                logger.info(f"[{self.name}] Fetching batch: pages {start_page + 1}-{end_page} for {from_date_str} to {to_date_str}")
                
                # Fetch multiple pages concurrently for this date range
                batch_pages = self._fetch_date_range_batch(from_date_str, to_date_str, start_page, end_page, page_size)
                
                if not batch_pages:
                    logger.info(f"[{self.name}] No more vulnerabilities found for this month")
                    break
                
                # Process all vulnerabilities from the batch
                all_vulnerabilities = []
                total_items_in_batch = 0
                
                for page_data in batch_pages:
                    if page_data and 'items' in page_data:
                        vulnerabilities = page_data['items']
                        all_vulnerabilities.extend(vulnerabilities)
                        total_items_in_batch += len(vulnerabilities)
                
                if not all_vulnerabilities:
                    logger.info(f"[{self.name}] No vulnerabilities in batch for this month")
                    break
                
                logger.info(f"[{self.name}] Processing {len(all_vulnerabilities)} vulnerabilities from batch")
                
                # Process vulnerabilities from the batch
                new_vulns_in_batch = 0
                
                for vuln_data in all_vulnerabilities:
                    euvd_id = vuln_data.get('id', '')
                    
                    # Create unique URL for this vulnerability
                    vuln_url = f"{self.base_url}/vulnerabilities/{euvd_id}"
                    
                    # Check if already processed using MD5 ID
                    vuln_md5_id = Vulnerability.create_id(vuln_url)
                    if self.is_item_processed(vuln_md5_id):
                        continue
                    
                    # Process and save vulnerability in real-time
                    try:
                        processed_vuln = self._process_vulnerability(vuln_data)
                        if processed_vuln:
                            # Save immediately
                            self.save_vulnerability_realtime(processed_vuln)
                            new_vulns_in_batch += 1
                            processed_count += 1
                                
                    except Exception as e:
                        logger.error(f"Error processing vulnerability {euvd_id}: {e}")
                        continue
                
                logger.info(f"[{self.name}] Batch {start_page + 1}-{end_page}: {new_vulns_in_batch} new vulnerabilities saved")
                
                # Check if no new vulnerabilities were found in this batch (all were duplicates)
                if new_vulns_in_batch == 0 and len(all_vulnerabilities) > 0:
                    logger.info(f"[{self.name}] No new vulnerabilities in batch (all {len(all_vulnerabilities)} were already processed) - stopping month processing")
                    break
                
                # Check if this batch had fewer items than expected (end of data for this month)
                if total_items_in_batch < batch_size * page_size:
                    logger.info(f"[{self.name}] Reached end of data for this month (batch had {total_items_in_batch} items)")
                    break
                
                page += batch_size
                time.sleep(self.request_delay)  # Rate limiting between batches
                
            except Exception as e:
                logger.error(f"Error processing batch starting at page {page + 1}: {e}")
                break
        
        return processed_count
    
    def _fetch_date_range_batch(self, from_date: str, to_date: str, start_page: int, end_page: int, page_size: int) -> List[Optional[Dict[str, Any]]]:
        """Fetch multiple pages concurrently for a specific date range."""
        batch_pages = []
        
        # Use ThreadPoolExecutor to fetch pages concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all page requests
            future_to_page = {}
            for page_num in range(start_page, end_page):
                future = executor.submit(self._fetch_date_range_page, from_date, to_date, page_num, page_size)
                future_to_page[future] = page_num
            
            # Collect results in order
            page_results = {}
            for future in concurrent.futures.as_completed(future_to_page):
                page_num = future_to_page[future]
                try:
                    page_data = future.result()
                    page_results[page_num] = page_data
                except Exception as e:
                    logger.error(f"Error fetching page {page_num + 1}: {e}")
                    page_results[page_num] = None
            
            # Return pages in order
            for page_num in range(start_page, end_page):
                batch_pages.append(page_results.get(page_num))
        
        return batch_pages
    
    def _fetch_date_range_page(self, from_date: str, to_date: str, page: int, size: int = 100) -> Optional[Dict[str, Any]]:
        """Fetch a page of vulnerabilities for a specific date range using the /api/search endpoint."""
        try:
            # Use search API with date range parameters
            params = {
                "page": page,
                "size": size,
                "fromDate": from_date,
                "toDate": to_date,
                "fromScore": 0,  # Include all CVSS scores
                "toScore": 10,
            }
            
            response = self._make_request("search", params)
            return response
            
        except Exception as e:
            logger.error(f"Error fetching date range page {page} ({from_date} to {to_date}): {e}")
            return None
    
    def _process_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a vulnerability from ENISA into standardized format."""
        try:
            # Extract basic information
            euvd_id = vuln_data.get('id', '')
            description = vuln_data.get('description', '')
            title = f"ENISA: {euvd_id}"
            vuln_url = f"{self.base_url}/vulnerabilities/{euvd_id}"
            
            # Parse dates
            published_date = self._parse_enisa_date(vuln_data.get('datePublished', ''))
            updated_date = self._parse_enisa_date(vuln_data.get('dateUpdated', ''))
            
            # Extract CVE from aliases
            aliases = vuln_data.get('aliases', '')
            cve_id = None
            if aliases:
                cve_match = self.cve_pattern.search(aliases)
                if cve_match:
                    cve_id = cve_match.group(0).upper()
            
            # Extract CVSS information
            base_score = vuln_data.get('baseScore', 0.0)
            cvss_version = vuln_data.get('baseScoreVersion', '')
            cvss_vector = vuln_data.get('baseScoreVector', '')
            severity = self._cvss_to_severity(base_score)
            
            # Extract EPSS score
            epss_score = vuln_data.get('epss', 0.0)
            
            # Extract assigner
            assigner = vuln_data.get('assigner', '')
            
            # Extract references
            references = set()
            if vuln_data.get('references'):
                refs = [ref.strip() for ref in vuln_data['references'].split('\n') if ref.strip()]
                references.update(refs)
            
            # Extract affected products and vendors
            affected_products = set()
            affected_vendors = set()
            product_details = []
            vendor_details = []
            
            # Process product information
            if vuln_data.get('enisaIdProduct'):
                for product_item in vuln_data['enisaIdProduct']:
                    if 'product' in product_item:
                        product_name = product_item['product'].get('name', '')
                        product_version = product_item.get('product_version', '')
                        if product_name:
                            affected_products.add(product_name)
                            product_details.append({
                                'id': product_item.get('id', ''),
                                'name': product_name,
                                'version': product_version
                            })
            
            # Process vendor information
            if vuln_data.get('enisaIdVendor'):
                for vendor_item in vuln_data['enisaIdVendor']:
                    if 'vendor' in vendor_item:
                        vendor_name = vendor_item['vendor'].get('name', '')
                        if vendor_name:
                            affected_vendors.add(vendor_name)
                            vendor_details.append({
                                'id': vendor_item.get('id', ''),
                                'name': vendor_name
                            })
            
            # Create standardized vulnerability
            vulnerability = Vulnerability(
                id=Vulnerability.create_id(vuln_url),
                content_hash=Vulnerability.create_content_hash(description),
                path_url=vuln_url,
                source=self.name,
                source_id=euvd_id,
                content=description,
                type=VulnerabilityType.VULNERABILITY,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=str(base_score) if base_score else None,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                aliases=aliases,
                assigner=assigner,
                epss_score=epss_score,
                published_at=published_date.isoformat() if published_date else datetime.now().isoformat(),
                updated_at=updated_date.isoformat() if updated_date else None,
                reference_urls=references,
                affected_products=affected_products,
                affected_vendors=affected_vendors,
                product_details=product_details if product_details else None,
                vendor_details=vendor_details if vendor_details else None
            )
            
            return vulnerability.to_dict()
            
        except Exception as e:
            logger.error(f"Error processing ENISA vulnerability: {e}")
            return None
    
    def _parse_enisa_date(self, date_str: str) -> Optional[datetime]:
        """Parse ENISA's specific date format."""
        if not date_str:
            return None
            
        try:
            # ENISA uses format like "Jun 8, 2025, 1:31:44 PM"
            return datetime.strptime(date_str, "%b %d, %Y, %I:%M:%S %p")
        except ValueError:
            try:
                # Try alternative format "December 8, 2025, 5:01:54 PM"
                return datetime.strptime(date_str, "%B %d, %Y, %I:%M:%S %p")
            except ValueError:
                try:
                    # Try ISO format
                    return datetime.strptime(date_str, "%Y-%m-%d")
                except ValueError:
                    logger.warning(f"Could not parse date: {date_str}")
                    return None
    
    def _cvss_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level."""
        try:
            score = float(score)
            if score >= 9.0:
                return "CRITICAL"
            elif score >= 7.0:
                return "HIGH"
            elif score >= 4.0:
                return "MEDIUM"
            elif score > 0:
                return "LOW"
            return "UNKNOWN"
        except (ValueError, TypeError):
            return "UNKNOWN"
    
    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make a request to the ENISA EUVD API with rate limiting and retries."""
        try:
            url = f"{self.api_base_url}/{endpoint}"
            logger.debug(f"Making request to {url} with params: {params}")
            
            # Add delay before request for rate limiting
            time.sleep(self.request_delay)
            
            response = self.session.get(
                url,
                params=params,
                headers=self.headers,
                timeout=30
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Validate response content type
            content_type = response.headers.get('content-type', '')
            if 'application/json' not in content_type.lower():
                logger.error(f"Invalid content type: {content_type}")
                return None
            
            # Parse JSON
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response: {e}")
                logger.debug(f"Response content: {response.text[:500]}")
                return None
            
            # Validate response structure
            if not isinstance(data, dict):
                logger.error(f"Invalid response structure: expected dict, got {type(data)}")
                return None
            
            return data
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response headers: {e.response.headers}")
                logger.error(f"Response content: {e.response.text[:500]}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during request: {e}")
            return None 