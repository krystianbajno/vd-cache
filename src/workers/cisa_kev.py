import logging
import json
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
from .base import BaseWorker

from src.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)

class CisaKevWorker(BaseWorker):
    """Worker for fetching vulnerability data from CISA's Known Exploited Vulnerabilities catalog."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.api_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.source_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        
        # Configure requests session
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnScout/1.0",
            "Accept": "application/json"
        })
    
    @property
    def name(self) -> str:
        return "cisa_kev"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from CISA KEV catalog."""
        try:
            logger.info(f"[{self.name}] Starting CISA KEV vulnerability collection")
            
            # Fetch KEV catalog
            kev_data = self._fetch_kev_catalog()
            if not kev_data:
                logger.warning(f"[{self.name}] Failed to fetch KEV catalog")
                return []
            
            # Process all vulnerabilities with real-time saving
            processed_count = self._process_all_vulnerabilities(kev_data)
            
            logger.info(f"[{self.name}] KEV processing completed: {processed_count} vulnerabilities processed")
            return []  # Return empty list as vulnerabilities are saved real-time
            
        except Exception as e:
            logger.error(f"Error in CISA KEV collection: {e}")
            raise
    
    def _fetch_kev_catalog(self) -> Optional[Dict[str, Any]]:
        """Fetch the CISA KEV catalog from the API."""
        try:
            logger.info(f"[{self.name}] Fetching KEV catalog from API...")
            
            response = self.session.get(self.api_url, timeout=30)
            response.raise_for_status()
            
            # Parse JSON response
            data = response.json()
            
            # Validate response structure
            if not isinstance(data, dict) or 'vulnerabilities' not in data:
                logger.error(f"[{self.name}] Invalid KEV catalog structure")
                return None
            
            vulnerabilities = data.get('vulnerabilities', [])
            logger.info(f"[{self.name}] Successfully fetched KEV catalog with {len(vulnerabilities)} vulnerabilities")
            
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch KEV catalog: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse KEV catalog JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching KEV catalog: {e}")
            return None
    
    def _process_all_vulnerabilities(self, kev_data: Dict[str, Any]) -> int:
        """Process all vulnerabilities from KEV catalog with real-time saving."""
        vulnerabilities = kev_data.get('vulnerabilities', [])
        processed_count = 0
        
        # Get catalog metadata
        catalog_version = kev_data.get('catalogVersion', 'unknown')
        date_released = kev_data.get('dateReleased', 'unknown')
        
        logger.info(f"[{self.name}] Processing KEV catalog v{catalog_version} (released: {date_released})")
        
        for vuln_data in vulnerabilities:
            try:
                # Extract CVE ID
                cve_id = vuln_data.get('cveID', '')
                if not cve_id:
                    logger.warning("Skipping vulnerability without CVE ID")
                    continue
                
                # Create unique URL for this vulnerability
                vuln_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                
                # Check if already processed using MD5 ID
                vuln_md5_id = Vulnerability.create_id(vuln_url)
                if self.is_item_processed(vuln_md5_id):
                    continue
                
                # Process vulnerability into standardized format
                processed_vuln = self._process_vulnerability(vuln_data)
                if processed_vuln:
                    # Save immediately in real-time
                    self.save_vulnerability_realtime(processed_vuln)
                    processed_count += 1
                    
                    # Log progress every 100 vulnerabilities
                    if processed_count % 100 == 0:
                        logger.info(f"[{self.name}] Processed {processed_count} vulnerabilities so far...")
                        
            except Exception as e:
                logger.error(f"Error processing vulnerability {vuln_data.get('cveID', 'unknown')}: {e}")
                continue
        
        return processed_count
    
    def _process_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single vulnerability from KEV catalog into standardized format."""
        try:
            # Extract basic information
            cve_id = vuln_data.get('cveID', '')
            vendor_project = vuln_data.get('vendorProject', '')
            product = vuln_data.get('product', '')
            vulnerability_name = vuln_data.get('vulnerabilityName', '')
            short_description = vuln_data.get('shortDescription', '')
            required_action = vuln_data.get('requiredAction', '')
            due_date = vuln_data.get('dueDate', '')
            known_ransomware = vuln_data.get('knownRansomwareCampaignUse', '')
            notes = vuln_data.get('notes', '')
            
            # Create URL for this vulnerability
            vuln_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            
            # Create title
            if vulnerability_name:
                title = f"CISA KEV: {vulnerability_name} ({cve_id})"
            else:
                title = f"CISA KEV: {cve_id}"
            
            # Create comprehensive description
            description_parts = []
            if short_description:
                description_parts.append(short_description)
            if required_action:
                description_parts.append(f"Required Action: {required_action}")
            if notes:
                description_parts.append(f"Notes: {notes}")
            
            description = ' | '.join(description_parts) if description_parts else f"Known exploited vulnerability {cve_id}"
            
            # Parse dates
            date_added = self._parse_date(vuln_data.get('dateAdded', ''))
            due_date_parsed = self._parse_date(due_date)
            
            # Determine severity - KEV vulnerabilities are high priority by definition
            severity = "HIGH"  # All KEV entries are considered high severity
            
            # Create reference URLs
            references = {
                vuln_url,
                self.source_url,
                f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{cve_id}"
            }
            
            # Extract vendor and product information
            affected_vendors = set()
            affected_products = set()
            
            if vendor_project:
                affected_vendors.add(vendor_project)
            if product:
                affected_products.add(product)
            
            # Create tags
            tags = {"cisa-kev", "known-exploited"}
            if known_ransomware and known_ransomware.lower() in ['yes', 'true', 'known']:
                tags.add("ransomware")
            
            # Create standardized vulnerability
            vulnerability = Vulnerability(
                id=Vulnerability.create_id(vuln_url),
                content_hash=Vulnerability.create_content_hash(short_description),
                path_url=vuln_url,
                source=self.name,
                source_id=cve_id,
                content=json.dumps(vuln_data),  # Store original KEV data
                type=VulnerabilityType.VULNERABILITY,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                published_at=date_added.isoformat() if date_added else datetime.now().isoformat(),
                updated_at=date_added.isoformat() if date_added else None,
                reference_urls=references,
                affected_products=affected_products,
                affected_vendors=affected_vendors,
                tags=tags,
                # KEV-specific fields stored in tags/description
                aliases=vulnerability_name if vulnerability_name != cve_id else None
            )
            
            return vulnerability.to_dict()
            
        except Exception as e:
            logger.error(f"Error processing CISA KEV vulnerability: {e}")
            return None
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string into datetime object."""
        if not date_str:
            return None
        
        try:
            # CISA KEV uses YYYY-MM-DD format
            return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            try:
                # Try alternative formats
                date_formats = [
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                    "%m/%d/%Y"
                ]
                
                for fmt in date_formats:
                    try:
                        return datetime.strptime(date_str, fmt)
                    except ValueError:
                        continue
                
                logger.warning(f"Could not parse date: {date_str}")
                return None
                
            except Exception as e:
                logger.warning(f"Error parsing date {date_str}: {e}")
                return None 