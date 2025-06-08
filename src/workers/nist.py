import os
import json
import logging
import requests
import tempfile
import re
import lzma
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .base import BaseWorker

from src.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)

class NistWorker(BaseWorker):
    """Worker for fetching vulnerability data from NIST National Vulnerability Database."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.data_url = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"
        self.source_url = "https://nvd.nist.gov/"
        
        # Configure requests session with retries
        self.session = requests.Session()
        retry_strategy = requests.adapters.Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Performance settings
        self.max_workers = 4
        self.batch_size = 1000
    
    @property
    def name(self) -> str:
        return "nist"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from NIST NVD using full data dump approach."""
        try:
            logger.info(f"[{self.name}] Starting NIST NVD vulnerability collection")
            
            # Download and process the complete NVD dataset
            nvd_data = self._download_and_load_data()
            if not nvd_data:
                logger.warning(f"[{self.name}] Failed to download NVD data")
                return []
            
            # Process all vulnerabilities with real-time saving
            processed_count = self._process_all_vulnerabilities(nvd_data)
            
            logger.info(f"[{self.name}] NVD processing completed: {processed_count} vulnerabilities processed")
            return []  # Return empty list as vulnerabilities are saved real-time
            
        except Exception as e:
            logger.error(f"Error in NIST NVD collection: {e}")
            raise
    
    def _download_and_load_data(self) -> Optional[Dict[str, Any]]:
        """Download and load the complete NVD dataset."""
        try:
            logger.info(f"[{self.name}] Downloading NVD data from {self.data_url}")
            
            # Download to temporary file
            response = self.session.get(self.data_url, stream=True)
            response.raise_for_status()
            
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_path = temp_file.name
            
            logger.info(f"[{self.name}] Download completed, loading JSON data...")
            
            # Load and parse the compressed JSON data
            with lzma.open(temp_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
            
            # Clean up temporary file
            os.unlink(temp_path)
            
            vulnerabilities_count = len(data.get('cve_items', []))
            logger.info(f"[{self.name}] Successfully loaded {vulnerabilities_count} vulnerabilities from NVD")
            
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download NVD data: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse NVD JSON data: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error downloading NVD data: {e}")
            return None
    
    def _process_all_vulnerabilities(self, nvd_data: Dict[str, Any]) -> int:
        """Process all vulnerabilities from NVD dataset with real-time saving."""
        cve_items = nvd_data.get('cve_items', [])
        processed_count = 0
        
        logger.info(f"[{self.name}] Processing {len(cve_items)} vulnerabilities from NVD dataset")
        
        # Process vulnerabilities in batches using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            for i in range(0, len(cve_items), self.batch_size):
                batch = cve_items[i:i + self.batch_size]
                
                logger.info(f"[{self.name}] Processing batch {i//self.batch_size + 1}/{(len(cve_items) + self.batch_size - 1)//self.batch_size} ({len(batch)} vulnerabilities)")
                
                # Submit batch for processing
                futures = []
                for item in batch:
                    future = executor.submit(self._process_single_vulnerability, item)
                    futures.append(future)
                
                # Process completed futures
                batch_processed = 0
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            batch_processed += 1
                            processed_count += 1
                    except Exception as e:
                        logger.error(f"Error processing vulnerability in batch: {e}")
                        continue
                
                logger.info(f"[{self.name}] Batch completed: {batch_processed} new vulnerabilities saved")
                
                # Log progress every few batches
                if (i // self.batch_size + 1) % 5 == 0:
                    logger.info(f"[{self.name}] Progress: {processed_count} vulnerabilities processed so far...")
        
        return processed_count
    
    def _process_single_vulnerability(self, item: Dict[str, Any]) -> bool:
        """Process a single vulnerability item and save it if new."""
        try:
            cve_id = item.get("id", "")
            if not cve_id:
                return False
            
            # Create unique URL for this vulnerability
            vuln_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            
            # Check if already processed using MD5 ID
            vuln_md5_id = Vulnerability.create_id(vuln_url)
            if self.is_item_processed(vuln_md5_id):
                return False
            
            # Process vulnerability into standardized format
            processed_vuln = self._process_vulnerability(item)
            if processed_vuln:
                # Save immediately in real-time
                self.save_vulnerability_realtime(processed_vuln)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error processing single vulnerability {item.get('id', 'unknown')}: {e}")
            return False
    
    def _process_vulnerability(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a single vulnerability from NVD into standardized format."""
        try:
            # Extract basic information
            cve_id = item.get("id", "")
            
            # Extract English description
            description = ""
            for desc in item.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Create URL for this vulnerability
            vuln_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            
            # Extract CVSS information
            metrics = item.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])
            
            # Prefer CVSS v3.1, then v3.0, then v2.0
            cvss_data = None
            cvss_version = None
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_version = "3.1"
            elif cvss_v30:
                cvss_data = cvss_v30[0].get("cvssData", {})
                cvss_version = "3.0"
            elif cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_version = "2.0"
            
            # Extract score and severity
            base_score = None
            severity = "UNKNOWN"
            cvss_vector = None
            
            if cvss_data:
                base_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString", "")
                
                if cvss_version in ["3.1", "3.0"]:
                    severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                elif cvss_version == "2.0" and base_score:
                    # Convert CVSS v2 score to severity
                    if base_score >= 9.0:
                        severity = "CRITICAL"
                    elif base_score >= 7.0:
                        severity = "HIGH"
                    elif base_score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
            
            # Parse dates
            published_date = self._parse_nvd_date(item.get("published", ""))
            updated_date = self._parse_nvd_date(item.get("lastModified", ""))
            
            # Extract reference URLs
            references = set()
            for ref in item.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.add(url)
            
            # Extract affected products and vendors from CPE data
            affected_products = set()
            affected_vendors = set()
            cpe_details = []
            
            configurations = item.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe = cpe_match.get("criteria", "")
                        if cpe:
                            cpe_details.append(cpe)
                            # Parse CPE format: cpe:2.3:a:vendor:product:version:...
                            cpe_parts = cpe.split(":")
                            if len(cpe_parts) >= 5:
                                vendor = cpe_parts[3]
                                product = cpe_parts[4]
                                if vendor and vendor != "*":
                                    affected_vendors.add(vendor)
                                if product and product != "*":
                                    affected_products.add(product)
            
            # Extract weaknesses (CWE)
            weaknesses = set()
            for weakness in item.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value:
                        weaknesses.add(value)
            
            # Process tags
            tags = {"nist", "nvd"}
            for tag in item.get("cveTags", []):
                if isinstance(tag, dict):
                    tag_name = tag.get("name", "")
                    if tag_name:
                        tags.add(tag_name.lower())
                elif isinstance(tag, str):
                    tags.add(tag.lower())
            
            # Create title
            title = f"NIST NVD: {cve_id}"
            if description:
                title = f"NIST NVD: {cve_id} - {description[:100]}..."
            
            # Create standardized vulnerability
            vulnerability = Vulnerability(
                id=Vulnerability.create_id(vuln_url),
                content_hash=Vulnerability.create_content_hash(description),
                path_url=vuln_url,
                source=self.name,
                source_id=cve_id,
                content=json.dumps(item),  # Store original NVD data
                type=VulnerabilityType.VULNERABILITY,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=str(base_score) if base_score else None,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                published_at=published_date.isoformat() if published_date else datetime.now().isoformat(),
                updated_at=updated_date.isoformat() if updated_date else None,
                reference_urls=references,
                affected_products=affected_products,
                affected_vendors=affected_vendors,
                tags=tags,
                weaknesses=weaknesses,
                cpe_details=cpe_details if cpe_details else None
            )
            
            return vulnerability.to_dict()
            
        except Exception as e:
            logger.error(f"Error processing NIST vulnerability: {e}")
            return None
    
    def _parse_nvd_date(self, date_str: str) -> Optional[datetime]:
        """Parse NVD's date format."""
        if not date_str:
            return None
        
        try:
            # NVD uses ISO format like "2023-12-08T10:15:08.000Z"
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except ValueError:
            try:
                # Try alternative formats
                date_formats = [
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d"
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