import os
import json
import logging
import requests
import zipfile
import io
from typing import List, Dict, Any, Optional
from datetime import datetime
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .base import BaseWorker
from src.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)

class OpenCVEWorker(BaseWorker):
    """Worker for loading OpenCVE data."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.source_url = "https://github.com/opencve/opencve-kb/archive/refs/heads/main.zip"
        self.repo_dir = os.path.join(self.cache_dir, "repo")
        os.makedirs(self.cache_dir, exist_ok=True)
        
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
        
        self._repo_initialized = False
    
    @property
    def name(self) -> str:
        return "opencve"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch all vulnerabilities from OpenCVE KB with real-time saving (full data dump - no checkpoints)."""
        try:
            logger.info(f"[{self.name}] Starting OpenCVE vulnerability collection with real-time saving")
            logger.info(f"[{self.name}] Processing full data dump - no checkpoints used")
            
            # Download and extract repository
            self._download_repo()
            
            # Process all vulnerabilities with real-time saving
            processed_count = self._process_all_vulnerabilities()
            
            logger.info(f"[{self.name}] Processing completed: {processed_count} vulnerabilities processed")
            return []  # Return empty list as vulnerabilities are saved real-time
            
        except Exception as e:
            logger.error(f"Error in OpenCVE vulnerability collection: {e}")
            raise
    
    def _download_repo(self):
        """Download and extract the OpenCVE KB repository."""
        try:
            logger.info(f"[{self.name}] Downloading OpenCVE KB repository...")
            response = self.session.get(self.source_url)
            response.raise_for_status()
            
            # Extract ZIP archive
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                # Extract to a temporary directory first
                temp_dir = os.path.join(self.cache_dir, "temp")
                os.makedirs(temp_dir, exist_ok=True)
                zip_ref.extractall(temp_dir)
                
                # Move the extracted directory to the final location
                extracted_dir = os.path.join(temp_dir, "opencve-kb-main")
                if os.path.exists(self.repo_dir):
                    import shutil
                    shutil.rmtree(self.repo_dir)
                os.rename(extracted_dir, self.repo_dir)
                
                # Clean up temp directory
                import shutil
                shutil.rmtree(temp_dir)
            
            logger.info(f"[{self.name}] Repository downloaded and extracted successfully")
            
        except Exception as e:
            logger.error(f"Failed to download repository: {e}")
            if os.path.exists(self.repo_dir):
                import shutil
                shutil.rmtree(self.repo_dir)
            raise
    
    def _process_all_vulnerabilities(self) -> int:
        """Process all vulnerabilities from OpenCVE KB with real-time saving."""
        processed_count = 0
        
        try:
            # Get available years
            years = self._get_available_years()
            logger.info(f"[{self.name}] Found {len(years)} years of data: {years}")
            
            for year in years:
                year_path = os.path.join(self.repo_dir, str(year))
                if not os.path.isdir(year_path):
                    continue
                
                logger.info(f"[{self.name}] Processing year {year}")
                year_processed = 0
                
                # Walk through all CVE JSON files in this year
                for root, dirs, files in os.walk(year_path):
                    for file_name in files:
                        if file_name.endswith('.json'):
                            file_path = os.path.join(root, file_name)
                            
                            try:
                                vuln_data = self._read_json_file(file_path)
                                if not vuln_data:
                                    continue
                                
                                # Process vulnerability into standardized format
                                processed_vuln = self._process_vulnerability(vuln_data, file_path)
                                if processed_vuln:
                                    # Save immediately in real-time
                                    self.save_vulnerability_realtime(processed_vuln)
                                    year_processed += 1
                                    processed_count += 1
                                    
                            except Exception as e:
                                logger.error(f"Error processing file {file_path}: {e}")
                                continue
                
                logger.info(f"[{self.name}] Year {year}: {year_processed} vulnerabilities processed")
            
            return processed_count
            
        except Exception as e:
            logger.error(f"Error processing vulnerabilities: {e}")
            raise
    
    def _process_vulnerability(self, vuln_data: Dict[str, Any], file_path: str) -> Optional[Dict[str, Any]]:
        """Process a vulnerability from OpenCVE into standardized format."""
        try:
            # Extract CVE ID from data or filename
            cve_id = vuln_data.get("id")
            if not cve_id:
                # Try to extract from filename (e.g., CVE-2023-1234.json)
                filename = os.path.basename(file_path)
                if filename.startswith("CVE-") and filename.endswith(".json"):
                    cve_id = filename[:-5]  # Remove .json extension
                else:
                    logger.warning(f"No CVE ID found in {file_path}")
                    return None
            
            # Create URL for this vulnerability
            vuln_url = f"https://www.opencve.io/cve/{cve_id}"
            
            # Extract basic information
            title = f"OpenCVE: {cve_id}"
            description = vuln_data.get("summary", "") or vuln_data.get("description", "")
            
            # Parse dates
            published_date = self._parse_date(vuln_data.get("published"))
            updated_date = self._parse_date(vuln_data.get("modified"))
            
            # Extract CVSS information
            cvss_data = vuln_data.get("cvss", {})
            if isinstance(cvss_data, list) and cvss_data:
                cvss_data = cvss_data[0]  # Take first CVSS score if multiple
            
            base_score = cvss_data.get("base_score", 0.0) if isinstance(cvss_data, dict) else 0.0
            cvss_vector = cvss_data.get("vector_string", "") if isinstance(cvss_data, dict) else ""
            cvss_version = self._extract_cvss_version(cvss_vector)
            severity = self._cvss_to_severity(base_score)
            
            # Extract references
            references = set()
            for ref in vuln_data.get("references", []):
                if isinstance(ref, dict) and ref.get("url"):
                    references.add(ref["url"])
                elif isinstance(ref, str):
                    references.add(ref)
            
            # Extract affected products and vendors
            affected_products = set()
            affected_vendors = set()
            
            for vendor in vuln_data.get("vendors", []):
                vendor_name = vendor.get("name", "")
                if vendor_name:
                    affected_vendors.add(vendor_name)
                
                for product in vendor.get("products", []):
                    product_name = product.get("name", "")
                    if product_name:
                        affected_products.add(product_name)
            
            # Extract CWE information
            weaknesses = set()
            for cwe in vuln_data.get("cwe", []):
                if isinstance(cwe, dict):
                    cwe_id = cwe.get("id", "")
                elif isinstance(cwe, str):
                    cwe_id = cwe
                else:
                    continue
                
                if cwe_id:
                    weaknesses.add(cwe_id)
            
            # Create standardized vulnerability
            vulnerability = Vulnerability(
                id=Vulnerability.create_id(vuln_url),
                content_hash=Vulnerability.create_content_hash(description),
                path_url=vuln_url,
                source=self.name,
                source_id=cve_id,
                content=description,
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
                weaknesses=weaknesses
            )
            
            return vulnerability.to_dict()
            
        except Exception as e:
            logger.error(f"Error processing OpenCVE vulnerability: {e}")
            return None
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse date string into datetime object."""
        if not date_str:
            return None
        
        try:
            # Try various date formats
            date_formats = [
                "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO with microseconds
                "%Y-%m-%dT%H:%M:%SZ",     # ISO format
                "%Y-%m-%d %H:%M:%S",      # Standard format
                "%Y-%m-%d",               # Date only
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
    
    def _extract_cvss_version(self, vector_string: str) -> Optional[str]:
        """Extract CVSS version from vector string."""
        if not vector_string:
            return None
        
        if vector_string.startswith("CVSS:3.1"):
            return "3.1"
        elif vector_string.startswith("CVSS:3.0"):
            return "3.0"
        elif vector_string.startswith("CVSS:2.0"):
            return "2.0"
        elif vector_string.startswith("CVSS:4.0"):
            return "4.0"
        
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
    
    def _read_json_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Read and parse a JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _get_available_years(self) -> List[int]:
        """Get list of available years in the repository."""
        try:
            years = []
            for item in os.listdir(self.repo_dir):
                if item.isdigit() and os.path.isdir(os.path.join(self.repo_dir, item)):
                    years.append(int(item))
            return sorted(years, reverse=True)  # Process newest first
        except Exception as e:
            logger.error(f"Error getting available years: {e}")
            return [] 