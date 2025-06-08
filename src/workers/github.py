import os
import json
import logging
import requests
import zipfile
import io
from typing import List, Dict, Any, Optional
from datetime import datetime
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .base import BaseWorker
from src.models.vulnerability import Vulnerability, VulnerabilityType

logger = logging.getLogger(__name__)

class GitHubAdvisoryWorker(BaseWorker):
    """Worker for fetching security advisories from GitHub Advisory Database."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.source_url = "https://github.com/github/advisory-database/archive/refs/heads/main.zip"
        
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
    
    @property
    def name(self) -> str:
        return "github"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch all security advisories from GitHub Advisory Database with real-time saving (full data dump - no checkpoints)."""
        try:
            logger.info(f"[{self.name}] Starting GitHub Advisory collection with real-time saving")
            logger.info(f"[{self.name}] Processing full data dump - no checkpoints used")
            
            # Download and process ZIP archive
            processed_count = self._download_and_process_advisories()
            
            logger.info(f"[{self.name}] Processing completed: {processed_count} vulnerabilities processed")
            return []  # Return empty list as vulnerabilities are saved real-time
            
        except Exception as e:
            logger.error(f"Error in GitHub Advisory collection: {e}")
            raise
    
    def _download_and_process_advisories(self) -> int:
        """Download ZIP archive and process all advisories with real-time saving."""
        try:
            headers = {
                "User-Agent": "VulnScout/1.0"
            }
            
            logger.info(f"[{self.name}] Downloading GitHub advisory database...")
            response = self.session.get(self.source_url, headers=headers)
            response.raise_for_status()
            
            processed_count = 0
            
            # Extract ZIP archive and process advisories
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                # GitHub advisories are organized by date, not ecosystem
                # Structure: advisory-database-main/advisories/github-reviewed/YEAR/MONTH/GHSA-ID/GHSA-ID.json
                advisory_path_prefix = "advisory-database-main/advisories/github-reviewed/"
                
                # Get all JSON advisory files
                advisory_files = [f for f in zip_ref.infolist() 
                               if f.filename.startswith(advisory_path_prefix) and f.filename.endswith('.json')]
                
                logger.info(f"[{self.name}] Found {len(advisory_files)} advisory files to process")
                
                # Process all advisory files
                for file_info in advisory_files:
                    try:
                        with zip_ref.open(file_info) as f:
                            advisory_data = json.load(f)
                            advisory_data['file_path'] = file_info.filename
                            
                            # Process advisory into standardized format
                            processed_advisory = self._process_advisory(advisory_data)
                            if processed_advisory:
                                # Save immediately in real-time
                                self.save_vulnerability_realtime(processed_advisory)
                                processed_count += 1
                                
                                # Log progress every 1000 advisories
                                if processed_count % 1000 == 0:
                                    logger.info(f"[{self.name}] Processed {processed_count} advisories so far...")
                                    
                    except Exception as e:
                        logger.error(f"Error processing advisory file {file_info.filename}: {e}")
                        continue
                
                return processed_count
                
        except Exception as e:
            logger.error(f"Error downloading and processing advisories: {e}")
            raise
    
    def _process_advisory(self, advisory_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a GitHub advisory into standardized format."""
        try:
            # Extract advisory ID
            advisory_id = advisory_data.get('id', '')
            if not advisory_id:
                logger.warning("Skipping advisory without ID")
                return None
            
            # Create URL for this advisory
            advisory_url = f"https://github.com/advisories/{advisory_id}"
            
            # Extract basic information
            title = advisory_data.get('summary', f"GitHub Advisory: {advisory_id}")
            description = advisory_data.get('details', '')
            
            # Extract ecosystem from affected packages
            ecosystem = "unknown"
            affected_packages = advisory_data.get('affected', [])
            if affected_packages:
                for affected in affected_packages:
                    package_info = affected.get('package', {})
                    pkg_ecosystem = package_info.get('ecosystem', '')
                    if pkg_ecosystem:
                        ecosystem = pkg_ecosystem.lower()
                        break
            
            # Parse dates
            published_date = self._parse_date(advisory_data.get('published'))
            updated_date = self._parse_date(advisory_data.get('modified'))
            
            # Extract CVE ID from references
            cve_id = None
            references = set()
            
            for ref in advisory_data.get("references", []):
                if isinstance(ref, dict):
                    ref_url = ref.get("url", "")
                    if ref_url:
                        references.add(ref_url)
                        # Check if it's a CVE reference
                        if ref.get("type") == "ADVISORY" and "CVE-" in ref_url:
                            cve_parts = ref_url.split("/")
                            for part in cve_parts:
                                if part.startswith("CVE-"):
                                    cve_id = part
                                    break
            
            # Extract CVSS information
            database_specific = advisory_data.get("database_specific", {})
            cvss_data = database_specific.get("cvss", {})
            
            base_score = 0.0
            cvss_vector = ""
            cvss_version = None
            
            if isinstance(cvss_data, dict):
                base_score = cvss_data.get("score", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                cvss_version = self._extract_cvss_version(cvss_vector)
            
            severity = database_specific.get("severity", "UNKNOWN").upper()
            if severity == "UNKNOWN":
                severity = self._cvss_to_severity(base_score)
            
            # Extract affected packages and versions
            affected_products = set()
            affected_versions = set()
            patched_versions = set()
            
            for affected in advisory_data.get("affected", []):
                package_info = affected.get("package", {})
                package_name = package_info.get("name", "")
                if package_name:
                    affected_products.add(package_name)
                
                # Extract version ranges
                for version_range in affected.get("ranges", []):
                    for event in version_range.get("events", []):
                        if "introduced" in event:
                            affected_versions.add(event["introduced"])
                        if "fixed" in event:
                            patched_versions.add(event["fixed"])
            
            # Extract CWE information
            weaknesses = set()
            for cwe_id in database_specific.get("cwe_ids", []):
                if cwe_id:
                    weaknesses.add(cwe_id)
            
            # Extract aliases (other identifiers)
            aliases_list = []
            for alias in advisory_data.get("aliases", []):
                if alias and alias != advisory_id:
                    aliases_list.append(alias)
            
            aliases = "\n".join(aliases_list) if aliases_list else None
            
            # Determine vulnerability type (GitHub advisories are security vulnerabilities)
            vuln_type = VulnerabilityType.VULNERABILITY
            
            # Create standardized vulnerability
            vulnerability = Vulnerability(
                id=Vulnerability.create_id(advisory_url),
                content_hash=Vulnerability.create_content_hash(description),
                path_url=advisory_url,
                source=self.name,
                source_id=advisory_id,
                content=description,
                type=vuln_type,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=str(base_score) if base_score else None,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                aliases=aliases,
                published_at=published_date.isoformat() if published_date else datetime.now().isoformat(),
                updated_at=updated_date.isoformat() if updated_date else None,
                reference_urls=references,
                affected_products=affected_products,
                affected_versions=affected_versions,
                patched_versions=patched_versions,
                weaknesses=weaknesses,
                tags={ecosystem, "github-advisory"} if ecosystem else {"github-advisory"}
            )
            
            return vulnerability.to_dict()
            
        except Exception as e:
            logger.error(f"Error processing GitHub advisory: {e}")
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
                "%Y-%m-%dT%H:%M:%S",      # ISO without Z
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