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
from src.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class OpenCVEWorker(BaseWorker):
    """Worker for loading OpenCVE data."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the worker."""
        super().__init__(config)
        self.source_url = "https://github.com/opencve/opencve-kb/archive/refs/heads/main.zip"
        self.repo_dir = os.path.join(self.cache_dir, "repo")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # State file for tracking last update
        self.state_file = os.path.join(self.cache_dir, "state.json")
        self.last_update = self._load_state()
        
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
        
        # Don't download in __init__
        self._repo_initialized = False
    
    @property
    def name(self) -> str:
        return "opencve"
    
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
    
    def initialize(self):
        """Initialize the worker."""
        if not self._repo_initialized:
            self._download_repo()
            self._repo_initialized = True

    def _download_repo(self):
        """Download and extract the OpenCVE KB repository."""
        try:
            logger.info("Downloading OpenCVE KB repository...")
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
                shutil.rmtree(temp_dir)
            
            logger.info("Repository downloaded and extracted successfully")
            
        except Exception as e:
            logger.error(f"Failed to download repository: {e}")
            if os.path.exists(self.repo_dir):
                import shutil
                shutil.rmtree(self.repo_dir)
    
    def _process_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a vulnerability from OpenCVE into a dictionary format."""
        try:
            # Extract required fields
            vuln_id = vuln_data.get("id")
            if not vuln_id:
                logger.warning("Skipping vulnerability without ID")
                return None
            
            # Get CVSS score
            cvss = vuln_data.get("cvss", {})
            base_score = cvss.get("base_score", 0.0)
            
            # Get affected products
            affected_products = []
            for vendor in vuln_data.get("vendors", []):
                for product in vendor.get("products", []):
                    affected_products.append(f"{vendor.get('name', 'Unknown')} {product.get('name', '')} {product.get('version', '')}")
            
            # Get references
            references = []
            for ref in vuln_data.get("references", []):
                if ref.get("url"):
                    references.append(ref["url"])
            
            # Create vulnerability model
            vulnerability = Vulnerability(
                id=f"opencve-{vuln_id}",  # Unique identifier
                cve_id=vuln_id,  # CVE ID is the same as vuln_id for OpenCVE
                source_id=vuln_id,  # OpenCVE uses CVE IDs as source IDs
                title=vuln_data.get("summary", f"OpenCVE: {vuln_id}"),
                description=vuln_data.get("description", ""),
                date=vuln_data.get("published", datetime.now().isoformat()),
                source=self.name,
                source_type="base",
                url=f"https://www.opencve.io/cve/{vuln_id}",
                base_score=str(base_score),
                base_severity=self._get_severity(base_score),
                reference_urls=set(references),
                vulnerable_components=set(affected_products),
                tags=set(["opencve"] + vuln_data.get("tags", [])),
                weaknesses=set(vuln_data.get("weaknesses", [])),
                patched_versions=None  # OpenCVE doesn't provide patched versions
            )
            
            return vulnerability.dict()
            
        except Exception as e:
            logger.error(f"Error processing vulnerability {vuln_data.get('id', 'unknown')}: {e}")
            return None
    
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
    
    def _read_json_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Read and parse a JSON file."""
        try:
            with open(file_path, 'r') as f:
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
            return sorted(years, reverse=True)
        except Exception as e:
            logger.error(f"Error getting available years: {e}")
            return []

    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from OpenCVE."""
        try:
            logger.info("Getting latest vulnerabilities from OpenCVE")
            
            # Ensure repository is initialized
            if not self._repo_initialized:
                logger.info("Initializing repository...")
                self.initialize()
            
            vulnerabilities = []
            available_years = self._get_available_years()
            
            if not available_years:
                logger.error("No available years found in repository")
                return []
            
            # Start with the most recent year
            for year in available_years:
                # Read the year's index
                index_path = os.path.join(self.repo_dir, str(year), "index.json")
                index_data = self._read_json_file(index_path)
                
                if not index_data or "cves" not in index_data:
                    logger.warning(f"No valid index data for year {year}")
                    continue
                
                # Process CVEs in reverse order (newest first)
                for cve_id in reversed(index_data["cves"]):
                    cve_path = os.path.join(self.repo_dir, str(year), f"{cve_id}.json")
                    vuln_data = self._read_json_file(cve_path)
                    
                    if vuln_data:
                        processed_vuln = self._process_vulnerability(vuln_data)
                        if processed_vuln:
                            vulnerabilities.append(processed_vuln)
            
            # Update last update time
            if vulnerabilities:
                latest_date = max(datetime.fromisoformat(v["date"]) for v in vulnerabilities)
                if latest_date > self.last_update:
                    self._save_state(latest_date)
                    self.last_update = latest_date
            
            logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities from OpenCVE")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error fetching vulnerabilities from OpenCVE: {e}")
            return [] 