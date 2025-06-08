import os
import json
import logging
import subprocess
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime
import glob

from plugins.base import SourcePlugin

logger = logging.getLogger(__name__)

class TrickestPlugin(SourcePlugin):
    """Plugin for loading Trickest CVE data."""
    
    @property
    def name(self) -> str:
        return "trickest"
    
    @property
    def description(self) -> str:
        return "Trickest CVE Data Loader"
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Trickest plugin."""
        super().__init__(config)
        self.source_url = "https://github.com/trickest/cve"
        self.cache_dir = os.path.join(config.get("cache", {}).get("dir", "cache"), "trickest")
        self.repo_dir = os.path.join(self.cache_dir, "repo")
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Cache settings
        self.cache_max_age = config.get("cache", {}).get("max_age", 86400)  # 24 hours
        
        # Start repository setup in background
        self._repo_setup_thread = None
        self._repo_ready = False
        self._start_repo_setup()
    
    def _start_repo_setup(self) -> None:
        """Start repository setup in a background thread."""
        def setup_repo():
            try:
                if not os.path.exists(self.repo_dir):
                    logger.info("Cloning Trickest CVE repository...")
                    subprocess.run(
                        ["git", "clone", "https://github.com/trickest/cve.git", self.repo_dir],
                        check=True,
                        capture_output=True
                    )
                    logger.info("Repository cloned successfully")
                else:
                    logger.info("Updating Trickest CVE repository...")
                    subprocess.run(
                        ["git", "-C", self.repo_dir, "pull"],
                        check=True,
                        capture_output=True
                    )
                    logger.info("Repository updated successfully")
                self._repo_ready = True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to setup repository: {e.stderr.decode()}")
            except Exception as e:
                logger.error(f"Unexpected error during repository setup: {e}")
        
        self._repo_setup_thread = threading.Thread(target=setup_repo, daemon=True)
        self._repo_setup_thread.start()
    
    def requires_online(self) -> bool:
        """This plugin requires internet access for initial clone/update."""
        return True
    
    def get_priority(self) -> int:
        """Get the priority of this plugin."""
        return self.config.get("plugins", {}).get(self.name, {}).get("priority", 2)
    
    def _get_cve_data(self) -> Optional[List[Dict[str, Any]]]:
        """
        Get CVE data from the local repository.
        
        Returns:
            List of CVE dictionaries or None if failed
        """
        try:
            # Check cache first
            cache_file = os.path.join(self.cache_dir, "cves.json")
            if os.path.exists(cache_file):
                cache_age = datetime.now().timestamp() - os.path.getmtime(cache_file)
                if cache_age < self.cache_max_age:
                    logger.info(f"Using cached CVE data from {cache_file}")
                    with open(cache_file, 'r') as f:
                        return json.load(f)
            
            # If repository is not ready, return cached data or empty list
            if not self._repo_ready:
                logger.info("Repository not ready yet, using cached data if available")
                if os.path.exists(cache_file):
                    with open(cache_file, 'r') as f:
                        return json.load(f)
                return []
            
            # Get all CVE files from the repository
            cves = []
            cve_dir = os.path.join(self.repo_dir, "cves")
            if not os.path.exists(cve_dir):
                logger.error("CVE directory not found in repository")
                return []
            
            # Process each CVE directory
            for year_dir in glob.glob(os.path.join(cve_dir, "*")):
                if not os.path.isdir(year_dir):
                    continue
                
                for cve_file in glob.glob(os.path.join(year_dir, "*.json")):
                    try:
                        with open(cve_file, 'r') as f:
                            cve_data = json.load(f)
                            cves.append(cve_data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse CVE file {cve_file}: {e}")
            
            # Cache the results
            with open(cache_file, 'w') as f:
                json.dump(cves, f)
            
            logger.info(f"Successfully processed {len(cves)} CVEs")
            return cves
            
        except Exception as e:
            logger.error(f"Error processing CVE data: {e}")
            return None
    
    def _process_vulnerability(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a single CVE from the Trickest database.
        
        Args:
            cve_data: Raw CVE data from Trickest
            
        Returns:
            Processed vulnerability dictionary
        """
        try:
            # Extract required fields
            cve_id = cve_data.get("id")
            if not cve_id:
                logger.warning("Skipping CVE without ID")
                return None
            
            # Create the vulnerability dictionary
            vuln = {
                "id": cve_id,
                "cve_id": cve_id,
                "source": self.name,
                "source_url": self.source_url,
                "url": f"https://github.com/trickest/cve/blob/main/cves/{cve_id}.json",
                "reference_urls": [
                    f"https://github.com/trickest/cve/blob/main/cves/{cve_id}.json",
                    self.source_url
                ],
                "base_score": None,  # Will be enriched by NIST
                "base_severity": cve_data.get("severity", "UNKNOWN"),
                "title": cve_data.get("title", f"Trickest CVE: {cve_id}"),
                "description": cve_data.get("description", ""),
                "vulnerable_components": cve_data.get("affected", []),
                "tags": ["trickest"] + cve_data.get("tags", []),
                "date": cve_data.get("published", datetime.now().isoformat()),
                "vendor": cve_data.get("vendor", "Unknown"),
                "product": cve_data.get("product", "Unknown"),
                "weaknesses": cve_data.get("weaknesses", []),
                "patched_versions": cve_data.get("patched_versions", []),
                "discovered_at": datetime.now().isoformat(),
                "is_exploit": bool(cve_data.get("exploits", [])),  # True if exploits exist
                "trickest_data": cve_data  # Store the original Trickest data
            }
            
            return vuln
            
        except Exception as e:
            logger.error(f"Error processing CVE {cve_data.get('id', 'unknown')}: {e}")
            return None
    
    def search(self, keywords: List[str], max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities matching the keywords.
        
        Args:
            keywords: List of keywords to search for
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Get the CVE data
        cves = self._get_cve_data()
        if not cves:
            return []
        
        # Filter by keywords if provided
        if keywords:
            filtered_cves = []
            for cve in cves:
                # Check if any keyword matches in various fields
                if any(kw.lower() in str(cve.get(field, "")).lower() 
                      for kw in keywords 
                      for field in ["id", "title", "description", "affected"]):
                    filtered_cves.append(cve)
            cves = filtered_cves
        
        # Process CVEs
        results = []
        for cve_data in cves[:max_results]:
            processed_vuln = self._process_vulnerability(cve_data)
            if processed_vuln:
                results.append(processed_vuln)
        
        return results
    
    def get_latest(self, max_results: int = 100) -> List[Dict[str, Any]]:
        """
        Get the latest vulnerabilities from the Trickest database.
        
        Args:
            max_results: Maximum number of results to return
            
        Returns:
            List of vulnerability dictionaries
        """
        # Get the CVE data
        cves = self._get_cve_data()
        if not cves:
            return []
        
        # Sort by published date (newest first)
        cves.sort(key=lambda x: x.get("published", ""), reverse=True)
        
        # Process CVEs
        results = []
        for cve_data in cves[:max_results]:
            processed_vuln = self._process_vulnerability(cve_data)
            if processed_vuln:
                results.append(processed_vuln)
        
        return results 