import os
import json
import logging
import requests
import zipfile
import io
from typing import List, Dict, Any
from datetime import datetime
from .base import BaseWorker
from src.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

class GitHubAdvisoryWorker(BaseWorker):
    """Worker for fetching security advisories from GitHub Advisory Database."""
    
    @property
    def name(self) -> str:
        return "github"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch security advisories from GitHub Advisory Database."""
        try:
            # Download ZIP archive
            zip_url = "https://github.com/github/advisory-database/archive/refs/heads/main.zip"
            headers = {
                "User-Agent": "VulnScout"
            }

            logger.info("Downloading GitHub advisory database...")
            response = requests.get(zip_url, headers=headers)
            response.raise_for_status()
            
            # Extract ZIP archive
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                # Extract only the advisories directory
                advisories = []
                ecosystems = [
                    "github-actions", "go", "maven", "npm", "nuget", 
                    "pip", "pub", "rubygems", "rust", "swift"
                ]
                
                for ecosystem in ecosystems:
                    ecosystem_path = f"advisory-database-main/advisories/{ecosystem}"
                    try:
                        # Get all JSON files in the ecosystem directory
                        for file_info in zip_ref.infolist():
                            if file_info.filename.startswith(ecosystem_path) and file_info.filename.endswith('.json'):
                                with zip_ref.open(file_info) as f:
                                    advisory_data = json.load(f)
                                    advisory_data['ecosystem'] = ecosystem
                                    advisories.append(advisory_data)
                    except Exception as e:
                        logger.error(f"Error processing ecosystem {ecosystem}: {e}")
                        continue
                
                logger.info(f"Successfully processed {len(advisories)} advisories")
                
                # Process advisories into vulnerabilities
                vulns = []
                for advisory in advisories:
                    try:
                        # Extract CVE ID if available
                        cve_id = None
                        for ref in advisory.get("references", []):
                            if ref.get("type") == "CVE":
                                cve_id = ref.get("url", "").split("/")[-1]
                                break
                        
                        # Create vulnerability model
                        vulnerability = Vulnerability(
                            id=f"github-{advisory.get('id')}",  # Unique identifier
                            cve_id=cve_id,  # CVE ID if available
                            source_id=advisory.get("id"),  # GitHub advisory ID
                            title=advisory.get("summary", ""),
                            description=advisory.get("details", ""),
                            date=advisory.get("published", datetime.now().isoformat()),
                            source=self.name,
                            source_type="base",
                            url=f"https://github.com/advisories/{advisory.get('id')}",
                            base_score=str(advisory.get("database_specific", {}).get("cvss", {}).get("score", "0.0")),
                            base_severity=advisory.get("database_specific", {}).get("severity", "UNKNOWN"),
                            reference_urls=set(ref.get("url") for ref in advisory.get("references", []) if ref.get("url")),
                            vulnerable_components={advisory.get("affected", [{}])[0].get("package", {}).get("name", "")},
                            tags=set(["github-advisory"] + advisory.get("database_specific", {}).get("cwe_ids", [])),
                            weaknesses=set(advisory.get("database_specific", {}).get("cwe_ids", [])),
                            patched_versions=advisory.get("affected", [{}])[0].get("ranges", [{}])[0].get("events", [{}])[0].get("fixed", None)
                        )
                        
                        vulns.append(vulnerability.dict())
                    except Exception as e:
                        logger.error(f"Error processing advisory {advisory.get('id', 'unknown')}: {e}")
                        continue
                
                return vulns
            
        except Exception as e:
            logger.error(f"Error fetching advisories from GitHub Advisory Database: {e}")
            return [] 