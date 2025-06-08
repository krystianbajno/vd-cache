"""
Simple template for creating new vulnerability scrapers.
This demonstrates clean, senior-level code patterns.
"""

import requests
from typing import List, Dict, Any
from datetime import datetime
from .base import BaseWorker
from src.models.vulnerability import Vulnerability, VulnerabilityType


class SimpleTemplateWorker(BaseWorker):
    """
    Template worker showing clean scraper implementation.
    
    To create a new scraper:
    1. Inherit from BaseWorker
    2. Implement fetch_vulnerabilities() 
    3. Use Vulnerability.from_path_and_content() for consistency
    4. Base class handles all database, state, and incremental logic
    """
    
    @property
    def name(self) -> str:
        return "simple_template"
    
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Main scraping logic - kept simple and focused.
        Base class handles caching, incremental processing, etc.
        """
        vulnerabilities = []
        
        # Example: Simple API or web scraping
        items = self._fetch_items_from_source()
        
        for item in items:
            # Check if already processed (handled by base class)
            item_id = Vulnerability.create_id(item['url'])
            if self.is_item_processed(item_id):
                continue
                
            # Create standardized vulnerability
            vuln = Vulnerability.from_path_and_content(
                path_url=item['url'],
                content=item.get('description', ''),
                source=self.name,
                source_id=item['id'],
                type=VulnerabilityType.VULNERABILITY,
                cve_id=item.get('cve_id'),
                title=item['title'],
                description=item['description'],
                severity=item.get('severity', 'MEDIUM'),
                published_at=item['published_date']
            )
            
            vulnerabilities.append(vuln.to_dict())
            
            # Mark as processed (handled by base class)
            self.mark_item_processed(item_id)
        
        return vulnerabilities
    
    def _fetch_items_from_source(self) -> List[Dict[str, Any]]:
        """Source-specific fetching logic."""
        # Example implementation
        try:
            response = requests.get("https://api.example.com/vulnerabilities")
            response.raise_for_status()
            return response.json().get('vulnerabilities', [])
        except Exception as e:
            self.logger.error(f"Error fetching from API: {e}")
            return []


# That's it! Base class handles:
# - Database operations
# - Incremental processing  
# - State management
# - Checkpointing
# - Progress tracking
# - Export functionality
# - Error handling and logging 