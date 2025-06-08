import os
import json
import logging
import sqlite3
import threading
import time
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from src.config import Config
from src.models.vulnerability import Vulnerability
from .incremental_manager import IncrementalManager

logger = logging.getLogger(__name__)

class BaseWorker(ABC):
    """Base class for all vulnerability workers with simplified incremental processing."""
    
    def __init__(self, config):
        # Handle both Config object and dictionary
        if hasattr(config, 'workers'):
            # Config object
            self.config = config
            self.worker_config = getattr(config, 'workers', {}).get(self.name, {})
        else:
            # Dictionary config (from factory)
            self.config = None
            self.worker_config = config
        
        self._init_cache()
        
        # Initialize incremental manager (handles DB initialization)
        self.incremental_manager = IncrementalManager(self.db_path, self.name)
        
        # Export file path
        self.export_file = os.path.join(self.cache_dir, f"{self.name}_export.json")
    
    def _init_cache(self):
        """Initialize cache directory for this worker."""
        self.cache_dir = os.path.join("cache", self.name)
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Each worker gets its own database
        self.db_path = os.path.join(self.cache_dir, "vulns.db")
    
    def _init_db(self):
        """Initialize the SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            # Main vulnerabilities table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Index for fast lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_id 
                ON vulnerabilities(id)
            """)
            
            conn.commit()
        
        logger.info(f"[{self.name}] Database initialized at {self.db_path}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this worker."""
        pass
    
    @property
    def last_update(self) -> datetime:
        """Get the last update timestamp."""
        return self.incremental_manager.get_last_update()
    
    def is_item_processed(self, item_id: str) -> bool:
        """Check if an item has already been processed (exists in vulnerabilities table)."""
        return self.incremental_manager.is_item_processed(item_id)
    
    def get_latest_checkpoint(self, checkpoint_type: str) -> str:
        """Get latest checkpoint for incremental processing."""
        return self.incremental_manager.get_latest_checkpoint(checkpoint_type)
    
    def set_checkpoint(self, checkpoint_type: str, checkpoint_value: str):
        """Set checkpoint for incremental processing."""
        self.incremental_manager.set_checkpoint(checkpoint_type, checkpoint_value)
    
    def get_all_checkpoints(self, checkpoint_type: str) -> List[str]:
        """Get all checkpoints for comparison with available items."""
        return self.incremental_manager.get_all_checkpoints(checkpoint_type)
    
    def save_vulnerability_realtime(self, vulnerability: Dict[str, Any]):
        """Save a single vulnerability immediately to database (real-time saving)."""
        if not vulnerability or not vulnerability.get("id"):
            logger.warning("Skipping vulnerability without ID")
            return False
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Convert dict to Vulnerability model for validation
                if isinstance(vulnerability, dict):
                    vuln_obj = Vulnerability(**vulnerability)
                else:
                    vuln_obj = vulnerability
                
                # Store vulnerability as JSON
                conn.execute(
                    "INSERT OR REPLACE INTO vulnerabilities (id, data) VALUES (?, ?)",
                    (vulnerability["id"], json.dumps(vuln_obj.to_dict()))
                )
                conn.commit()
                logger.debug(f"[{self.name}] Saved vulnerability: {vulnerability['id']}")
                return True
                
        except Exception as e:
            logger.error(f"[{self.name}] Error saving vulnerability {vulnerability.get('id', 'unknown')}: {e}")
            return False
    
    def export_to_json(self, output_file: str = None) -> str:
        """Export all processed vulnerabilities to JSON file."""
        if not output_file:
            output_file = self.export_file
        
        try:
            vulnerabilities = []
            
            # Read all vulnerabilities from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT id, data FROM vulnerabilities ORDER BY created_at")
                for row in cursor.fetchall():
                    vuln_id, vuln_data = row
                    try:
                        vuln_dict = json.loads(vuln_data)
                        vulnerabilities.append(vuln_dict)
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing vulnerability data for {vuln_id}: {e}")
                        continue
            
            # Create export metadata
            export_data = {
                'metadata': {
                    'source': self.name,
                    'export_time': datetime.now().isoformat(),
                    'total_vulnerabilities': len(vulnerabilities),
                    'progress_report': self.incremental_manager.get_progress_report(),
                    'last_update': self.last_update.isoformat()
                },
                'vulnerabilities': vulnerabilities
            }
            
            # Write to JSON file
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"[{self.name}] Exported {len(vulnerabilities)} vulnerabilities to {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            raise
    
    def get_progress_report(self) -> Dict[str, Any]:
        """Get detailed progress report."""
        return self.incremental_manager.get_progress_report()

    @abstractmethod
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from the source."""
        pass

    def run(self) -> None:
        """Run the worker to fetch vulnerabilities with simplified processing."""
        try:
            logger.info(f"[{self.name}] Starting vulnerability collection (last update: {self.last_update.isoformat()})")
            
            # Fetch vulnerabilities (with real-time saving built into workers)
            vulns = self.fetch_vulnerabilities()
            
            # Export to JSON if we have vulnerabilities
            if vulns:
                self.export_to_json()
                logger.info(f"[{self.name}] Completed: {len(vulns)} new vulnerabilities processed")
            else:
                logger.info(f"[{self.name}] No new vulnerabilities found")
            
            return vulns
        except Exception as e:
            logger.error(f"[{self.name}] Error in worker: {e}")
            raise 