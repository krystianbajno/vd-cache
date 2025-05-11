import os
import json
import logging
import sqlite3
import threading
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from src.config import Config
from src.models.vulnerability import VulnerabilityIntelligence

logger = logging.getLogger(__name__)

class BaseWorker(ABC):
    """Base class for all vulnerability data workers."""
    
    def __init__(self, config: Config):
        """Initialize the worker with configuration."""
        self.config = config
        self.worker_config = config.get_worker_config(self.name)
        self._init_cache()
    
    def _init_cache(self):
        """Initialize cache directory and database."""
        self.cache_dir = os.path.join(self.config.get_cache_dir(), self.name)
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # SQLite database
        self.db_path = os.path.join(self.cache_dir, "vulns.db")
        self._init_db()
        
        # State file for tracking last update
        self.state_file = os.path.join(self.cache_dir, "state.json")
        self.last_update = self._load_state()
    
    def _init_db(self):
        """Initialize SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS all_ids (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the worker."""
        pass
    
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
    
    @abstractmethod
    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from the source."""
        pass
    
    def cache_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """Cache vulnerabilities in SQLite."""
        if not vulns:
            logger.warning("No vulnerabilities to cache")
            return
        
        try:
            logger.info(f"Opening database at {self.db_path}")
            with sqlite3.connect(self.db_path) as conn:
                # Store each vulnerability
                for vuln in vulns:
                    vuln_id = vuln.get("id")
                    if vuln_id:
                        try:
                            # Try to load existing vulnerability intelligence
                            cursor = conn.execute(
                                "SELECT data FROM vulnerabilities WHERE id = ?",
                                (vuln_id,)
                            )
                            row = cursor.fetchone()
                            
                            if row:
                                # Update existing intelligence
                                existing_data = json.loads(row[0])
                                intelligence = VulnerabilityIntelligence(**existing_data)
                            else:
                                # Create new intelligence
                                intelligence = VulnerabilityIntelligence(id=vuln_id)
                            
                            # Add the new vulnerability data
                            intelligence.add_vulnerability(vuln)
                            
                            # Store updated intelligence
                            conn.execute(
                                "INSERT OR REPLACE INTO vulnerabilities (id, data) VALUES (?, ?)",
                                (vuln_id, json.dumps(intelligence.to_dict()))
                            )
                        except Exception as e:
                            logger.error(f"Error inserting vulnerability {vuln_id}: {e}")
                    else:
                        logger.warning(f"Skipping vulnerability without ID: {vuln}")
                
                # Store all IDs
                vuln_ids = [v.get("id") for v in vulns if v.get("id")]
                if vuln_ids:
                    try:
                        # Clear existing IDs
                        conn.execute("DELETE FROM all_ids")
                        # Insert new IDs
                        conn.executemany(
                            "INSERT INTO all_ids (id) VALUES (?)",
                            [(id,) for id in vuln_ids]
                        )
                        logger.info(f"Updated all_ids table with {len(vuln_ids)} IDs")
                    except Exception as e:
                        logger.error(f"Error updating all_ids table: {e}")
                else:
                    logger.warning("No valid IDs to store in all_ids table")
                
                conn.commit()
                logger.info(f"Successfully committed {len(vulns)} vulnerabilities to database")
            
            logger.info(f"Cached {len(vulns)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error caching vulnerabilities: {e}")
            logger.error(f"Database path: {self.db_path}")
            logger.error(f"Number of vulnerabilities: {len(vulns)}")
            raise
    
    def run(self) -> None:
        """Run the worker to fetch vulnerabilities."""
        try:
            logger.info(f"Fetching {self.name} vulnerabilities (last update: {self.last_update.isoformat()})")
            # Fetch new vulnerabilities
            vulns = self.fetch_vulnerabilities()
            
            # Cache them if we have any
            if vulns:
                self.cache_vulnerabilities(vulns)
                
                # Update last update time
                try:
                    # Filter out vulnerabilities without published_at
                    vulns_with_dates = [v for v in vulns if v.get("published_at")]
                    if vulns_with_dates:
                        latest_date = max(datetime.fromisoformat(v["published_at"]) for v in vulns_with_dates)
                        if latest_date > self.last_update:
                            self._save_state(latest_date)
                            self.last_update = latest_date
                    else:
                        logger.warning("No vulnerabilities with valid dates found")
                except (KeyError, ValueError) as e:
                    logger.error(f"Error processing dates: {e}")
            else:
                logger.warning(f"No vulnerabilities found for {self.name}")
            
            return vulns
        except Exception as e:
            logger.error(f"Error in worker loop: {e}")
            raise 