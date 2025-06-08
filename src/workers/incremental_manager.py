"""
Simplified incremental processing manager with smart checkpoints.
Uses vulnerabilities table + checkpoints table for tracking progress.
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, Any, Set, Optional, List

logger = logging.getLogger(__name__)


class IncrementalManager:
    """Manages incremental processing with smart checkpoints."""
    
    def __init__(self, db_path: str, worker_name: str):
        self.db_path = db_path
        self.worker_name = worker_name
        self._init_db()
    
    def _init_db(self):
        """Initialize database tables for vulnerability storage and checkpoints."""
        with sqlite3.connect(self.db_path) as conn:
            # Main vulnerabilities table - source of truth
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Smart checkpoints table - newest entry is current checkpoint
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    checkpoint_type TEXT NOT NULL,
                    checkpoint_value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Index for fast lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_checkpoints_type_created 
                ON checkpoints(checkpoint_type, created_at DESC)
            """)
            
            conn.commit()
    
    def get_last_update(self) -> datetime:
        """Get the last update timestamp from vulnerabilities."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT MAX(created_at) FROM vulnerabilities"
            )
            row = cursor.fetchone()
            if row and row[0]:
                try:
                    return datetime.fromisoformat(row[0])
                except ValueError:
                    pass
        return datetime(2000, 1, 1)
    
    def get_latest_checkpoint(self, checkpoint_type: str) -> Optional[str]:
        """Get the latest checkpoint value for a given type."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT checkpoint_value FROM checkpoints 
                WHERE checkpoint_type = ? 
                ORDER BY created_at DESC 
                LIMIT 1
            """, (checkpoint_type,))
            row = cursor.fetchone()
            return row[0] if row else None
    
    def set_checkpoint(self, checkpoint_type: str, checkpoint_value: str):
        """Set a new checkpoint (newest entry becomes current)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO checkpoints (checkpoint_type, checkpoint_value) 
                VALUES (?, ?)
            """, (checkpoint_type, checkpoint_value))
            conn.commit()
        logger.info(f"[{self.worker_name}] Checkpoint set: {checkpoint_type} = {checkpoint_value}")
    
    def get_all_checkpoints(self, checkpoint_type: str) -> List[str]:
        """Get all checkpoints for a type (for comparison with available items)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT checkpoint_value FROM checkpoints 
                WHERE checkpoint_type = ? 
                ORDER BY created_at ASC
            """, (checkpoint_type,))
            return [row[0] for row in cursor.fetchall()]
    
    def is_item_processed(self, item_id: str) -> bool:
        """Check if an item has been processed by checking vulnerabilities table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT 1 FROM vulnerabilities WHERE id = ? LIMIT 1",
                (item_id,)
            )
            return cursor.fetchone() is not None
    
    def get_vulnerability_count(self) -> int:
        """Get total count of stored vulnerabilities."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
            return cursor.fetchone()[0]
    
    def get_progress_report(self) -> Dict[str, Any]:
        """Get progress report with checkpoint information."""
        with sqlite3.connect(self.db_path) as conn:
            # Get vulnerability count
            cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            
            # Get latest checkpoints by type
            cursor = conn.execute("""
                SELECT checkpoint_type, checkpoint_value, MAX(created_at) as latest
                FROM checkpoints 
                GROUP BY checkpoint_type
                ORDER BY latest DESC
            """)
            checkpoints = {}
            for row in cursor.fetchall():
                checkpoints[row[0]] = {
                    'value': row[1],
                    'updated_at': row[2]
                }
            
            return {
                'worker': self.worker_name,
                'vulnerabilities_stored': vuln_count,
                'last_update': self.get_last_update().isoformat(),
                'checkpoints': checkpoints
            } 