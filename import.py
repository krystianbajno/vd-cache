#!/usr/bin/env python3
"""
Import script for processing JSON export files and creating SQLite database.
Imports vulnerabilities and checkpoint data from JSON exports.
"""

import sqlite3
import json
import logging
import argparse
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulnerabilityImporter:
    """Imports vulnerabilities and checkpoints from JSON export to SQLite database."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
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
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_id 
                ON vulnerabilities(id)
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_checkpoints_type_created 
                ON checkpoints(checkpoint_type, created_at DESC)
            """)
            
            conn.commit()
        
        logger.info(f"Database initialized at {self.db_path}")
    
    def import_from_json(self, json_file_path: str, overwrite: bool = False) -> Dict[str, Any]:
        """
        Import vulnerabilities and checkpoints from JSON export file.
        
        Args:
            json_file_path: Path to the JSON export file
            overwrite: If True, overwrite existing records; if False, skip duplicates
            
        Returns:
            Dictionary with import statistics
        """
        logger.info(f"Starting import from {json_file_path}")
        
        # Load JSON data
        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                export_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading JSON file: {e}")
            raise
        
        # Validate JSON structure
        if 'metadata' not in export_data or 'vulnerabilities' not in export_data:
            raise ValueError("Invalid JSON structure - missing metadata or vulnerabilities")
        
        metadata = export_data['metadata']
        vulnerabilities = export_data['vulnerabilities']
        
        logger.info(f"Import source: {metadata.get('source', 'unknown')}")
        logger.info(f"Export time: {metadata.get('export_time', 'unknown')}")
        logger.info(f"Total vulnerabilities in export: {len(vulnerabilities)}")
        
        # Import vulnerabilities
        stats = self._import_vulnerabilities(vulnerabilities, overwrite)
        
        # Import checkpoints from multiple sources
        checkpoint_stats = {'checkpoints_imported': 0}
        
        # Import from progress_report.checkpoints (latest checkpoints)
        if 'progress_report' in metadata and 'checkpoints' in metadata['progress_report']:
            latest_stats = self._import_checkpoints(metadata['progress_report']['checkpoints'])
            checkpoint_stats['checkpoints_imported'] += latest_stats.get('checkpoints_imported', 0)
        
        # Import from all_checkpoints (full history) - preferred
        if 'all_checkpoints' in metadata:
            history_stats = self._import_checkpoint_history(metadata['all_checkpoints'])
            checkpoint_stats['checkpoints_imported'] += history_stats.get('checkpoints_imported', 0)
            checkpoint_stats['checkpoint_history_imported'] = history_stats.get('checkpoints_imported', 0)
        
        stats.update(checkpoint_stats)
        
        logger.info(f"Import completed: {stats}")
        return stats
    
    def _import_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], overwrite: bool) -> Dict[str, Any]:
        """Import vulnerabilities into the database."""
        imported_count = 0
        skipped_count = 0
        error_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            for vuln in vulnerabilities:
                try:
                    vuln_id = vuln.get('id')
                    if not vuln_id:
                        logger.warning("Vulnerability missing ID, skipping")
                        error_count += 1
                        continue
                    
                    # Check if vulnerability already exists
                    cursor = conn.execute("SELECT 1 FROM vulnerabilities WHERE id = ?", (vuln_id,))
                    exists = cursor.fetchone() is not None
                    
                    if exists and not overwrite:
                        skipped_count += 1
                        continue
                    
                    # Prepare vulnerability data for storage
                    vuln_json = json.dumps(vuln, ensure_ascii=False)
                    
                    # Use original scraped_at if available, otherwise current timestamp
                    created_at = vuln.get('scraped_at') or vuln.get('database_created_at') or datetime.now().isoformat()
                    
                    if exists and overwrite:
                        # Update existing record
                        conn.execute("""
                            UPDATE vulnerabilities 
                            SET data = ?, created_at = ? 
                            WHERE id = ?
                        """, (vuln_json, created_at, vuln_id))
                    else:
                        # Insert new record
                        conn.execute("""
                            INSERT INTO vulnerabilities (id, data, created_at) 
                            VALUES (?, ?, ?)
                        """, (vuln_id, vuln_json, created_at))
                    
                    imported_count += 1
                    
                except Exception as e:
                    logger.error(f"Error importing vulnerability {vuln.get('id', 'unknown')}: {e}")
                    error_count += 1
                    continue
            
            conn.commit()
        
        return {
            'vulnerabilities_imported': imported_count,
            'vulnerabilities_skipped': skipped_count,
            'vulnerabilities_errors': error_count
        }
    
    def _import_checkpoints(self, checkpoints_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import checkpoints from export data."""
        imported_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            for checkpoint_type, checkpoint_info in checkpoints_data.items():
                try:
                    checkpoint_value = checkpoint_info.get('value')
                    updated_at = checkpoint_info.get('updated_at')
                    
                    if not checkpoint_value:
                        logger.warning(f"Checkpoint {checkpoint_type} missing value, skipping")
                        continue
                    
                    # Insert checkpoint (allow duplicates as history is important)
                    conn.execute("""
                        INSERT INTO checkpoints (checkpoint_type, checkpoint_value, created_at) 
                        VALUES (?, ?, ?)
                    """, (checkpoint_type, checkpoint_value, updated_at or datetime.now().isoformat()))
                    
                    imported_count += 1
                    logger.info(f"Imported checkpoint: {checkpoint_type} = {checkpoint_value}")
                    
                except Exception as e:
                    logger.error(f"Error importing checkpoint {checkpoint_type}: {e}")
                    continue
            
            conn.commit()
        
        return {'checkpoints_imported': imported_count}
    
    def _import_checkpoint_history(self, checkpoint_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Import full checkpoint history from export data."""
        imported_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            for checkpoint_entry in checkpoint_history:
                try:
                    checkpoint_type = checkpoint_entry.get('type')
                    checkpoint_value = checkpoint_entry.get('value')
                    created_at = checkpoint_entry.get('created_at')
                    
                    if not checkpoint_type or not checkpoint_value:
                        logger.warning(f"Checkpoint entry missing required fields: {checkpoint_entry}")
                        continue
                    
                    # Insert checkpoint with original timestamp
                    conn.execute("""
                        INSERT INTO checkpoints (checkpoint_type, checkpoint_value, created_at) 
                        VALUES (?, ?, ?)
                    """, (checkpoint_type, checkpoint_value, created_at or datetime.now().isoformat()))
                    
                    imported_count += 1
                    
                except Exception as e:
                    logger.error(f"Error importing checkpoint history entry {checkpoint_entry}: {e}")
                    continue
            
            conn.commit()
        
        logger.info(f"Imported {imported_count} checkpoint history entries")
        return {'checkpoints_imported': imported_count}
    
    def get_import_summary(self) -> Dict[str, Any]:
        """Get summary of imported data."""
        with sqlite3.connect(self.db_path) as conn:
            # Get vulnerability count
            cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            
            # Get checkpoint count by type
            cursor = conn.execute("""
                SELECT checkpoint_type, COUNT(*) 
                FROM checkpoints 
                GROUP BY checkpoint_type
            """)
            checkpoint_counts = dict(cursor.fetchall())
            
            # Get latest checkpoints
            cursor = conn.execute("""
                SELECT checkpoint_type, checkpoint_value, MAX(created_at) as latest
                FROM checkpoints 
                GROUP BY checkpoint_type
            """)
            latest_checkpoints = {}
            for row in cursor.fetchall():
                latest_checkpoints[row[0]] = {
                    'value': row[1],
                    'updated_at': row[2]
                }
            
            return {
                'total_vulnerabilities': vuln_count,
                'checkpoint_counts': checkpoint_counts,
                'latest_checkpoints': latest_checkpoints
            }


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description='Import vulnerabilities from JSON export to SQLite database')
    parser.add_argument('json_file', help='Path to JSON export file')
    parser.add_argument('--db-path', default='vulns.db', help='SQLite database path (default: vulns.db)')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite existing records')
    parser.add_argument('--summary-only', action='store_true', help='Show summary without importing')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.json_file).exists():
        logger.error(f"JSON file not found: {args.json_file}")
        return 1
    
    # Initialize importer
    importer = VulnerabilityImporter(args.db_path)
    
    if args.summary_only:
        # Just show current database summary
        summary = importer.get_import_summary()
        logger.info(f"Current database summary: {summary}")
        return 0
    
    try:
        # Perform import
        stats = importer.import_from_json(args.json_file, args.overwrite)
        
        # Show final summary
        summary = importer.get_import_summary()
        logger.info(f"Import completed successfully!")
        logger.info(f"Import statistics: {stats}")
        logger.info(f"Database summary: {summary}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Import failed: {e}")
        return 1


if __name__ == '__main__':
    exit(main()) 