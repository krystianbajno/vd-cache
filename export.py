#!/usr/bin/env python3
"""
Export script to convert SQLite vulnerability databases to JSON files.
Reads from cache/*/vulns.db and creates source-specific JSON exports.
"""

import os
import json
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import argparse

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def find_vuln_databases() -> List[tuple]:
    """Find all vulns.db files in cache subdirectories."""
    cache_dir = Path("cache")
    databases = []
    
    if not cache_dir.exists():
        logger.warning("Cache directory not found")
        return databases
    
    for source_dir in cache_dir.iterdir():
        if source_dir.is_dir():
            vuln_db = source_dir / "vulns.db"
            if vuln_db.exists():
                databases.append((source_dir.name, str(vuln_db)))
                logger.info(f"Found database: {source_dir.name} -> {vuln_db}")
    
    return databases


def export_vulnerabilities_from_db(db_path: str, source_name: str) -> Dict[str, Any]:
    """Export all vulnerabilities from a SQLite database."""
    vulnerabilities = []
    metadata = {
        "source": source_name,
        "export_time": datetime.now().isoformat(),
        "total_vulnerabilities": 0,
        "database_path": db_path
    }
    
    try:
        with sqlite3.connect(db_path) as conn:
            # Get vulnerability count
            cursor = conn.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_count = cursor.fetchone()[0]
            metadata["total_vulnerabilities"] = total_count
            
            if total_count == 0:
                logger.warning(f"No vulnerabilities found in {source_name} database")
                return {"metadata": metadata, "vulnerabilities": []}
            
            # Export all vulnerabilities
            cursor = conn.execute("""
                SELECT id, data, created_at 
                FROM vulnerabilities 
                ORDER BY created_at
            """)
            
            for row in cursor.fetchall():
                vuln_id, vuln_data, created_at = row
                try:
                    # Parse the JSON data
                    vuln_dict = json.loads(vuln_data)
                    vuln_dict["database_created_at"] = created_at
                    vulnerabilities.append(vuln_dict)
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing vulnerability data for {vuln_id}: {e}")
                    continue
            
            logger.info(f"Exported {len(vulnerabilities)} vulnerabilities from {source_name}")
            
            # Get checkpoint information from checkpoints table
            try:
                cursor = conn.execute("""
                    SELECT checkpoint_type, checkpoint_value, created_at 
                    FROM checkpoints 
                    ORDER BY created_at
                """)
                
                # Build checkpoint data structure
                all_checkpoints = []
                latest_checkpoints = {}
                
                for checkpoint_type, checkpoint_value, created_at in cursor.fetchall():
                    checkpoint_entry = {
                        'type': checkpoint_type,
                        'value': checkpoint_value,
                        'created_at': created_at
                    }
                    all_checkpoints.append(checkpoint_entry)
                    
                    # Track latest checkpoint per type
                    latest_checkpoints[checkpoint_type] = {
                        'value': checkpoint_value,
                        'updated_at': created_at
                    }
                
                # Add comprehensive checkpoint information
                if all_checkpoints:
                    from src.workers.incremental_manager import IncrementalManager
                    
                    # Create a temporary manager to get progress report
                    temp_manager = IncrementalManager(db_path, source_name)
                    progress_report = temp_manager.get_progress_report()
                    
                    metadata["progress_report"] = progress_report
                    metadata["all_checkpoints"] = all_checkpoints
                    metadata["checkpoint_summary"] = {
                        'total_checkpoints': len(all_checkpoints),
                        'checkpoint_types': list(latest_checkpoints.keys()),
                        'latest_checkpoints': latest_checkpoints
                    }
                
            except Exception as e:
                logger.debug(f"Could not read checkpoints from {source_name}: {e}")
    
    except Exception as e:
        logger.error(f"Error reading from database {db_path}: {e}")
        return {"metadata": metadata, "vulnerabilities": []}
    
    return {
        "metadata": metadata,
        "vulnerabilities": vulnerabilities
    }


def create_export_directory() -> Path:
    """Create export directory if it doesn't exist."""
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    logger.info(f"Export directory: {export_dir.absolute()}")
    return export_dir


def export_to_json_file(export_data: Dict[str, Any], source_name: str, export_dir: Path) -> str:
    """Export data to JSON file."""
    output_file = export_dir / f"{source_name}.json"
    
    try:
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str, ensure_ascii=False)
        
        logger.info(f"Exported {source_name} to {output_file}")
        logger.info(f"  - Vulnerabilities: {export_data['metadata']['total_vulnerabilities']}")
        logger.info(f"  - File size: {output_file.stat().st_size / 1024:.1f} KB")
        
        return str(output_file)
    
    except Exception as e:
        logger.error(f"Error writing {output_file}: {e}")
        return ""


def create_consolidated_export(all_exports: List[Dict[str, Any]], export_dir: Path):
    """Create a consolidated export with all sources."""
    consolidated = {
        "metadata": {
            "export_time": datetime.now().isoformat(),
            "sources": [],
            "total_vulnerabilities": 0,
            "vulnerabilities_by_source": {}
        },
        "vulnerabilities": []
    }
    
    for export_data in all_exports:
        source_name = export_data["metadata"]["source"]
        vuln_count = len(export_data["vulnerabilities"])
        
        consolidated["metadata"]["sources"].append(source_name)
        consolidated["metadata"]["total_vulnerabilities"] += vuln_count
        consolidated["metadata"]["vulnerabilities_by_source"][source_name] = vuln_count
        
        # Add all vulnerabilities with source annotation
        for vuln in export_data["vulnerabilities"]:
            vuln["_export_source"] = source_name
            consolidated["vulnerabilities"].append(vuln)
    
    # Sort by scraped_at or created_at
    consolidated["vulnerabilities"].sort(
        key=lambda x: x.get("scraped_at", x.get("database_created_at", ""))
    )
    
    # Export consolidated file
    consolidated_file = export_dir / "all_sources.json"
    try:
        with open(consolidated_file, 'w') as f:
            json.dump(consolidated, f, indent=2, default=str, ensure_ascii=False)
        
        logger.info(f"Created consolidated export: {consolidated_file}")
        logger.info(f"  - Total vulnerabilities: {consolidated['metadata']['total_vulnerabilities']}")
        logger.info(f"  - Sources: {', '.join(consolidated['metadata']['sources'])}")
        logger.info(f"  - File size: {consolidated_file.stat().st_size / 1024:.1f} KB")
        
    except Exception as e:
        logger.error(f"Error creating consolidated export: {e}")


def main():
    """Main export function."""
    parser = argparse.ArgumentParser(description="Export vulnerability databases to JSON")
    parser.add_argument("--source", help="Export only specific source (e.g., packetstorm)")
    parser.add_argument("--output-dir", default="export", help="Output directory (default: export)")
    parser.add_argument("--no-consolidated", action="store_true", help="Skip consolidated export")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON with indentation")
    
    args = parser.parse_args()
    
    logger.info("Starting vulnerability database export...")
    
    # Find all databases
    databases = find_vuln_databases()
    if not databases:
        logger.error("No vulnerability databases found in cache/ directory")
        return
    
    # Filter by source if specified
    if args.source:
        databases = [(name, path) for name, path in databases if name == args.source]
        if not databases:
            logger.error(f"Source '{args.source}' not found")
            return
    
    # Create export directory
    export_dir = Path(args.output_dir)
    export_dir.mkdir(exist_ok=True)
    
    # Export each database
    all_exports = []
    exported_files = []
    
    for source_name, db_path in databases:
        logger.info(f"\nExporting {source_name}...")
        
        export_data = export_vulnerabilities_from_db(db_path, source_name)
        if export_data["vulnerabilities"]:
            output_file = export_to_json_file(export_data, source_name, export_dir)
            if output_file:
                exported_files.append(output_file)
                all_exports.append(export_data)
        else:
            logger.warning(f"No data to export for {source_name}")
    
    # Create consolidated export
    if not args.no_consolidated and len(all_exports) > 1:
        logger.info("\nCreating consolidated export...")
        create_consolidated_export(all_exports, export_dir)
    
    # Summary
    logger.info(f"\n📊 Export Summary:")
    logger.info(f"  - Sources processed: {len(databases)}")
    logger.info(f"  - Files created: {len(exported_files)}")
    logger.info(f"  - Export directory: {export_dir.absolute()}")
    
    if exported_files:
        logger.info("  - Created files:")
        for file_path in exported_files:
            logger.info(f"    • {file_path}")
    
    logger.info("Export completed! 🎉")


if __name__ == "__main__":
    main() 