#!/usr/bin/env python3
"""
Incremental Processing Manager for VulnScout

This module provides tools for managing incremental vulnerability data processing,
including save/resume functionality, JSON export/import, and progress monitoring.
"""

import os
import sys
import json
import argparse
import logging
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from src.config import Config
from src.workers.factory import WorkerFactory
from src.workers.base import BaseWorker

logger = logging.getLogger(__name__)

class IncrementalManager:
    """Manager for incremental processing operations."""
    
    def __init__(self, config: Config):
        self.config = config
        self.cache_dir = config.get_cache_dir()
        
    def get_worker(self, worker_name: str) -> BaseWorker:
        """Get a worker instance by name."""
        worker_class = WorkerFactory._workers.get(worker_name)
        if not worker_class:
            raise ValueError(f"Unknown worker: {worker_name}")
        return worker_class(self.config)
    
    def list_workers(self) -> List[str]:
        """List all available workers."""
        return list(WorkerFactory._workers.keys())
    
    def get_progress_report(self, worker_name: str) -> Dict[str, Any]:
        """Get progress report for a specific worker."""
        worker = self.get_worker(worker_name)
        return worker.get_progress_report()
    
    def get_all_progress_reports(self) -> Dict[str, Dict[str, Any]]:
        """Get progress reports for all workers."""
        reports = {}
        for worker_name in self.list_workers():
            try:
                reports[worker_name] = self.get_progress_report(worker_name)
            except Exception as e:
                reports[worker_name] = {'error': str(e)}
        return reports
    
    def export_worker_data(self, worker_name: str, output_file: str = None) -> str:
        """Export worker data to JSON file."""
        worker = self.get_worker(worker_name)
        return worker.export_to_json(output_file)
    
    def import_worker_data(self, worker_name: str, import_file: str) -> bool:
        """Import worker data from JSON file."""
        worker = self.get_worker(worker_name)
        return worker.import_from_json(import_file)
    
    def reset_worker_progress(self, worker_name: str) -> bool:
        """Reset progress for a specific worker."""
        try:
            worker = self.get_worker(worker_name)
            
            # Remove progress files
            files_to_remove = [
                worker.progress_file,
                worker.processed_items_file
            ]
            
            for file_path in files_to_remove:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Removed {file_path}")
            
            # Reinitialize worker state
            worker._init_incremental_state()
            
            logger.info(f"Reset progress for worker: {worker_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting worker progress: {e}")
            return False
    
    def resume_worker(self, worker_name: str) -> bool:
        """Resume processing for a specific worker."""
        try:
            worker = self.get_worker(worker_name)
            
            # Check if there's a checkpoint to resume from
            if not worker.resume_from_checkpoint():
                logger.info(f"No checkpoint found for {worker_name}, starting fresh")
                return False
            
            # Run the worker
            logger.info(f"Resuming worker: {worker_name}")
            worker.run()
            
            return True
            
        except Exception as e:
            logger.error(f"Error resuming worker: {e}")
            return False
    
    def create_github_release_json(self, output_dir: str = "releases") -> Dict[str, str]:
        """Create JSON files suitable for GitHub releases."""
        os.makedirs(output_dir, exist_ok=True)
        
        release_files = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for worker_name in self.list_workers():
            try:
                worker = self.get_worker(worker_name)
                
                # Check if worker has any data
                progress = worker.get_progress_report()
                if progress['processed_items'] == 0:
                    logger.info(f"Skipping {worker_name}: no processed items")
                    continue
                
                # Export to release file
                release_file = os.path.join(output_dir, f"{worker_name}_{timestamp}.json")
                exported_file = worker.export_to_json(release_file)
                
                release_files[worker_name] = exported_file
                logger.info(f"Created release file for {worker_name}: {exported_file}")
                
            except Exception as e:
                logger.error(f"Error creating release file for {worker_name}: {e}")
        
        # Create metadata file
        metadata_file = os.path.join(output_dir, f"metadata_{timestamp}.json")
        metadata = {
            'created_at': datetime.now().isoformat(),
            'workers': list(release_files.keys()),
            'files': release_files,
            'total_files': len(release_files)
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        release_files['metadata'] = metadata_file
        return release_files
    
    def export_all_workers_separately(self, output_dir: str = "exports") -> Dict[str, str]:
        """Export each worker's data to separate JSON files."""
        os.makedirs(output_dir, exist_ok=True)
        
        exported_files = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        for worker_name in self.list_workers():
            try:
                worker = self.get_worker(worker_name)
                
                # Check if worker has any data
                progress = worker.get_progress_report()
                if progress['processed_items'] == 0:
                    logger.info(f"Skipping {worker_name}: no processed items")
                    continue
                
                # Export to separate file
                output_file = os.path.join(output_dir, f"{worker_name}_{timestamp}.json")
                exported_file = worker.export_to_json(output_file)
                
                exported_files[worker_name] = exported_file
                logger.info(f"Exported {worker_name} data to: {exported_file}")
                
                # Also create a standardized format file
                standardized_file = os.path.join(output_dir, f"{worker_name}_standardized_{timestamp}.json")
                self._create_standardized_export(worker, standardized_file)
                exported_files[f"{worker_name}_standardized"] = standardized_file
                
            except Exception as e:
                logger.error(f"Error exporting {worker_name}: {e}")
        
        return exported_files
    
    def _create_standardized_export(self, worker: BaseWorker, output_file: str):
        """Create a standardized export format for a worker."""
        try:
            # Get raw vulnerabilities from database
            vulnerabilities = []
            
            with sqlite3.connect(worker.db_path) as conn:
                cursor = conn.execute("SELECT id, data FROM vulnerabilities ORDER BY created_at")
                for row in cursor.fetchall():
                    vuln_id, vuln_data = row
                    try:
                        intelligence_data = json.loads(vuln_data)
                        
                        # Convert VulnerabilityIntelligence to standardized format
                        standardized_vuln = self._standardize_vulnerability(intelligence_data, worker.name)
                        if standardized_vuln:
                            vulnerabilities.append(standardized_vuln)
                            
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing vulnerability data for {vuln_id}: {e}")
                        continue
            
            # Create standardized export
            export_data = {
                'format_version': '1.0',
                'metadata': {
                    'source': worker.name,
                    'export_time': datetime.now().isoformat(),
                    'total_vulnerabilities': len(vulnerabilities),
                    'format': 'standardized',
                    'description': f'Standardized vulnerability data from {worker.name}'
                },
                'vulnerabilities': vulnerabilities
            }
            
            # Write to JSON file
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Created standardized export for {worker.name}: {output_file}")
            
        except Exception as e:
            logger.error(f"Error creating standardized export for {worker.name}: {e}")
    
    def _standardize_vulnerability(self, intelligence_data: Dict[str, Any], source: str) -> Optional[Dict[str, Any]]:
        """Convert VulnerabilityIntelligence data to standardized format."""
        try:
            # Extract the most relevant information
            cve_ids = intelligence_data.get('cve_ids', [])
            primary_cve = cve_ids[0] if cve_ids else None
            
            titles = intelligence_data.get('titles', [])
            primary_title = titles[0]['text'] if titles else f"Vulnerability from {source}"
            
            descriptions = intelligence_data.get('descriptions', [])
            primary_description = descriptions[0]['text'] if descriptions else ""
            
            urls = intelligence_data.get('urls', [])
            primary_url = urls[0]['url'] if urls else ""
            
            dates = intelligence_data.get('dates', [])
            primary_date = dates[0]['date'] if dates else datetime.now().isoformat()
            
            base_scores = intelligence_data.get('base_scores', [])
            primary_score = base_scores[0]['score'] if base_scores else None
            
            severities = intelligence_data.get('severities', [])
            primary_severity = severities[0]['severity'] if severities else "UNKNOWN"
            
            return {
                'id': intelligence_data.get('id'),
                'cve_id': primary_cve,
                'title': primary_title,
                'description': primary_description,
                'published_date': primary_date,
                'source': source,
                'source_url': primary_url,
                'cvss_score': primary_score,
                'severity': primary_severity,
                'reference_urls': list(intelligence_data.get('reference_urls', [])),
                'vulnerable_components': list(intelligence_data.get('vulnerable_components', [])),
                'tags': list(intelligence_data.get('tags', [])),
                'weaknesses': list(intelligence_data.get('weaknesses', [])),
                'all_cve_ids': cve_ids,
                'all_source_ids': intelligence_data.get('source_ids', []),
                'sources': list(intelligence_data.get('sources', [])),
                'first_seen': intelligence_data.get('first_seen'),
                'last_updated': intelligence_data.get('last_updated')
            }
            
        except Exception as e:
            logger.error(f"Error standardizing vulnerability: {e}")
            return None
    
    def create_consolidated_export(self, output_file: str = None) -> str:
        """Create a single consolidated JSON file with data from all workers."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"consolidated_vulnerabilities_{timestamp}.json"
        
        try:
            all_vulnerabilities = []
            worker_stats = {}
            
            for worker_name in self.list_workers():
                try:
                    worker = self.get_worker(worker_name)
                    progress = worker.get_progress_report()
                    
                    if progress['processed_items'] == 0:
                        worker_stats[worker_name] = {'count': 0, 'status': 'no_data'}
                        continue
                    
                    # Get vulnerabilities from this worker
                    with sqlite3.connect(worker.db_path) as conn:
                        cursor = conn.execute("SELECT id, data FROM vulnerabilities ORDER BY created_at")
                        worker_vulns = []
                        
                        for row in cursor.fetchall():
                            vuln_id, vuln_data = row
                            try:
                                intelligence_data = json.loads(vuln_data)
                                standardized_vuln = self._standardize_vulnerability(intelligence_data, worker_name)
                                if standardized_vuln:
                                    worker_vulns.append(standardized_vuln)
                            except json.JSONDecodeError as e:
                                logger.error(f"Error parsing vulnerability data for {vuln_id}: {e}")
                                continue
                        
                        all_vulnerabilities.extend(worker_vulns)
                        worker_stats[worker_name] = {
                            'count': len(worker_vulns),
                            'status': 'success',
                            'progress': progress
                        }
                        
                except Exception as e:
                    worker_stats[worker_name] = {'count': 0, 'status': f'error: {str(e)}'}
                    logger.error(f"Error processing {worker_name}: {e}")
            
            # Sort by date (newest first)
            all_vulnerabilities.sort(
                key=lambda x: x.get('published_date', ''), 
                reverse=True
            )
            
            # Create consolidated export
            export_data = {
                'format_version': '1.0',
                'metadata': {
                    'export_time': datetime.now().isoformat(),
                    'total_vulnerabilities': len(all_vulnerabilities),
                    'format': 'consolidated',
                    'description': 'Consolidated vulnerability data from all workers',
                    'worker_statistics': worker_stats
                },
                'vulnerabilities': all_vulnerabilities
            }
            
            # Write to JSON file
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Created consolidated export with {len(all_vulnerabilities)} vulnerabilities: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error creating consolidated export: {e}")
            raise


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def cmd_status(args, manager: IncrementalManager):
    """Show status of all workers."""
    reports = manager.get_all_progress_reports()
    
    print("\n" + "="*60)
    print("VULNERABILITY DATA PROCESSING STATUS")
    print("="*60)
    
    for worker_name, report in reports.items():
        print(f"\n[{worker_name.upper()}]")
        
        if 'error' in report:
            print(f"  Status: ERROR - {report['error']}")
            continue
        
        print(f"  Phase: {report['current_phase']}")
        print(f"  Progress: {report['processed_items']}/{report['total_items']} items ({report['progress_percentage']}%)")
        print(f"  Completed phases: {', '.join(report['completed_phases'])}")
        
        if report['last_checkpoint']:
            print(f"  Last checkpoint: {report['last_checkpoint']}")
        
        if report['start_time']:
            print(f"  Started: {report['start_time']}")


def cmd_export(args, manager: IncrementalManager):
    """Export worker data to JSON."""
    if args.separate:
        # Export all workers to separate files
        exported_files = manager.export_all_workers_separately(args.output_dir or "exports")
        print(f"\nExported {len(exported_files)} separate files:")
        for worker_name, file_path in exported_files.items():
            print(f"  {worker_name}: {file_path}")
        return
    
    if args.worker == 'all':
        workers = manager.list_workers()
    else:
        workers = [args.worker]
    
    exported_files = []
    
    for worker_name in workers:
        try:
            output_file = args.output
            if len(workers) > 1:
                # Multiple workers - create separate files
                base_name = f"{worker_name}_export.json"
                if args.output:
                    output_dir = os.path.dirname(args.output) or "."
                    output_file = os.path.join(output_dir, base_name)
                else:
                    output_file = base_name
            
            exported_file = manager.export_worker_data(worker_name, output_file)
            exported_files.append(exported_file)
            print(f"Exported {worker_name} data to: {exported_file}")
            
        except Exception as e:
            print(f"Error exporting {worker_name}: {e}")
    
    print(f"\nExported {len(exported_files)} files:")
    for file_path in exported_files:
        print(f"  - {file_path}")


def cmd_import(args, manager: IncrementalManager):
    """Import worker data from JSON."""
    try:
        success = manager.import_worker_data(args.worker, args.input_file)
        if success:
            print(f"Successfully imported data for {args.worker} from {args.input_file}")
        else:
            print(f"Failed to import data for {args.worker}")
    except Exception as e:
        print(f"Error importing data: {e}")


def cmd_reset(args, manager: IncrementalManager):
    """Reset worker progress."""
    if args.worker == 'all':
        workers = manager.list_workers()
    else:
        workers = [args.worker]
    
    for worker_name in workers:
        try:
            success = manager.reset_worker_progress(worker_name)
            if success:
                print(f"Reset progress for {worker_name}")
            else:
                print(f"Failed to reset progress for {worker_name}")
        except Exception as e:
            print(f"Error resetting {worker_name}: {e}")


def cmd_resume(args, manager: IncrementalManager):
    """Resume worker processing."""
    try:
        success = manager.resume_worker(args.worker)
        if success:
            print(f"Successfully resumed {args.worker}")
        else:
            print(f"No checkpoint found for {args.worker} or failed to resume")
    except Exception as e:
        print(f"Error resuming {args.worker}: {e}")


def cmd_release(args, manager: IncrementalManager):
    """Create GitHub release files."""
    try:
        release_files = manager.create_github_release_json(args.output_dir)
        
        print(f"\nCreated {len(release_files)} release files:")
        for worker_name, file_path in release_files.items():
            print(f"  {worker_name}: {file_path}")
        
        print(f"\nFiles ready for GitHub release in: {args.output_dir}")
        
    except Exception as e:
        print(f"Error creating release files: {e}")


def cmd_export_separate(args, manager: IncrementalManager):
    """Export each worker to separate files."""
    try:
        exported_files = manager.export_all_workers_separately(args.output_dir)
        
        print(f"\nExported {len(exported_files)} separate files:")
        for worker_name, file_path in exported_files.items():
            print(f"  {worker_name}: {file_path}")
        
        print(f"\nSeparate files created in: {args.output_dir}")
        
    except Exception as e:
        print(f"Error creating separate export files: {e}")


def cmd_consolidate(args, manager: IncrementalManager):
    """Create consolidated export with all workers."""
    try:
        consolidated_file = manager.create_consolidated_export(args.output_file)
        
        print(f"\nCreated consolidated export: {consolidated_file}")
        
    except Exception as e:
        print(f"Error creating consolidated export: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Incremental Processing Manager for VulnScout",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                           # Show status of all workers
  %(prog)s export --worker packetstorm      # Export PacketStorm data
  %(prog)s export --worker all              # Export all worker data
  %(prog)s import --worker packetstorm --input data.json  # Import data
  %(prog)s reset --worker packetstorm       # Reset progress
  %(prog)s resume --worker packetstorm      # Resume processing
  %(prog)s release --output-dir releases    # Create GitHub release files
        """
    )
    
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Set logging level'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show processing status')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export worker data to JSON')
    export_parser.add_argument('--worker', required=True, 
                              help='Worker name or "all" for all workers')
    export_parser.add_argument('--output', help='Output file path')
    export_parser.add_argument('--separate', action='store_true',
                              help='Export each worker to separate files')
    export_parser.add_argument('--output-dir', default='exports',
                              help='Output directory for separate files')
    
    # Export separate command
    export_separate_parser = subparsers.add_parser('export-separate', 
                                                   help='Export each worker to separate files')
    export_separate_parser.add_argument('--output-dir', default='exports',
                                       help='Output directory for separate files')
    
    # Consolidate command
    consolidate_parser = subparsers.add_parser('consolidate', 
                                              help='Create consolidated export with all workers')
    consolidate_parser.add_argument('--output-file', 
                                   help='Output file for consolidated export')
    
    # Import command
    import_parser = subparsers.add_parser('import', help='Import worker data from JSON')
    import_parser.add_argument('--worker', required=True, help='Worker name')
    import_parser.add_argument('--input-file', required=True, help='Input JSON file')
    
    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Reset worker progress')
    reset_parser.add_argument('--worker', required=True,
                             help='Worker name or "all" for all workers')
    
    # Resume command
    resume_parser = subparsers.add_parser('resume', help='Resume worker processing')
    resume_parser.add_argument('--worker', required=True, help='Worker name')
    
    # Release command
    release_parser = subparsers.add_parser('release', help='Create GitHub release files')
    release_parser.add_argument('--output-dir', default='releases',
                               help='Output directory for release files')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Setup logging
    setup_logging(args.log_level)
    
    try:
        # Initialize configuration and manager
        config = Config()
        manager = IncrementalManager(config)
        
        # Execute command
        if args.command == 'status':
            cmd_status(args, manager)
        elif args.command == 'export':
            cmd_export(args, manager)
        elif args.command == 'export-separate':
            cmd_export_separate(args, manager)
        elif args.command == 'consolidate':
            cmd_consolidate(args, manager)
        elif args.command == 'import':
            cmd_import(args, manager)
        elif args.command == 'reset':
            cmd_reset(args, manager)
        elif args.command == 'resume':
            cmd_resume(args, manager)
        elif args.command == 'release':
            cmd_release(args, manager)
        else:
            print(f"Unknown command: {args.command}")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 