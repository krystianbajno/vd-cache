import os
import logging
import threading
import argparse
from typing import Dict, Any, List
from src.config import Config
from src.workers.factory import WorkerFactory

def parse_arguments():
    """Parse command line arguments for worker selection."""
    available_workers = WorkerFactory.get_available_workers()
    
    parser = argparse.ArgumentParser(
        description="Vulnerability Data Collection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Available workers: {', '.join(available_workers)}

Examples:
  python main.py                           # Run all configured workers
  python main.py --workers packetstorm     # Run only PacketStorm worker
  python main.py --workers enisa,github   # Run multiple specific workers
  python main.py --list-workers           # List available workers
  python main.py --sequential             # Run workers sequentially instead of parallel
        """
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=str,
        help=f"Comma-separated list of workers to run. Available: {', '.join(available_workers)}"
    )
    
    parser.add_argument(
        "--list-workers", "-l",
        action="store_true",
        help="List available workers and exit"
    )
    
    parser.add_argument(
        "--sequential", "-s",
        action="store_true",
        help="Run workers sequentially instead of in parallel"
    )
    
    parser.add_argument(
        "--log-level",
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help="Override log level"
    )
    
    return parser.parse_args()

def select_workers(config: Config, args) -> List[str]:
    """Select which workers to run based on arguments and configuration."""
    available_workers = WorkerFactory.get_available_workers()
    
    if args.workers:
        # Use workers specified via command line
        selected = [w.strip() for w in args.workers.split(",")]
        # Validate worker names
        invalid_workers = [w for w in selected if w not in available_workers]
        if invalid_workers:
            raise ValueError(f"Invalid worker(s): {', '.join(invalid_workers)}. Available: {', '.join(available_workers)}")
        return selected
    else:
        # Use workers from configuration
        return config.get_workers()

def main():
    # Parse command line arguments
    args = parse_arguments()
    
    # List workers and exit if requested
    if args.list_workers:
        available_workers = WorkerFactory.get_available_workers()
        print("Available workers:")
        for worker in available_workers:
            print(f"  • {worker}")
        return
    
    # Load configuration
    config = Config()
    
    # Configure logging
    log_level = args.log_level or config.get_log_level()
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting vulnerability data collection...")
    
    # Select workers to run
    try:
        selected_worker_names = select_workers(config, args)
        if not selected_worker_names:
            logger.warning("No workers selected. Use --workers option, VULNSCOUT_WORKERS env var, or config.yaml")
            return
    except ValueError as e:
        logger.error(str(e))
        return
    
    logger.info(f"Selected workers: {', '.join(selected_worker_names)}")
    
    # Create worker instances
    workers = []
    for worker_name in selected_worker_names:
        try:
            worker = WorkerFactory.create_worker(worker_name, config.get_worker_config(worker_name))
            workers.append(worker)
            logger.info(f"Created worker: {worker_name}")
        except Exception as e:
            logger.error(f"Failed to create worker {worker_name}: {e}")
            continue
    
    if not workers:
        logger.error("No workers could be created")
        return
    
    # Run workers
    if args.sequential:
        # Run workers sequentially
        logger.info("Running workers sequentially...")
        for worker in workers:
            logger.info(f"Starting worker: {worker.name}")
            try:
                worker.run()
                logger.info(f"Completed worker: {worker.name}")
            except Exception as e:
                logger.error(f"Worker {worker.name} failed: {e}")
                continue
    else:
        # Run workers in parallel
        logger.info("Running workers in parallel...")
        threads = []
        for worker in workers:
            thread = threading.Thread(target=worker.run, daemon=True)
            thread.start()
            threads.append(thread)
            logger.info(f"Started worker: {worker.name}")
        
        # Wait for all threads
        for thread in threads:
            thread.join()
    
    logger.info("All workers completed.")

if __name__ == "__main__":
    main() 