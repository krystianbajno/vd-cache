import os
import logging
import threading
from typing import Dict, Any
from src.config import Config
from src.workers.factory import WorkerFactory

def main():
    # Load configuration
    config = Config()
    
    # Configure logging
    logging.basicConfig(
        level=config.get_log_level(),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Starting vulnerability data collection...")
    
    # Create workers based on configuration
    workers = WorkerFactory.create_workers(config)
    if not workers:
        logger.warning("No workers enabled. Use VULNSCOUT_WORKERS env var or config.yaml to enable workers.")
        return
    
    # Run all workers in separate threads
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