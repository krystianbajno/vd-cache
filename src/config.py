import os
import yaml
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

class Config:
    """Configuration manager that supports both YAML config and environment variables."""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            return config or {}
        except Exception as e:
            logger.warning(f"Failed to load config from {self.config_path}: {e}")
            return {}
    
    def get_workers(self) -> List[str]:
        """Get list of enabled workers from config or environment."""
        # Check environment variable first
        env_workers = os.getenv("VULNSCOUT_WORKERS")
        if env_workers:
            workers = [w.strip() for w in env_workers.split(",")]
            logger.info(f"Using workers from environment: {workers}")
            return workers
        
        # Fall back to config file
        workers = [w.strip() for w in self.config.get("workers", {}).get("enabled", "").split(",")]
        logger.info(f"Using workers from config: {workers}")
        return workers
    
    def get_worker_config(self, worker_name: str) -> Dict[str, Any]:
        """Get configuration for a specific worker."""
        config = self.config.get("workers", {}).get(worker_name, {})
        
        # Check for worker-specific environment variables
        env_prefix = f"VULNSCOUT_{worker_name.upper()}"
        
        # Handle API tokens
        token_env = f"{env_prefix}_TOKEN"
        if token_env in os.environ:
            config["api_token"] = os.environ[token_env]
        
        # Handle max results
        max_results_env = f"{env_prefix}_MAX_RESULTS"
        if max_results_env in os.environ:
            try:
                config["max_results"] = int(os.environ[max_results_env])
            except ValueError:
                logger.warning(f"Invalid {max_results_env} value: {os.environ[max_results_env]}")
        
        return config
    
    def get_log_level(self) -> str:
        """Get logging level from config or environment."""
        return os.getenv("VULNSCOUT_LOG_LEVEL") or self.config.get("logging", {}).get("level", "INFO")
    
    def get_cache_dir(self) -> str:
        """Get cache directory from config."""
        return os.getenv("VULNSCOUT_CACHE_DIR") or self.config.get("cache", {}).get("dir", "cache")
    
    def get_cache_max_age(self) -> int:
        """Get cache maximum age from config."""
        try:
            return int(os.getenv("VULNSCOUT_CACHE_MAX_AGE", 
                                str(self.config.get("cache", {}).get("max_age", 86400))))
        except ValueError:
            logger.warning("Invalid VULNSCOUT_CACHE_MAX_AGE value, using default")
            return 86400 