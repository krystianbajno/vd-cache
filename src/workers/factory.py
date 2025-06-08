import logging
from typing import List, Dict, Type, Any
from .base import BaseWorker
from .enisa import EnisaWorker
from .packetstorm import PacketStormWorker
from .github import GitHubAdvisoryWorker
from .opencve import OpenCVEWorker
from .exploitdb import ExploitDBWorker
from .cisa_kev import CisaKevWorker
from .nist import NistWorker
from src.config import Config

logger = logging.getLogger(__name__)

class WorkerFactory:
    """Factory for creating vulnerability data workers."""
    
    # Registry of available workers
    _workers: Dict[str, Type[BaseWorker]] = {
        "enisa": EnisaWorker,
        "packetstorm": PacketStormWorker,
        "github": GitHubAdvisoryWorker,
        "opencve": OpenCVEWorker,
        "exploitdb": ExploitDBWorker,
        "cisa_kev": CisaKevWorker,
        "nist": NistWorker
    }
    
    @classmethod
    def create_worker(cls, worker_type: str, config: Dict[str, Any]) -> BaseWorker:
        """Create a worker instance based on the type."""
        if worker_type not in cls._workers:
            raise ValueError(f"Unknown worker type: {worker_type}")
            
        return cls._workers[worker_type](config)
    
    @classmethod
    def get_available_workers(cls) -> List[str]:
        """Get list of available worker types."""
        return list(cls._workers.keys())

    @classmethod
    def create_workers(cls, config: Config) -> List[BaseWorker]:
        """Create worker instances based on configuration."""
        enabled_workers = config.get_workers()
        workers = []
        
        for worker_name in enabled_workers:
            if worker_name not in cls._workers:
                logger.warning(f"Unknown worker: {worker_name}")
                continue
                
            try:
                worker_class = cls._workers[worker_name]
                worker = worker_class(config)
                workers.append(worker)
                logger.info(f"Created worker: {worker_name}")
            except Exception as e:
                logger.error(f"Failed to create worker {worker_name}: {e}")
        
        return workers
    
    @classmethod
    def register_worker(cls, name: str, worker_class: Type[BaseWorker]) -> None:
        """Register a new worker class."""
        cls._workers[name] = worker_class 