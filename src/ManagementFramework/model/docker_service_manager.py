import docker
from src.ManagementFramework.utils.logger import logger
from src.ManagementFramework.model.container_config import ContainerConfig
from typing import List


class DockerServiceManager:
    _instance = None
    client: docker.DockerClient
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance
    
    def __init__(self) -> None:
        self.client = docker.from_env()

    def check_container_status(self, container_name):
        logger.info('start DockerServiceManager.check_container_status')
        try:
            container = self.client.containers.get(container_name)
            return container.status
        except Exception as e:
            logger.error(e)

    def restart_container(self, container_name: str):
        logger.info('start DockerServiceManager.restart_container')
        try:
            container = self.client.containers.get(container_name)
            container.restart()
        except Exception as e:
            logger.error(e)
        
    def disconnect_network(self, container_name: str, network_name: str):
        logger.info('start DockerServiceManager.disconnect_network')
        try:
            network = self.client.networks.get(network_name)
            network.disconnect(container_name)
        except Exception as e:
            logger.error(e)
        
    def connect_network(self, container_name: str, network_name: str, aliases: List[str]):
        logger.info('start DockerServiceManager.connect_network')
        try:
            network = self.client.networks.get(network_name)
            network.connect(container_name, aliases=aliases)
        except Exception as e:
            logger.error(e)
         
    def remove_container(self, container_name: str):
        logger.info('start DockerServiceManager.remove_container')
        try:
            container = self.client.containers.get(container_name)
            container.remove()
        except Exception as e:
            logger.error(e)
        
    def kill_container(self, container_name: str):
        logger.info('start DockerServiceManager.stop_container')
        try:
            container = self.client.containers.get(container_name)
            container.kill()
        except Exception as e:
            logger.error(e)
    
    def recreate_container(self, container_name: str, config: ContainerConfig):
        logger.info('start DockerServiceManager.recreate_container')
        try:
            self.kill_container(container_name)
            self.remove_container(container_name)
            self.run_container(container_name, config)
            
        except Exception as e:
            logger.error(e)            
    
    def run_container(self, container_name: str, config: ContainerConfig):
        logger.info('start DockerServiceManager.run_container')
        try:
            self.client.containers.run(
                image=config.image,
                name=container_name,
                ports=config.ports,
                detach=config.detach,
                
                volumes=config.volumes,
                network=config.network,
                tty=config.tty,
                
                entrypoint=config.entrypoint,
                command=config.command,
                
                cgroupns=config.cgroupns,
                cap_add=config.cap_add,
                cap_drop=config.cap_drop,
                pids_limit=config.pids_limit,
                read_only=config.read_only,
                
                mem_limit=config.mem_limit,
            )
        except Exception as e:
            logger.error(e)
    
    # 0=C (change), 1=A(add)
    def diff_container(self, container_name: str) -> List[str]:
        logger.info('start DockerServiceManager.diff_container')
        try:
            container = self.client.containers.get(container_name)
            return container.diff()
        except Exception as e:
            logger.error(e)    
    
    # @TODO: test
    def update_container(self, container_name: str, config: ContainerConfig):
        logger.info('start DockerServiceManager.update_container')
        try:
            container = self.client.containers.get(container_name)
            container.update(
                mem_limit=config.mem_limit,
                cpu_shares=config.cpu_shares,
                blkio_weight=config.blkio_weight,
                kernel_memory=config.kernel_memory,
                restart_policy=config.restart_policy,
            )
        except Exception as e:
            logger.error(e)

    # @TODO: test
    def export_container(self, container_name: str, path: str):
        logger.info('start DockerServiceManager.export_container')
        try:
            container = self.client.containers.get(container_name)
            container.export(path)
        except Exception as e:
            logger.error(e)