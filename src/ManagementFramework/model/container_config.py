from typing import List, Union
from pydantic import BaseModel


class ContainerConfig(BaseModel):
    image: str
    name: str
    # {'2222/tcp': 3333}
    ports: dict
    detach: bool = True
    
    # {'/home/user1/': {'bind': '/mnt/vol2', 'mode': 'rw'},
    # '/var/www': {'bind': '/mnt/vol1', 'mode': 'ro'}}
    volumes: Union[dict, None] = None
    network: Union[str, None] = None
    tty: Union[bool, None] = None
    
    entrypoint: Union[List[str], None] = None
    command: Union[str, None] = None
    
    # private | host
    cgroupns: Union[str, None] = None
    cap_add: Union[List[str], None] = None
    cap_drop: Union[List[str], None] = None
    pids_limit: Union[int, None] = None
    read_only: Union[bool, None] = None
    
    # perf
    blkio_weight: Union[int, None] = None
    mem_limit: Union[int, None] = None
    cpu_shares: Union[int, None] = None
    kernel_memory: Union[int, None] = None
    restart_policy: Union[dict, None] = None