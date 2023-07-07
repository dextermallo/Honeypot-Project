from src.ManagementFramework.model.docker_service_manager import DockerServiceManager
from src.ManagementFramework.utils.const import *
from src.ManagementFramework.model.container_config import ContainerConfig


config = ContainerConfig(
    image="justsky/honeypots",
    name=HONEYPOT_CONTAINER_NAME,
    command="--setup all",
    ports={ "80/tcp": None },
    volumes={
        '/Users/dexter/Desktop/GitHub/Honeypot-Project/src/waf-honeypots/logs': { 'bind': '/honeypots/logs', 'mode': 'rw' },
        '/Users/dexter/Desktop/GitHub/Honeypot-Project/src/waf-honeypots/honeypot_config.json': { 'bind': '/honeypots/config.json', 'mode': 'rw' }
    },
    tty=True,
    network=NETWORK_NAME,
    
)

# DockerServiceManager().client.containers.run(
#     image=config.image,
#     name=f"{config.name}-1",
#     ports=config.ports,
#     tty=True,
#     volumes=config.volumes,
# )

# DockerServiceManager().recreate_container(HONEYPOT_CONTAINER_NAME, config)
# print(DockerServiceManager().diff_container(HONEYPOT_CONTAINER_NAME))
