import docker
import time

def check_container_status(container_name):
    client = docker.from_env()
    container = client.containers.get(container_name)
    return container.status

def restart_container(container_name):
    client = docker.from_env()
    container = client.containers.get(container_name)
    container.restart()

def main():
    container_name = "web"
    print('start restart')
    restart_container(container_name)
    print('end restart')
    # cnt = 0
    # while True:
    #     status = check_container_status(container_name)
        
    #     if status != 'running':
    #         print(f"Web server container ({container_name}) is not running. Restarting...")
    #         restart_container(container_name)
    #     else:
    #         print(f"Web server container ({container_name}) is running.")
        
    #     # Adjust the monitoring interval as needed
    #     time.sleep(10)
    #     cnt += 1
    #     if cnt == 6:
    #         break

if __name__ == '__main__':
    main()