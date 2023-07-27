import subprocess
import time
import os
from typing import Type
import json
import docker
import requests

from enum import Enum

class TestType(Enum):
    ping = 1
    big_query = 2
    malicious = 3

class Service(Enum):
    proxy = ""
    server = ":8001"

ping_command = (
    "ab -n {n} -c {c} http://127.0.0.1{port}/"
)

big_query_command = (
    "ab -n {n} -c {c} "
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " -H 'abcd:efgh'"
    " -H 'ijkl:mnop'"
    " -H 'qrst:uvwx'"
    " -H 'yzab:cdef'"
    " -H 'ghij:klmn'"
    " -H 'opqr:stuv'"
    " -H 'wxyz:abcd'"
    " -H 'efgh:ijkl'"
    " -H 'mnop:qrst'"
    " -H 'uvwx:yzab'"
    " -H 'cdef:ghij'"
    " -H 'klmn:opqr'"
    " -H 'stuv:wxyz'"
    " http://127.0.0.1{port}/\?a\=abcd\&b\=efgh\&c\=ijkl\&d\=mnop\&e\=qrst\&f\=uvwxy\&g\=zabcd\&h\=efghi\&i\=jklmn\&j\=opqrs\&k\=tuvwx\&l\=yzabc\&m\=defgh\&n\=ijklm\&o\=nopqr\&p\=stuvw\&q\=xyzab\&r\=cdefg\&s\=hijkl\&t\=mnopq\&u\=rstuv\&v\=wxyza\&w\=bcdef\&x\=ghijk\&y\=lmnop\&z\=qrst\&a\=uvwxy\&b\=zabcd\&c\=efghi\&d\=jklmn\&e\=opqrs\&f\=tuvwx\&g\=yzabc\&h\=defgh\&i\=ijklm\&j\=nopqr\&k\=stuvw\&l\=xyzab\&m\=cdefg\&n\=hijkl\&o\=mnopq\&p\=rstuv\&q\=wxyza\&r\=bcdef\&s\=ghijk\&t\=lmnop\&u\=opqrs\&v\=tuvwx\&w\=yzabc\&x\=defgh\&y\=ijklm\&z\=nopqr\&a\=stuvw\&b\=xyzab\&c\=cdefg\&d\=hijkl\&e\=mnopq\&f\=rstuv\&g\=wxyza\&h\=bcdef\&i\=ghijk\&j\=lmnop\&k\=opqrs\&l\=tuvwx\&m\=yzabc\&n\=defgh\&o\=ijklm\&p\=nopqr\&q\=rstuv\&r\=wxyza\&s\=bcdef\&t\=ghijk\&u\=lmnop\&v\=opqrs\&w\=tuvwx\&x\=yzabc\&y\=defgh\&z\=ijklm\&a\=nopqr\&b\=rstuv\&c\=wxyza\&d\=bcdef\&e\=ghijk\&f\=lmnop\&g\=opqrs\&h\=tuvwx\&i\=yzabc\&j\=defgh\&k\=ijklm\&l\=nopqr\&m\=rstuv\&n\=wxyza\&o\=bcdef\&p\=ghijk\&q\=lmnop\&r\=opqrs\&s\=tuvwx\&t\=yzabc\&u\=defgh\&v\=ijklm\&w\=nopqr\&x\=rstuv\&y\=wxyza\&z\=bcdef/"
)

malicious_command = (
    "ab -n {n} -c {c} 'http://127.0.0.1{port}/?param=><script>alert(1)</script>'"
)

class TestCase:
    type: TestType
    n: int
    c: int
    port: Service
    command: str
    name: str
    def __init__(self, type: TestType, n: int, c: int, port: Service):
        self.type = type
        self.n = n
        self.c = c
        self.port = port
        self.name = f"{port.name}-{type.name}-n{n}-c{c}"
        
        if type is TestType.ping:
            self.command = ping_command.format(n=n, c=c, port=port.value)
        elif type is TestType.big_query:
            self.command = big_query_command.format(n=n, c=c, port=port.value)
        elif type is TestType.malicious:
            self.command = malicious_command.format(n=n, c=c, port=port.value)
        
        self.command += f" > ./data/{self.name}.txt"

class Collector():
    
    __honeypot_name = "honeypot-1"
    
    def collect(self, test_case: TestCase):
        print("start collect()")
        self.__start_cadvisor()

        proc_data_collector = subprocess.Popen([test_case.command], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc_data_collector.wait()
        
        data_list, timestamp_set = [], set()
        url = f"http://127.0.0.1:8080/api/v1.1/subcontainers/docker/{self.__get_waf_container_id()}"

        self.fetch_data(data_list, timestamp_set, url)
        self.save_json(f"./data/{test_case.name}.json", data_list)
        self.__stop_cadvisor()

    def __start_cadvisor(self):
        print("start __start_cadvisor()")
        cmd = """
        docker run \
        --volume=/:/rootfs:ro \
        --volume=/var/run:/var/run:ro \
        --volume=/sys:/sys:ro \
        --volume=/var/lib/docker/:/var/lib/docker:ro \
        --volume=/dev/disk/:/dev/disk:ro \
        --publish=8080:8080 \
        --detach=true \
        --name=cadvisor \
        --privileged \
        --device=/dev/kmsg \
        gcr.io/cadvisor/cadvisor:v0.45.0
        """    
        
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cnt = 0
        while not self.container_is_healthy("cadvisor") and cnt < 6:
            time.sleep(10)
            cnt += 1
        time.sleep(30)

    def __stop_cadvisor(self):
        print("start __stop_cadvisor()")
        cmd = "docker stop cadvisor && docker rm cadvisor"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
    def __get_waf_container_id(self) -> str:
        print("start __get_waf_container_id()")
        client = docker.from_env()
        container = client.containers.get(self.__honeypot_name)
        return container.id

    def fetch_data(self, data_list: list, timestamp_set: set, url: str):
        print("start fetch_data()")
        response = requests.post(url)

        if response.status_code != 200:
            raise Exception("Response status code is not 200")

        for stats in response.json()[0]["stats"]:
            timestamp = stats["timestamp"]
            if timestamp in timestamp_set:
                continue

            timestamp_set.add(timestamp)
            data_list.append(stats)

    def save_json(self, dist_path: str, data: any, cls: Type[json.JSONEncoder] = None):
        print("start save_json()")
        os.makedirs(os.path.dirname(dist_path), exist_ok=True)
        with open(dist_path, "w+") as file:
            json.dump(data, file, indent=2, cls=cls)
        file.close()
    
    def container_is_healthy(self, name_or_id: str):
        print("start container_is_healthy()")
        return docker.from_env().api.inspect_container(name_or_id)["State"]["Status"] == 'running'

test_case_list = [
        TestCase(TestType.ping, 100, 10, Service.proxy),
        TestCase(TestType.malicious, 100, 10, Service.proxy),
        TestCase(TestType.big_query, 100, 10, Service.proxy),

        TestCase(TestType.ping, 100, 10, Service.server),
        TestCase(TestType.malicious, 100, 10, Service.server),
        TestCase(TestType.big_query, 100, 10, Service.server),
        
        TestCase(TestType.ping, 1000, 100, Service.proxy),
        TestCase(TestType.malicious, 1000, 100, Service.proxy),
        TestCase(TestType.big_query, 1000, 100, Service.proxy),
        
        TestCase(TestType.ping, 1000, 100, Service.server),
        TestCase(TestType.malicious, 1000, 100, Service.server),
        TestCase(TestType.big_query, 1000, 100, Service.server),
        
        TestCase(TestType.ping, 10000, 100, Service.proxy),
        TestCase(TestType.malicious, 10000, 100, Service.proxy),
        TestCase(TestType.big_query, 10000, 100, Service.proxy),
        
        TestCase(TestType.ping, 10000, 100, Service.server),
        TestCase(TestType.malicious, 10000, 100, Service.server),
        TestCase(TestType.big_query, 10000, 100, Service.server),
    ]

if __name__ == "__main__":
    collector = Collector()    
    for test_case in test_case_list:
        collector.collect(test_case)