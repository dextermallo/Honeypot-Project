import threading
from typing import Union
from enum import Enum
from src.ManagementFramework.utils.type import GateFn, GateNextFn
from src.ManagementFramework.model.global_ctx import GlobalCtx
from src.ManagementFramework.utils.logger import logger
from src.ManagementFramework.model.log_ctx import LogCtx
from src.ManagementFramework.utils.const import *
from src.ManagementFramework.model.docker_service_manager import DockerServiceManager


class SecurityMeasureType(Enum):
    restart = 1
    
    network_isolation = 2
    
    file_system_diff = 3
    
    specific_rule_measure = 4
    
    # use with restart or specific rule measure
    container_exec_changes = 5

class SecurityMeasure():
    name: str
    desc: str
    type: SecurityMeasureType
    passGateFn: GateNextFn
    failGateFn: Union[GateNextFn, None]
    gateFn: GateFn
    
    def __init__(self,
                 name: str,
                 desc: str,
                 type: SecurityMeasureType,
                 gateFn: GateFn,
                 passGateFn: GateNextFn,
                 failGateFn: Union[GateNextFn, None] = None
                 ) -> None:
        self.name = name
        self.desc = desc
        self.type = type
        self.gateFn = gateFn
        self.passGateFn = passGateFn
        self.failGateFn = failGateFn
    
    def inspect(self, ctx: LogCtx, globalCtx: Union[GlobalCtx, None] = None) -> Union[None, bool]:
        result = self.gateFn(ctx, globalCtx)
        
        if result:
            self.passGateFn(ctx, globalCtx)
            return True
        
        if self.failGateFn is not None:
            self.failGateFn(ctx, globalCtx)
            return False
        
        return None
            

"""
Network Isolation Measure
"""
def measure_network_isolation_instance() -> SecurityMeasure:
    def network_isolation_gate_fn(logCtx: LogCtx, _: None) -> bool:
        logger.info('start network_isolation_gate_fn')
        return logCtx.score >= 10

    def network_isolation_pass_gate_fn(*_: None) -> bool:
        logger.info('start network_isolation_pass_gate_fn')
        DockerServiceManager().disconnect_network(HONEYPOT_CONTAINER_NAME, NETWORK_NAME)
        
        def reconnect_network_after_timeout():
            DockerServiceManager().connect_network(HONEYPOT_CONTAINER_NAME, NETWORK_NAME, [HONEYPOT_CONTAINER_NAME])
        
        threading.Timer(ISOLATION_TIMEOUT, reconnect_network_after_timeout).start()
        return True

    return SecurityMeasure(
        name="Network Isolation",
        desc="Isolate the container network with a specific timeout",
        type=SecurityMeasureType.network_isolation,
        gateFn=network_isolation_gate_fn,
        passGateFn=network_isolation_pass_gate_fn,
    )

def measure_restart_instance() -> SecurityMeasure:
    def restart_gate_fn(_: LogCtx, globalCtx: GlobalCtx) -> bool:
        logger.info('start restart_gate_fn')
        return globalCtx.inboundAccumulateScore >= MAX_INBOUND_ACCUMULATE_SCORE \
            or globalCtx.outboundAccumulateScore >= MAX_OUTBOUND_ACCUMULATE_SCORE
    
    def restart_pass_gate_fn(*_: None) -> bool:
        logger.info('start restart_pass_gate_fn')
        DockerServiceManager().restart_container(HONEYPOT_CONTAINER_NAME)
        return True
    
    return SecurityMeasure(
        name="Restart",
        desc="Restart the container",
        type=SecurityMeasureType.restart,
        gateFn=restart_gate_fn,
        passGateFn=restart_pass_gate_fn
    )

def measure_single_ip_frequent_malicious_access() -> SecurityMeasure:
    def ip_frequent_malicious_access_gate_fn(logCtx: LogCtx, globalCtx: GlobalCtx) -> bool:
        logger.info('start ip_frequent_malicious_access_gate_fn')
        return len(globalCtx.raw_ctx[logCtx.ip]) >= MAX_MEM_RECORD_PER_IP
    
    def ip_frequent_malicious_access_pass_gate_fn(*_: None) -> bool:
        logger.info('start ip_frequent_malicious_access_pass_gate_fn')
        DockerServiceManager().restart_container(HONEYPOT_CONTAINER_NAME)
        return True
    
    return SecurityMeasure(
        name="Single IP Frequent Malicious Access",
        desc="Restart the container",
        type= SecurityMeasureType.specific_rule_measure,
        gateFn=ip_frequent_malicious_access_gate_fn,
        passGateFn=ip_frequent_malicious_access_pass_gate_fn
    )
    
    
def measure_resource_limitation_for_frequent_request():
    pass

SECURITY_MEASURE_LIST = [
    measure_network_isolation_instance(),
    measure_single_ip_frequent_malicious_access(),
    measure_restart_instance(),
]