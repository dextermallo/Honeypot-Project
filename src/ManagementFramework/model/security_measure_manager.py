from typing import Union
from src.ManagementFramework.model.security_measure import SECURITY_MEASURE_LIST
from src.ManagementFramework.model.global_ctx import GlobalCtx
from src.ManagementFramework.utils.logger import logger
from src.ManagementFramework.model.log_ctx import LogCtx


class SecurityMeasureManager:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance
    
    def __init__(self) -> None:
        pass
    
    def inspect_all(self, logCtx: LogCtx, globalCtx: Union[GlobalCtx, None] = None) -> None:
        logger.info('start SecurityMeasureManager.inspect_all')
        
        for security_measure in SECURITY_MEASURE_LIST:
            result = security_measure.inspect(logCtx, globalCtx)
            if result is not None:
                return