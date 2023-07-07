import time
import os
import re
from src.ManagementFramework.utils.const import *
from src.ManagementFramework.utils.logger import logger
from src.ManagementFramework.model.log_ctx import LogCtx
from src.ManagementFramework.model.global_ctx import GlobalCtx
from src.ManagementFramework.model.security_measure_manager import SecurityMeasureManager


class HoneypotManager:
    crs_error_log_path: str
    last_modified: int
    last_line: int
    globalCtx: GlobalCtx

    def __init__(self, crs_error_log_path: str) -> None:
        self.crs_error_log_path = crs_error_log_path
        self.last_modified = 0
        self.last_line = 0
        self.globalCtx = {}
    
    def monitor(self):
        logger.info("Start HoneypotManager.monitor")
        while True:
            modified_time = os.path.getmtime(self.crs_error_log_path)    
            if modified_time > self.last_modified:
                with open(self.crs_error_log_path, 'r') as file:
                    lines = file.readlines()
                    for line in lines[self.last_line:]:
                        logCtx = self.__extract_ctx(line)
                        
                        if logCtx is not None:
                            self.globalCtx.update(logCtx)
                            SecurityMeasureManager.inspect_all(logCtx)

                    logger.info(f"Read: {self.last_line} - {len(lines)}")
                    self.last_line = len(lines)
                file.close()
                self.last_modified = modified_time
            time.sleep(MONITOR_INTERVAL)
        
    def __extract_ctx(self, ctx: str) -> LogCtx:
        logger.info('start HoneypotManager.__extract_ctx')
        timestamp = re.search(LOG_TIMESTAMP_PATTERN, ctx)
        score = re.search(LOG_SCORE_PATTERN, ctx)
        client = re.search(LOG_CLIENT_PATTERN, ctx)
        
        if timestamp and score and client:
            timestamp = timestamp.group(0)
            score_type = score.group(1)
            total_score = score.group(2)
            client_ip = client.group(1)            
            logCtx = LogCtx(client_ip, total_score, score_type == "In", timestamp, [])
            return logCtx
        
        return None
    
 
if __name__ == '__main__':    
    error_log_path = '/Users/dexter/Desktop/GitHub/Honeypot-Project/src/waf-honeypots/logs/modsec3-nginx/error.log'
    honeypotManager = HoneypotManager(error_log_path)
    honeypotManager.monitor()