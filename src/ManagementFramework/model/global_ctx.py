from collections import deque
from typing import Dict
from src.ManagementFramework.model.log_ctx import LogCtx
from src.ManagementFramework.utils.const import *


class GlobalCtx:
    inboundAccumulateScore: int
    outboundAccumulateScore: int
    raw_ctx: Dict[str, deque[LogCtx]]
    
    def __init__(self):
        self.inboundAccumulateScore = MAX_INBOUND_ACCUMULATE_SCORE
        self.outboundAccumulateScore = MAX_OUTBOUND_ACCUMULATE_SCORE
        self.raw_ctx = {}
        
    def update(self, logCtx: LogCtx):
        if logCtx.ip not in self.raw_ctx:
            self.raw_ctx[logCtx.ip] = deque(maxlen=MAX_MEM_RECORD_PER_IP)
        
        self.raw_ctx[logCtx.ip].append(logCtx)
        
        if logCtx.isInbound:
            self.inboundAccumulateScore += logCtx.score
        else:
            self.outboundAccumulateScore += logCtx.score