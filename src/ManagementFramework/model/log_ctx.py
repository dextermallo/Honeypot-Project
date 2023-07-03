from typing import List


class LogCtx:
    ip: str
    score: int
    isInbound: bool
    timestamp: str
    labels: List[str]
    
    def __init__(self, ip: str, score: int, isInbound: bool, timestamp: str, labels: List[str]) -> None:
        self.ip = ip
        self.score = score
        self.isInbound = isInbound
        self.timestamp = timestamp
        self.labels = labels