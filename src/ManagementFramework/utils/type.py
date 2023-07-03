from typing import Dict, List, Callable, Union
from src.ManagementFramework.model.log_ctx import LogCtx


GateFn = Callable[[LogCtx, Union[Dict[str, List[LogCtx]], None]], bool]
GateNextFn = Callable[[LogCtx, Union[Dict[str, List[LogCtx]], None]], None]