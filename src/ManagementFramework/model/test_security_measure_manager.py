from src.ManagementFramework.model.security_measure_manager import SecurityMeasureManager
from src.ManagementFramework.model.log_ctx import LogCtx


securityMeasureManager = SecurityMeasureManager()
textCtx = LogCtx('127.0.0.1', 10, False, '2021-10-10', ['test'])
securityMeasureManager.inspect_all(textCtx)