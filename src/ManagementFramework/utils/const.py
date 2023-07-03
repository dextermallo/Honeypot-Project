# CRS-related
LOG_TIMESTAMP_PATTERN = r"^\d{4}\/\d{2}\/\d{2} \d{2}\:\d{2}\:\d{2}"
LOG_SCORE_PATTERN = r"(In|Out)bound Anomaly Score Exceeded \(Total Score: (\d+)\)"
LOG_CLIENT_PATTERN = r"client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# manager-related
MONITOR_INTERVAL = 5
ISOLATION_TIMEOUT = 60
MAX_MEM_RECORD_PER_IP = 1000
MAX_IP_ACCESSED = 100
MAX_INBOUND_ACCUMULATE_SCORE = 1e9
MAX_OUTBOUND_ACCUMULATE_SCORE = 1e9


# container-related
HONEYPOT_CONTAINER_NAME = 'honeypots'
NETWORK_NAME = 'waf-honeypots_default'