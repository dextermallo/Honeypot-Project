package main

// CRS-related
const LOG_TIMESTAMP_PATTERN = `^\d{4}\/\d{2}\/\d{2} \d{2}\:\d{2}\:\d{2}`
const LOG_SCORE_PATTERN = `(In|Out)bound Anomaly Score Exceeded \(Total Score: (\d+)\)`
const LOG_CLIENT_PATTERN = `client: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`

// manager-related
const MONITOR_INTERVAL = 5
const ISOLATION_TIMEOUT = 60
const MAX_MEM_RECORD_PER_IP = 1000
const MAX_IP_ACCESSED = 100
const MAX_INBOUND_ACCUMULATE_SCORE = 1e9
const MAX_OUTBOUND_ACCUMULATE_SCORE = 1e9

// container-related
const HONEYPOT_CONTAINER_NAME = "honeypots"
const NETWORK_NAME = "waf-honeypots_default"

var RULE_WHITE_LIST = map[int]bool{949110: true, 949111: true}
