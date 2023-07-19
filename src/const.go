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

// security-measure-related
var RULE_WHITE_LIST = map[int]bool{949110: true, 949111: true}

const BLOCKING_THRESHOLD = 3

var DIFF_HONEYPOT_IGNORED_LIST = []string{
	"/usr/local/lib/python3.10",
	"/tmp",
	"/usr/local$",
	"/usr/local/lib$",
	"/usr$",
}

const RECENT_ACTIVITY_RESTART_UPPER_BOUND = 10
const RECENT_ACTIVITY_THRESHOLD = 10000

const ACTIVITY_COUNT_CHECK_INTERVAL = 1000
const DISTINCT_IP_CHECK_INTERVAL = 10
const TOTAL_SCORE_CHECK_INTERVAL = 100000
