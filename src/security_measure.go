package main

import (
	"time"

	"github.com/dexter/owasp-honeypot/utils/container"
	"github.com/dexter/owasp-honeypot/utils/logger"
)

type SecurityMeasure struct {
	name        string
	description string
	passFn      func()
	failFn      func()
	inspect     func(logCtx *LogCtx, globalCtx *GlobalCtx) (bool, error)
}

var SecurityMeasureList = []SecurityMeasure{
	{
		name:        "NetworkIsolationByResource",
		description: "Recent activity >= 10,000 && total isolation <= 10 => network isolation",
		passFn:      nil,
		failFn: func() {
			logger.Info("Disconnecting service from honeypot network")
			container.Disconnect(NETWORK_NAME, HONEYPOT_CONTAINER_NAME)
			time.AfterFunc(30*time.Second, func() {
				logger.Info("Service is back online")
				container.Connect(NETWORK_NAME, HONEYPOT_CONTAINER_NAME)
			})
		},
		inspect: func(lc *LogCtx, gc *GlobalCtx) (bool, error) {
			if gc.getRecentActivityCnt() >= RECENT_ACTIVITY_THRESHOLD && gc.recentActivityBlockTime < RECENT_ACTIVITY_RESTART_UPPER_BOUND {
				gc.recentActivityBlockTime += 1
				logger.Info(gc.recentActivityBlockTime)
				return false, nil
			}
			return true, nil
		},
	},
	{
		name:        "ResourceRestart",
		description: "Recent activity >= 10,000 && total isolation > 10 => restart",
		passFn:      nil,
		failFn: func() {
			container.Restart("honeypot")
		},
		inspect: func(lc *LogCtx, gc *GlobalCtx) (bool, error) {
			if gc.getRecentActivityCnt() >= RECENT_ACTIVITY_THRESHOLD && gc.recentActivityBlockTime >= RECENT_ACTIVITY_RESTART_UPPER_BOUND {
				return false, nil
			}
			return true, nil
		},
	},
}

// total anomaly score += 100,000
// distinct IP count += 10
// total activity count += 1,000
// then, check integrity
