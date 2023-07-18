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
	{
		name:        "PeriodicCheckOnActivityCnt",
		description: "Periodically check on activity count",
		passFn:      nil,
		failFn: func() {
			err := container.CreateHoneypot()
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, gc *GlobalCtx) (bool, error) {
			if gc.activityCnt/ACTIVITY_COUNT_CHECK_INTERVAL > gc.prevActivityCntInterval {
				changes, err := container.Diff(HONEYPOT_CONTAINER_NAME, DIFF_HONEYPOT_IGNORED_LIST)
				gc.prevActivityCntInterval = gc.activityCnt / ACTIVITY_COUNT_CHECK_INTERVAL

				if err != nil {
					logger.Error(err.Error())
					return false, err
				}

				if len(changes) > 0 {
					logger.Error("Changes detected in container filesystem")
					logger.Error(changes)
					return false, nil
				}
			}
			return true, nil
		},
	},
	{
		name:        "PeriodicCheckOnIPCnt",
		description: "Periodically check on IP count",
		passFn:      nil,
		failFn: func() {
			err := container.CreateHoneypot()
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, gc *GlobalCtx) (bool, error) {
			if len(gc.distinctIPSet)/DISTINCT_IP_CHECK_INTERVAL > gc.prevDistinctIPInterval {
				changes, err := container.Diff(HONEYPOT_CONTAINER_NAME, DIFF_HONEYPOT_IGNORED_LIST)
				gc.prevDistinctIPInterval = len(gc.distinctIPSet) / DISTINCT_IP_CHECK_INTERVAL

				if err != nil {
					logger.Error(err.Error())
					return false, err
				}

				if len(changes) > 0 {
					logger.Error("Changes detected in container filesystem")
					logger.Error(changes)
					return false, nil
				}
			}
			return true, nil
		},
	},
	{
		name:        "PeriodicCheckOnTotalScore",
		description: "Periodically check on total score",
		passFn:      nil,
		failFn: func() {
			err := container.CreateHoneypot()
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, gc *GlobalCtx) (bool, error) {
			if gc.inboundAccumulateScore/TOTAL_SCORE_CHECK_INTERVAL > gc.prevTotalScoreInterval {
				changes, err := container.Diff(HONEYPOT_CONTAINER_NAME, DIFF_HONEYPOT_IGNORED_LIST)
				gc.prevTotalScoreInterval = gc.inboundAccumulateScore / TOTAL_SCORE_CHECK_INTERVAL

				if err != nil {
					logger.Error(err.Error())
					return false, err
				}

				if len(changes) > 0 {
					logger.Error("Changes detected in container filesystem")
					logger.Error(changes)
					return false, nil
				}
			}
			return true, nil
		},
	},
}
