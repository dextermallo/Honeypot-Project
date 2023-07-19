package main

import (
	"strconv"
	"time"

	"github.com/dextermallo/owasp-honeypot/utils/container"
	"github.com/dextermallo/owasp-honeypot/utils/logger"
)

type SecurityMeasure struct {
	name        string
	description string
	passFn      func(honeypotService *HoneypotService)
	failFn      func(honeypotService *HoneypotService)
	inspect     func(logCtx *LogCtx, honeypotService *HoneypotService) (bool, error)
}

var SecurityMeasureList = []SecurityMeasure{
	{
		name:        "NetworkIsolationByResource",
		description: "Recent activity >= 10,000 && total isolation <= 10 => network isolation",
		passFn:      nil,
		failFn: func(honeypotService *HoneypotService) {
			logger.Info("Disconnecting service from honeypot network" + honeypotService.id)
			container.Disconnect(honeypotService.id, honeypotService.network)
			time.AfterFunc(30*time.Second, func() {
				logger.Info("Service is back online")
				container.Connect(honeypotService.network, honeypotService.id)
			})
		},
		inspect: func(lc *LogCtx, honeypotService *HoneypotService) (bool, error) {
			gc := honeypotService.globalCtx
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
		failFn: func(honeypotService *HoneypotService) {
			err := container.CreateHoneypot(honeypotService.id, honeypotService.network)
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, honeypotService *HoneypotService) (bool, error) {
			gc := honeypotService.globalCtx
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
		failFn: func(honeypotService *HoneypotService) {
			err := container.CreateHoneypot(honeypotService.id, honeypotService.network)
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, honeypotService *HoneypotService) (bool, error) {
			gc := honeypotService.globalCtx
			if gc.activityCnt/ACTIVITY_COUNT_CHECK_INTERVAL > gc.prevActivityCntInterval {
				logger.Warning("activity count increased to: " + strconv.Itoa(gc.activityCnt))
				changes, err := container.Diff("honeypot-"+honeypotService.id, DIFF_HONEYPOT_IGNORED_LIST)
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
		failFn: func(honeypotService *HoneypotService) {
			err := container.CreateHoneypot(honeypotService.id, honeypotService.network)
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, honeypotService *HoneypotService) (bool, error) {
			gc := honeypotService.globalCtx
			if len(gc.distinctIPSet)/DISTINCT_IP_CHECK_INTERVAL > gc.prevDistinctIPInterval {
				logger.Warning("distinct IP increased to: " + strconv.Itoa(len(gc.distinctIPSet)))
				changes, err := container.Diff("honeypot-"+honeypotService.id, DIFF_HONEYPOT_IGNORED_LIST)
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
		failFn: func(honeypotService *HoneypotService) {
			err := container.CreateHoneypot(honeypotService.id, honeypotService.network)
			if err != nil {
				logger.Error(err.Error())
			}
		},
		inspect: func(lc *LogCtx, honeypotService *HoneypotService) (bool, error) {
			gc := honeypotService.globalCtx
			if gc.inboundAccumulateScore/TOTAL_SCORE_CHECK_INTERVAL > gc.prevTotalScoreInterval {
				changes, err := container.Diff("honeypot-"+honeypotService.id, DIFF_HONEYPOT_IGNORED_LIST)
				logger.Warning("total score increased to: " + strconv.Itoa(gc.inboundAccumulateScore))

				gc.prevTotalScoreInterval = gc.inboundAccumulateScore / TOTAL_SCORE_CHECK_INTERVAL

				if err != nil {
					logger.Error(err.Error())
					return false, err
				}

				if len(changes) > 0 {
					logger.Error("changes detected in container filesystem")
					logger.Error(changes)
					return false, nil
				}
			}
			return true, nil
		},
	},
}
