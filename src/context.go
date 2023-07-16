package main

import (
	"sync"
)

type LogCtx struct {
	ip         string
	timestamp  string
	ruleID     []int
	totalScore int
}

func NewLogCtx() *LogCtx {
	return &LogCtx{
		ip:         "",
		timestamp:  "",
		ruleID:     []int{},
		totalScore: 0,
	}
}

type GlobalCtx struct {

	// statistics
	inboundAccumulateScore int
	activityCnt            int
	ruleExecCnt            int
	distinctIPSet          map[string]bool

	// data cache
	activityLock sync.Mutex
	isLocked     bool
	curLogCtx    *LogCtx
	ctx          map[string][]LogCtx

	// action-related
	blockList map[int]bool
}

func NewGlobalCtx() *GlobalCtx {
	return &GlobalCtx{
		inboundAccumulateScore: 0,
		activityCnt:            0,
		ruleExecCnt:            0,
		activityLock:           sync.Mutex{},
		isLocked:               false,
		curLogCtx:              NewLogCtx(),
		distinctIPSet:          map[string]bool{},
		blockList:              map[int]bool{},
		ctx:                    map[string][]LogCtx{},
	}
}

func (globalCtx *GlobalCtx) update(logCtx *LogCtx) {
	globalCtx.isLocked = true

	globalCtx.inboundAccumulateScore += logCtx.totalScore
	globalCtx.activityCnt += 1
	globalCtx.ruleExecCnt += len(logCtx.ruleID)
	globalCtx.distinctIPSet[logCtx.ip] = true

	if arr, ok := globalCtx.ctx[logCtx.ip]; !ok {
		globalCtx.ctx[logCtx.ip] = []LogCtx{}
	} else {
		if len(arr) >= MAX_MEM_RECORD_PER_IP {
			arr = arr[1:]
		}
		arr = append(arr, *logCtx)
	}

	globalCtx.isLocked = false
	globalCtx.curLogCtx = NewLogCtx()
}

func (globalCtx *GlobalCtx) addBlockList(ruleList []int) {
	for _, ruleID := range ruleList {
		globalCtx.blockList[ruleID] = true
	}
}
