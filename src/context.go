package main

import (
	"sync"
	"time"

	"github.com/dextermallo/owasp-honeypot/utils/logger"
	"github.com/jellydator/ttlcache/v3"
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
	invokeCnt map[int]int
	blockList map[int]bool

	// recent activity
	recentActivityCnt       *ttlcache.Cache[string, int]
	recentActivityBlockTime int

	// record
	prevActivityCntInterval int
	prevDistinctIPInterval  int
	prevTotalScoreInterval  int
}

func NewGlobalCtx() *GlobalCtx {
	return &GlobalCtx{
		inboundAccumulateScore:  0,
		activityCnt:             0,
		ruleExecCnt:             0,
		activityLock:            sync.Mutex{},
		isLocked:                false,
		curLogCtx:               NewLogCtx(),
		distinctIPSet:           map[string]bool{},
		invokeCnt:               map[int]int{},
		ctx:                     map[string][]LogCtx{},
		blockList:               map[int]bool{},
		recentActivityCnt:       ttlcache.New(ttlcache.WithTTL[string, int](5 * time.Minute)),
		recentActivityBlockTime: 0,
		prevActivityCntInterval: 0,
		prevDistinctIPInterval:  0,
		prevTotalScoreInterval:  0,
	}
}

func (gc *GlobalCtx) update(logCtx *LogCtx) {
	logger.Debug("start globalCtx.update()")
	gc.isLocked = true

	gc.inboundAccumulateScore += logCtx.totalScore
	gc.activityCnt += 1
	gc.ruleExecCnt += len(logCtx.ruleID)
	gc.distinctIPSet[logCtx.ip] = true

	if arr, ok := gc.ctx[logCtx.ip]; !ok {
		gc.ctx[logCtx.ip] = []LogCtx{}
	} else {
		if len(arr) >= MAX_MEM_RECORD_PER_IP {
			arr = arr[1:]
		}
		gc.ctx[logCtx.ip] = append(arr, *logCtx)
	}

	if gc.recentActivityCnt.Get(logCtx.ip) == nil {
		gc.recentActivityCnt.Set(logCtx.ip, 1, 5*time.Minute)
	} else {
		inc := gc.recentActivityCnt.Get(logCtx.ip)
		gc.recentActivityCnt.Set(logCtx.ip, inc.Value()+1, 5*time.Minute)
	}

	gc.isLocked = false
	gc.curLogCtx = NewLogCtx()
}

func (gc *GlobalCtx) updateBlockList(ruleList []int) (bool, error) {
	for _, ruleID := range ruleList {
		if _, isExist := gc.invokeCnt[ruleID]; isExist {
			gc.invokeCnt[ruleID] += 1
			if gc.invokeCnt[ruleID] >= BLOCKING_THRESHOLD {
				gc.blockList[ruleID] = true
			}
		}
	}

	return true, nil
}

func (gc *GlobalCtx) getRecentActivityCnt() int {
	cnt := 0

	for _, item := range gc.recentActivityCnt.Items() {
		cnt += item.Value()
	}

	return cnt
}

type HoneypotService struct {
	id        string
	endpoint  string
	globalCtx *GlobalCtx
	network   string
	prefix    string
}

func NewHoneypotService(id string, endpoint string, network string, prefix string) *HoneypotService {
	return &HoneypotService{
		id:        id,
		endpoint:  endpoint,
		globalCtx: NewGlobalCtx(),
		network:   network,
		prefix:    prefix,
	}
}
