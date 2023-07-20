package main

import (
	"testing"
	"time"
)

func TestLogCtx(t *testing.T) {
	logCtx := NewLogCtx()

	if logCtx.ip != "" {
		t.Errorf("LogCtx.ip not initialized")
	}

	if logCtx.timestamp != "" {
		t.Errorf("LogCtx.timestamp not initialized")
	}

	if len(logCtx.ruleID) != 0 {
		t.Errorf("LogCtx.ruleID not initialized")
	}

	if logCtx.totalScore != 0 {
		t.Errorf("LogCtx.totalScore not initialized")
	}
}

func TestGlobalCtx(t *testing.T) {
	gc := NewGlobalCtx()

	lc := NewLogCtx()
	lc.ip = "123.123.123.123"
	lc.timestamp = "2021-01-01 00:00:00"
	lc.ruleID = []int{1, 2, 3}
	lc.totalScore = 100

	gc.update(lc)

	if gc.inboundAccumulateScore != 100 {
		t.Errorf("GlobalCtx.inboundAccumulateScore not updated")
	}

	if gc.activityCnt != 1 {
		t.Errorf("GlobalCtx.activityCnt not updated")
	}

	if gc.ruleExecCnt != 3 {
		t.Errorf("GlobalCtx.ruleExecCnt not updated")
	}

	if !gc.distinctIPSet[lc.ip] {
		t.Errorf("GlobalCtx.distinctIPSet not updated")
	}
}

func TestUpdateBlockList(t *testing.T) {
	gc := NewGlobalCtx()

	_, err := gc.updateBlockList([]int{1, 2, 3})

	if err != nil {
		t.Errorf(err.Error())
	}

	if gc.invokeCnt[1] != 1 {
		t.Errorf("GlobalCtx.invokeCnt not updated")
	}
}

func TestGetRecentActivityCnt(t *testing.T) {
	gc := NewGlobalCtx()

	gc.recentActivityCnt.Set("123.123.123.123", 1, 5*time.Minute)
	gc.recentActivityCnt.Set("0.0.0.0", 5, 5*time.Minute)

	if gc.getRecentActivityCnt() != 6 {
		t.Errorf("GlobalCtx.getRecentActivityCnt() not working")
	}
}

func TestHoneypotService(t *testing.T) {
	hs := NewHoneypotService("1", "http://localhost:8001/", "distributed-honeypot", "/public")

	if hs.id != "1" {
		t.Errorf("HoneypotService.id not initialized")
	}

	if hs.endpoint != "http://localhost:8001/" {
		t.Errorf("HoneypotService.endpoint not initialized")
	}

	if hs.network != "distributed-honeypot" {
		t.Errorf("HoneypotService.network not initialized")
	}

	if hs.prefix != "/public" {
		t.Errorf("HoneypotService.prefix not initialized")
	}
}
