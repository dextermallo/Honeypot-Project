package main

import (
	"fmt"
	"testing"
)

func TestNewLogCtx(t *testing.T) {
	fmt.Println("TestNewLogCtx")
	logCtx := NewLogCtx()
	logCtx.ip = "123.123.123.123"
	logCtx.score = []int{1, 2, 3}
	logCtx.ruleID = []int{1, 2, 3}
	logCtx.totalScore = 6

	if logCtx.ip != "123.123.123.123" {
		t.Errorf("incorrect ip")
	}

	if logCtx.score[0] != 1 {
		t.Errorf("incorrect score")
	}

	if logCtx.ruleID[0] != 1 {
		t.Errorf("incorrect ruleID")
	}

	if logCtx.totalScore != 6 {
		t.Errorf("incorrect totalScore")
	}
}

func TestNewGlobalCtx(t *testing.T) {
	fmt.Println("TestNewGlobalCtx")
	globalCtx := NewGlobalCtx()

	logCtx := NewLogCtx()
	logCtx.ip = "123.123.123.123"
	logCtx.score = []int{1, 2, 3}
	logCtx.ruleID = []int{1, 2, 3}
	logCtx.totalScore = 6

	globalCtx.update(logCtx)

	if globalCtx.inboundAccumulateScore != 6 {
		t.Errorf("incorrect inboundAccumulateScore")
	}
}
