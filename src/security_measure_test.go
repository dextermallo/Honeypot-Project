package main

import (
	"testing"
	"time"

	"github.com/dextermallo/owasp-honeypot/utils/container"
)

func TestSecurityMeasure(t *testing.T) {
	honeypotService := NewHoneypotService("3", "/", "distributed-honeypot", "/")

	gc := NewGlobalCtx()
	honeypotService.globalCtx = gc

	gc.recentActivityCnt.Set("0.0.0.0", 999, 5*time.Minute)

	if gc.getRecentActivityCnt() != 999 {
		t.Errorf("gc.getRecentActivityCnt() should be 10000")
	}

	lc := NewLogCtx()

	ok, _ := SecurityMeasureList[0].inspect(lc, honeypotService)

	if !ok {
		t.Errorf("SecurityMeasureList[0].inspect() should pass")
	}

	// disconnect for 30 seconds
	SecurityMeasureList[0].failFn(honeypotService)

	time.Sleep(30 * time.Second)

	gc.recentActivityBlockTime = 100
	ok, _ = SecurityMeasureList[1].inspect(lc, honeypotService)

	if !ok {
		t.Errorf("SecurityMeasureList[1].inspect() should pass")
	}

	// reinstall
	SecurityMeasureList[1].failFn(honeypotService)
	time.Sleep(15 * time.Second)

	gc.activityCnt = 999

	ok, _ = SecurityMeasureList[2].inspect(lc, honeypotService)

	if !ok {
		t.Errorf("SecurityMeasureList[2].inspect() should pass")
	}

	container.Remove("honeypot-3")
}
