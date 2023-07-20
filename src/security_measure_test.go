package main

import (
	"testing"
	"time"

	"github.com/dextermallo/owasp-honeypot/utils/container"
)

func TestSecurityMeasure(t *testing.T) {

	honeypotService := NewHoneypotService("3", "/", "distributed-honeypot", "/test")

	container.CreateHoneypot(honeypotService.id, honeypotService.network)

	gc := NewGlobalCtx()
	gc.recentActivityBlockTime = 9
	honeypotService.globalCtx = gc

	gc.recentActivityCnt.Set("0.0.0.0", 10000, 5*time.Minute)

	lc := NewLogCtx()

	ok, _ := SecurityMeasureList[0].inspect(lc, honeypotService)

	if ok {
		t.Errorf("SecurityMeasureList[0].inspect() should not pass")
	}

	// disconnect for 30 seconds
	SecurityMeasureList[0].failFn(honeypotService)

	time.Sleep(30 * time.Second)

	gc.recentActivityBlockTime = 11

	ok, _ = SecurityMeasureList[1].inspect(lc, honeypotService)

	if ok {
		t.Errorf("SecurityMeasureList[1].inspect() should not pass")
	}

	// reinstall
	SecurityMeasureList[1].failFn(honeypotService)
	time.Sleep(15 * time.Second)

	gc.activityCnt = 1e6

	ok, _ = SecurityMeasureList[2].inspect(lc, honeypotService)

	if !ok {
		t.Errorf("SecurityMeasureList[2].inspect() should pass")
	}

	container.Remove(honeypotService.id)
}
