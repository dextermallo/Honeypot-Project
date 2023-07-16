package main

import "fmt"

type ISecurityMeasure interface {
	inspect(logCtx *LogCtx, globalCtx *GlobalCtx)
	exec() (bool, error)
}

type SMNetworkIsolation struct {
	name        string
	description string
	passFn      func() (bool, error)
	failFn      func() (bool, error)
	passed      bool
}

func NewSMNetworkIsolation() *SMNetworkIsolation {
	return &SMNetworkIsolation{
		name:        "NetworkIsolation",
		description: "NetworkIsolation",
		passFn: func() (bool, error) {
			fmt.Println("passedFn")
			return true, nil
		},
		failFn: func() (bool, error) {
			fmt.Println("failFn")
			return true, nil
		},
		passed: true,
	}
}

// Resource usage >= 50% && total isolation < 3 => adjust resources
// Resource usage >= 50% && total isolation <= 10 => network isolation
// Resource usage >= 50% && total isolation > 10 => restart
// total anomaly score += 100,000
// distinct IP count += 10
// total activity count += 1,000
// then, check integrity

func (sm *SMNetworkIsolation) inspect(logCtx *LogCtx, globalCtx *GlobalCtx) {
	// check threshold

	if globalCtx.inboundAccumulateScore >= 10 {
		sm.passed = false
	}

	// if threshold is exceeded, run failFn
	// else, run passFn if it exists
}

func (sm *SMNetworkIsolation) exec() (bool, error) {
	fmt.Println("exec")
	if sm.passed {
		sm.passFn()
	} else {
		sm.failFn()
	}
	return true, nil
}

var SecurityMeasureList = []ISecurityMeasure{
	NewSMNetworkIsolation(),
}
