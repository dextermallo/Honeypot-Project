package container

import (
	"testing"
)

func TestContainerMultiOp(t *testing.T) {
	err := CreateHoneypot("3", "distributed-honeypot")

	if err != nil {
		t.Errorf(err.Error())
	}

	diff, diffErr := Diff("honeypot-3", []string{})

	ok, runningErr := IsRunning("honeypot-3")

	if runningErr != nil || !ok {
		t.Errorf(runningErr.Error())
	}

	if diffErr != nil {
		t.Errorf(diffErr.Error())
	}

	if len(diff) == 0 {
		t.Errorf("No diff detected")
	}

	err = Disconnect("distributed-honeypot", "honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Connect("distributed-honeypot", "honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Remove("honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestNonExistContainer(t *testing.T) {
	err := CreateHoneypot("3", "distributed-honeypot")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Remove("honeypot-x")

	if err == nil {
		t.Errorf("Container should not exist")
	}

	err = Disconnect("distributed-honeypot", "honeypot-x")

	if err == nil {
		t.Errorf("Container should not exist")
	}

	err = Connect("distributed-honeypot", "honeypot-x")

	if err == nil {
		t.Errorf("Container should not exist")
	}
}
