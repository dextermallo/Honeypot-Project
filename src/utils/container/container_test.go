package container

import (
	"testing"
)

func TestContainerMultiOp(t *testing.T) {
	err := ReinstallHoneypot("3", "distributed-honeypot")

	if err != nil {
		t.Errorf(err.Error())
	}

	ok, runningErr := IsRunning("honeypot-3")

	if runningErr != nil || !ok {
		t.Errorf(runningErr.Error())
	}

	diff, diffErr := Diff("honeypot-3", []string{})

	if diffErr != nil {
		t.Errorf(diffErr.Error())
	}

	if len(diff) == 0 {
		t.Errorf("No diff detected")
	}

	err = Connect("distributed-honeypot", "honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Disconnect("distributed-honeypot", "honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Restart("honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Remove("honeypot-3")

	if err != nil {
		t.Errorf(err.Error())
	}
}
