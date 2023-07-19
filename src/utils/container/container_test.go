package container

import (
	"testing"
)

func TestContainerMultiOp(t *testing.T) {
	err := CreateHoneypot("test", "distributed-honeypot")

	if err != nil {
		t.Errorf(err.Error())
	}

	diff, diffErr := Diff("test", []string{})

	if diffErr != nil {
		t.Errorf(diffErr.Error())
	}

	if len(diff) == 0 {
		t.Errorf("No diff detected")
	}

	err = Disconnect("distributed-honeypot", "test")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Connect("distributed-honeypot", "test")

	if err != nil {
		t.Errorf(err.Error())
	}

	err = Remove("test")

	if err != nil {
		t.Errorf(err.Error())
	}
}
