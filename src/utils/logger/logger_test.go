package logger

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLogger(t *testing.T) {
	SetLogLevel(DebugLevel)
	if logLevel != DebugLevel {
		t.Errorf("Log level not set")
	}

	SetOutputMode(false)
	if outputMode {
		t.Errorf("Output mode not set")
	}

	Debug("Debug message")
	Info("Info message")
	Warning("Warning message")
	Error("Error message")

	file, err := ioutil.ReadFile("coraza.log")
	if err != nil {
		t.Errorf(err.Error())
	}

	if !strings.Contains(string(file), "Debug message") {
		t.Errorf("Debug message not logged")
	}

	if !strings.Contains(string(file), "Info message") {
		t.Errorf("Info message not logged")
	}

	if !strings.Contains(string(file), "Warning message") {
		t.Errorf("Warning message not logged")
	}

	if !strings.Contains(string(file), "Error message") {
		t.Errorf("Error message not logged")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFatal")
	cmd.Env = append(os.Environ(), "EXEC_TEST_FATAL=1")
	err = cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		os.Setenv("EXEC_TEST_FATAL", "0")
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestOutputMode(t *testing.T) {

	SetOutputMode(true)
	if !outputMode {
		t.Errorf("Output mode not set")
	}

	Debug("Debug message")
	Info("Info message")
	Warning("Warning message")
	Error("Error message")

	file, err := ioutil.ReadFile("coraza.log")
	if err != nil {
		t.Errorf(err.Error())
	}

	if !strings.Contains(string(file), "Debug message") {
		t.Errorf("Debug message not logged")
	}

	if !strings.Contains(string(file), "Info message") {
		t.Errorf("Info message not logged")
	}

	if !strings.Contains(string(file), "Warning message") {
		t.Errorf("Warning message not logged")
	}

	if !strings.Contains(string(file), "Error message") {
		t.Errorf("Error message not logged")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFatal")
	cmd.Env = append(os.Environ(), "EXEC_TEST_FATAL=1")
	err = cmd.Run()
	if e, ok := err.(*exec.ExitError); ok && !e.Success() {
		os.Setenv("EXEC_TEST_FATAL", "0")
		return
	}
	t.Fatalf("process ran with err %v, want exit status 1", err)
}

func TestFatal(t *testing.T) {
	if os.Getenv("EXEC_TEST_FATAL") == "1" {
		Fatal()
		return
	}
}
