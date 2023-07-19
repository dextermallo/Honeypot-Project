package logger

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	DebugLevel LogLevel = iota
	InfoLevel
	WarningLevel
	ErrorLevel
	FatalLevel
)

var (
	logLevel   LogLevel = InfoLevel
	logger     *log.Logger
	outputMode bool = false
)

func init() {
	file, err := os.OpenFile("coraza.log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}

	logger = log.New(file, "", log.Ldate|log.Ltime|log.Lmicroseconds)
}

func SetLogLevel(level LogLevel) {
	logLevel = level
}

func SetOutputMode(isOn bool) {
	outputMode = isOn
}

func Debug(message ...any) {
	if logLevel <= DebugLevel {
		logger.Println("[DEBUG]", message)
		if outputMode {
			fmt.Println("[DEBUG]", message)
		}
	}
}

func Info(message ...any) {
	if logLevel <= InfoLevel {
		logger.Println("[INFO]", message)
		if outputMode {
			fmt.Println("[INFO]", message)
		}
	}
}

func Warning(message ...any) {
	if logLevel <= WarningLevel {
		logger.Println("[WARNING]", message)
		if outputMode {
			fmt.Println("[WARNING]", message)
		}
	}
}

func Error(message ...any) {
	if logLevel <= ErrorLevel {
		logger.Println("[ERROR]", message)
		if outputMode {
			fmt.Println("[ERROR]", message)
		}
	}
}

func Fatal(message ...any) {
	logger.Fatalln("[FATAL]", message)
	if outputMode {
		fmt.Println("[FATAL]", message)
	}
	os.Exit(1)
}
