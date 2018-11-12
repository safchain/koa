package engine

import (
	"log"
	"os"
)

var (
	stdout = log.New(os.Stderr, AppName+": ", log.Ldate|log.Ltime|log.Lshortfile)
	stderr = log.New(os.Stderr, AppName+": ", log.Ldate|log.Ltime|log.Lshortfile)

	Logger = &logger{}
)

type logger struct{}

func (l *logger) Errorf(format string, args ...interface{}) {
	stderr.Printf(format, args...)
}

func (l *logger) Infof(format string, args ...interface{}) {
	stdout.Printf(format, args...)
}
