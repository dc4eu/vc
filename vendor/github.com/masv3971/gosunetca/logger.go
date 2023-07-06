package gosunetca

import "github.com/go-logr/logr"

type Log struct {
	logr.Logger
}

// Info log
func (l *Log) Info(msg string, args ...interface{}) {
	l.Logger.V(0).WithValues(args...).Info(msg)
}

// Debug log
func (l *Log) Debug(msg string, args ...interface{}) {
	l.Logger.V(1).WithValues(args...).Info(msg)
}

// Trace log
func (l *Log) Trace(msg string, args ...interface{}) {
	l.Logger.V(2).WithValues(args...).Info(msg)
}
