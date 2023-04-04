package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger for portability
type Logger struct {
	zap.Logger
}

// New creates a default logger based on what kind of environment is used.
func New(name string, production bool) *Logger {
	var config zap.Config

	switch production {
	case true:
		config = zap.NewProductionConfig()
	case false:
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	config.DisableCaller = true
	log, _ := config.Build()

	return &Logger{Logger: *log.Named(name)}
}

// NewSimple creates a simple logger for barbaric purposes
func NewSimple(name string) *Logger {
	return &Logger{Logger: *zap.L().Named(name)}
}

// New creates a sub-logger of the original one
func (l *Logger) New(path string) *Logger {
	return &Logger{Logger: *l.Named(path)}
}

// Warn log
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.Logger.Sugar().Warnw(msg, args...)
}

// Error log
func (l *Logger) Error(msg string, args ...interface{}) {
	l.Logger.Sugar().Errorw(msg, args...)
}

// Fatal log
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.Logger.Sugar().Fatalw(msg, args...)
}

// Debug log
func (l *Logger) Debug(msg string, args ...interface{}) {
	l.Logger.Sugar().Debugw(msg, args...)
}

// Info log
func (l *Logger) Info(msg string, args ...interface{}) {
	l.Logger.Sugar().Infow(msg, args...)
}
