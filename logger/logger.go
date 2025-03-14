package logger

import (
	"bsctss/config"
	"fmt"
	"os"
	"path"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the global logger instance, providing a SugaredLogger API.
var Logger *zap.SugaredLogger

func init() {
	logDir := path.Join(config.Config().BasePath, config.Config().LogDir)
	// Create log directory if not exists.
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Println("Failed to create log directory:", err)
	}
	// Log file for all logs.
	logFilename := path.Join(logDir, fmt.Sprintf("log_%s.log", time.Now().Format("2006-01-02-150405")))
	logFile, err := os.OpenFile(logFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed to open log file:", err)
	}

	// Error log file for error-level and above.
	errFilename := path.Join(logDir, fmt.Sprintf("error_%s.log", time.Now().Format("2006-01-02-150405")))
	errFile, err := os.OpenFile(errFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Failed to open error log file:", err)
	}

	fmt.Printf("Log file: %s\nError file: %s\n", logFilename, errFilename)

	// Dynamically set log level.
	atomicLevel := zap.NewAtomicLevel()
	switch config.Config().LogLevel {
	case "warning":
		atomicLevel.SetLevel(zap.WarnLevel)
	case "info":
		atomicLevel.SetLevel(zap.InfoLevel)
	case "debug":
		atomicLevel.SetLevel(zap.DebugLevel)
	case "error":
		atomicLevel.SetLevel(zap.ErrorLevel)
	default:
		atomicLevel.SetLevel(zap.DebugLevel)
	}

	// Configure encoders.
	consoleEncoderConfig := zapcore.EncoderConfig{
		TimeKey:       "timestamp",
		LevelKey:      "level",
		CallerKey:     "caller",
		MessageKey:    "message",
		StacktraceKey: "stacktrace",
		EncodeTime:    zapcore.ISO8601TimeEncoder,
		EncodeLevel:   zapcore.CapitalColorLevelEncoder,
		EncodeCaller:  zapcore.ShortCallerEncoder,
	}

	// For file output, disable color.
	fileEncoderConfig := consoleEncoderConfig
	fileEncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder // no color in files

	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)
	fileEncoder := zapcore.NewJSONEncoder(fileEncoderConfig)

	// Create syncers.
	consoleSyncer := zapcore.Lock(os.Stdout)
	fileSyncer := zapcore.AddSync(logFile)
	errSyncer := zapcore.AddSync(errFile)

	// Core setup: log to console, file, and error-only file.
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleSyncer, atomicLevel),
		zapcore.NewCore(fileEncoder, fileSyncer, atomicLevel),
		zapcore.NewCore(fileEncoder, errSyncer, zap.ErrorLevel),
	)
	var logger *zap.Logger
	if !config.Config().DisableLogCaller {
		// Build a base logger. CallerSkip(1) is used so logs show the call site outside this pkg.
		logger = zap.New(core, zap.AddCaller(), zap.AddCallerSkip(0))
	} else {
		logger = zap.New(core)
	}

	// Convert to SugaredLogger for convenience.
	Logger = logger.Sugar()
}

// Named returns a logger with the specified name appended.
func Named(name string) *zap.SugaredLogger {
	return Logger.Named(name)
}

// With attaches a variadic number of fields to the logging context.
func With(args ...interface{}) *zap.SugaredLogger {
	return Logger.With(args...)
}

// WithOptions clones the logger, applying the supplied zap.Option(s).
func WithOptions(opts ...zap.Option) *zap.SugaredLogger {
	return Logger.Desugar().WithOptions(opts...).Sugar()
}

// Sync flushes any buffered log entries.
func Sync() error {
	return Logger.Sync()
}

// ============== Full SugaredLogger API ============= //
// (1) Print-style logging: Debug, Info, Warn, Error, DPanic, Panic, Fatal.

func Debug(args ...interface{})  { Logger.Debug(args...) }
func Info(args ...interface{})   { Logger.Info(args...) }
func Warn(args ...interface{})   { Logger.Warn(args...) }
func Error(args ...interface{})  { Logger.Error(args...) }
func DPanic(args ...interface{}) { Logger.DPanic(args...) }
func Panic(args ...interface{})  { Logger.Panic(args...) }
func Fatal(args ...interface{})  { Logger.Fatal(args...) }

// (2) Printf-style logging: Debugf, Infof, Warnf, Errorf, DPanicf, Panicf, Fatalf.

func Debugf(template string, args ...interface{})  { Logger.Debugf(template, args...) }
func Infof(template string, args ...interface{})   { Logger.Infof(template, args...) }
func Warnf(template string, args ...interface{})   { Logger.Warnf(template, args...) }
func Errorf(template string, args ...interface{})  { Logger.Errorf(template, args...) }
func DPanicf(template string, args ...interface{}) { Logger.DPanicf(template, args...) }
func Panicf(template string, args ...interface{})  { Logger.Panicf(template, args...) }
func Fatalf(template string, args ...interface{})  { Logger.Fatalf(template, args...) }

// (3) Println-style logging: Debugln, Infoln, Warnln, Errorln, DPanicln, Panicln, Fatalln.

func Debugln(args ...interface{})  { Logger.Debugln(args...) }
func Infoln(args ...interface{})   { Logger.Infoln(args...) }
func Warnln(args ...interface{})   { Logger.Warnln(args...) }
func Errorln(args ...interface{})  { Logger.Errorln(args...) }
func DPanicln(args ...interface{}) { Logger.DPanicln(args...) }
func Panicln(args ...interface{})  { Logger.Panicln(args...) }
func Fatalln(args ...interface{})  { Logger.Fatalln(args...) }

// (4) Loosely-typed structured logging: Debugw, Infow, Warnw, Errorw, DPanicw, Panicw, Fatalw.

func Debugw(msg string, keysAndValues ...interface{})  { Logger.Debugw(msg, keysAndValues...) }
func Infow(msg string, keysAndValues ...interface{})   { Logger.Infow(msg, keysAndValues...) }
func Warnw(msg string, keysAndValues ...interface{})   { Logger.Warnw(msg, keysAndValues...) }
func Errorw(msg string, keysAndValues ...interface{})  { Logger.Errorw(msg, keysAndValues...) }
func DPanicw(msg string, keysAndValues ...interface{}) { Logger.DPanicw(msg, keysAndValues...) }
func Panicw(msg string, keysAndValues ...interface{})  { Logger.Panicw(msg, keysAndValues...) }
func Fatalw(msg string, keysAndValues ...interface{})  { Logger.Fatalw(msg, keysAndValues...) }

// (5) Generic log-level functions.

// Log logs at a specific zapcore.Level.
func Log(lvl zapcore.Level, args ...interface{}) {
	Logger.Log(lvl, args...)
}

// Logf logs at a specific zapcore.Level with formatting.
func Logf(lvl zapcore.Level, template string, args ...interface{}) {
	Logger.Logf(lvl, template, args...)
}

// Logw logs a message at a specific zapcore.Level, with key-value pairs.
func Logw(lvl zapcore.Level, msg string, keysAndValues ...interface{}) {
	Logger.Logw(lvl, msg, keysAndValues...)
}

// Logln logs at a specific zapcore.Level, using space-separated arguments.
func Logln(lvl zapcore.Level, args ...interface{}) {
	Logger.Logln(lvl, args...)
}
