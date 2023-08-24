package rpclog

import (
	"fmt"

	"github.com/btcsuite/btclog"
	"github.com/rs/zerolog"
)

type Logger struct{ *zerolog.Logger }

// To make the log lines appear as the correct rpcclient lines
const skipFrames = 1

func (l *Logger) Tracef(format string, params ...interface{}) {
	l.Logger.Trace().CallerSkipFrame(skipFrames).Msgf(format, params...)
}

func (l *Logger) Debugf(format string, params ...interface{}) {
	l.Logger.Debug().CallerSkipFrame(skipFrames).Msgf(format, params...)
}

func (l *Logger) Infof(format string, params ...interface{}) {
	l.Logger.Info().CallerSkipFrame(skipFrames).Msgf(format, params...)
}

func (l *Logger) Warnf(format string, params ...interface{}) {
	l.Logger.Warn().CallerSkipFrame(skipFrames).Msgf(format, params...)
}

func (l *Logger) Errorf(format string, params ...interface{}) {
	l.Logger.Error().CallerSkipFrame(skipFrames).Msgf(format, params...)
}

func (l *Logger) Criticalf(format string, params ...interface{}) {
	l.Logger.Error().CallerSkipFrame(skipFrames).Msgf(format, params...)
}

func (l *Logger) Trace(v ...interface{}) {
	l.Logger.Trace().CallerSkipFrame(skipFrames).Msg(fmt.Sprint(v...))
}

func (l *Logger) Debug(v ...interface{}) {
	l.Logger.Debug().CallerSkipFrame(skipFrames).Msg(fmt.Sprint(v...))
}

func (l *Logger) Info(v ...interface{}) {
	l.Logger.Info().CallerSkipFrame(skipFrames).Msg(fmt.Sprint(v...))
}

func (l *Logger) Warn(v ...interface{}) {
	l.Logger.Warn().CallerSkipFrame(skipFrames).Msg(fmt.Sprint(v...))
}

func (l *Logger) Error(v ...interface{}) {
	l.Logger.Error().CallerSkipFrame(skipFrames).Msg(fmt.Sprint(v...))
}

func (l *Logger) Critical(v ...interface{}) {
	l.Logger.Error().CallerSkipFrame(skipFrames).Msg(fmt.Sprint(v...))
}

func (l *Logger) Level() btclog.Level {
	lvl := l.Logger.GetLevel()
	switch lvl {
	case zerolog.TraceLevel:
		return btclog.LevelTrace

	case zerolog.DebugLevel:
		return btclog.LevelDebug
	case zerolog.InfoLevel:
		return btclog.LevelInfo
	case zerolog.WarnLevel:
		return btclog.LevelWarn
	case zerolog.ErrorLevel:
		return btclog.LevelError
	case zerolog.Disabled:
		return btclog.LevelOff
	default:
		panic(lvl)
	}
}

func (l *Logger) SetLevel(level btclog.Level) {
	var lvl zerolog.Level
	switch level {
	case btclog.LevelTrace:
		lvl = zerolog.TraceLevel

	case btclog.LevelDebug:
		lvl = zerolog.DebugLevel

	case btclog.LevelInfo:
		lvl = zerolog.InfoLevel

	case btclog.LevelWarn:
		lvl = zerolog.WarnLevel

	case btclog.LevelError:
		lvl = zerolog.ErrorLevel

	case btclog.LevelCritical:
		lvl = zerolog.ErrorLevel

	case btclog.LevelOff:
		lvl = zerolog.Disabled
	}

	log := l.Logger.Level(lvl)
	l.Logger = &log
}

var _ btclog.Logger = new(Logger)
