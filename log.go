package zaplog

import (
	"errors"
	"fmt"
	"github.com/jinzhu/copier"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sort"
	"sync"
	"time"
)

// SamplingConfig sets a sampling strategy for the logger. Sampling caps the
// global CPU and I/O load that logging puts on your process while attempting
// to preserve a representative subset of your logs.
//
// Values configured here are per-second. See zapcore.NewSampler for details.
type SamplingConfig struct {
	Initial    int `json:"initial" yaml:"initial" toml:"initial" mapstructure:"initial"`
	Thereafter int `json:"thereafter" yaml:"thereafter" toml:"thereafter" mapstructure:"thereafter"`
}

// Config offers a declarative way to construct a logger. It doesn't do
// anything that can't be done with New, Options, and the various
// zapcore.WriteSyncer and zapcore.Core wrappers, but it's a simpler way to
// toggle common options.
//
// Note that Config intentionally supports only the most common options. More
// unusual logging setups (logging to network connections or message queues,
// splitting output between multiple files, etc.) are possible, but require
// direct use of the zapcore package. For sample code, see the package-level
// BasicConfiguration and AdvancedConfiguration examples.
//
// For an example showing runtime log level changes, see the documentation for
// AtomicLevel.
type Config struct {
	// Level is the minimum enabled logging level. Note that this is a dynamic
	// level, so calling Config.Level.SetLevel will atomically change the log
	// level of all loggers descended from this config.
	Level string `json:"level" yaml:"level" toml:"level" mapstructure:"level"`
	// Development puts the logger in development mode, which changes the
	// behavior of DPanicLevel and takes stacktraces more liberally.
	Development bool `json:"development" yaml:"development" toml:"development" mapstructure:"development"`
	// DisableCaller stops annotating logs with the calling function's file
	// name and line number. By default, all logs are annotated.
	DisableCaller bool `json:"disableCaller" yaml:"disableCaller" toml:"disableCaller" mapstructure:"disableCaller"`
	// DisableStacktrace completely disables automatic stacktrace capturing. By
	// default, stacktraces are captured for WarnLevel and above logs in
	// development and ErrorLevel and above in production.
	DisableStacktrace bool `json:"disableStacktrace" yaml:"disableStacktrace" toml:"disableStacktrace" mapstructure:"disableStacktrace"`
	// Sampling sets a sampling policy. A nil SamplingConfig disables sampling.
	Sampling *SamplingConfig `json:"sampling" yaml:"sampling" toml:"sampling" mapstructure:"sampling"`
	// Encoding sets the logger's encoding. Valid values are "json" and
	// "console", as well as any third-party encodings registered via
	// RegisterEncoder.
	Encoding string `json:"encoding" yaml:"encoding" toml:"encoding" mapstructure:"encoding"`
	// EncoderConfig sets options for the chosen encoder. See
	// zapcore.EncoderConfig for details.
	EncoderConfig EncoderConfig `json:"encoderConfig" yaml:"encoderConfig" toml:"encoderConfig" mapstructure:"encoderConfig"`
	// OutputPaths is a list of URLs or file paths to write logging output to.
	// See Open for details.
	OutputPaths []string `json:"outputPaths" yaml:"outputPaths" toml:"outputPaths" mapstructure:"outputPaths"`
	// ErrorOutputPaths is a list of URLs to write internal logger errors to.
	// The default is standard error.
	//
	// Note that this setting only affects internal errors; for sample code that
	// sends error-level logs to a different location from info- and debug-level
	// logs, see the package-level AdvancedConfiguration example.
	ErrorOutputPaths []string `json:"errorOutputPaths" yaml:"errorOutputPaths" toml:"errorOutputPaths" mapstructure:"errorOutputPaths"`
	// InitialFields is a collection of fields to add to the root logger.
	InitialFields map[string]interface{} `json:"initialFields" yaml:"initialFields" toml:"initialFields" mapstructure:"initialFields"`
}

// An EncoderConfig allows users to configure the concrete encoders supplied by
// zapcore.
type EncoderConfig struct {
	// Set the keys used for each log entry. If any key is empty, that portion
	// of the entry is omitted.
	MessageKey    string `json:"messageKey" yaml:"messageKey" toml:"messageKey" mapstructure:"messageKey"`
	LevelKey      string `json:"levelKey" yaml:"levelKey" toml:"levelKey" mapstructure:"levelKey"`
	TimeKey       string `json:"timeKey" yaml:"timeKey" toml:"timeKey" mapstructure:"timeKey"`
	NameKey       string `json:"nameKey" yaml:"nameKey" toml:"nameKey" mapstructure:"nameKey"`
	CallerKey     string `json:"callerKey" yaml:"callerKey" toml:"callerKey" mapstructure:"callerKey"`
	StacktraceKey string `json:"stacktraceKey" yaml:"stacktraceKey" toml:"stacktraceKey" mapstructure:"stacktraceKey"`
	LineEnding    string `json:"lineEnding" yaml:"lineEnding" toml:"lineEnding" mapstructure:"lineEnding"`
	// Configure the primitive representations of common complex types. For
	// example, some users may want all time.Times serialized as floating-point
	// seconds since epoch, while others may prefer ISO8601 strings.
	EncodeLevel    zapcore.LevelEncoder    `json:"levelEncoder" yaml:"levelEncoder" toml:"levelEncoder" mapstructure:"levelEncoder"`
	EncodeTime     zapcore.TimeEncoder     `json:"timeEncoder" yaml:"timeEncoder" toml:"timeEncoder" mapstructure:"timeEncoder"`
	EncodeDuration zapcore.DurationEncoder `json:"durationEncoder" yaml:"durationEncoder" toml:"durationEncoder" mapstructure:"durationEncoder"`
	EncodeCaller   zapcore.CallerEncoder   `json:"callerEncoder" yaml:"callerEncoder" toml:"callerEncoder" mapstructure:"callerEncoder"`
	// Unlike the other primitive type encoders, EncodeName is optional. The
	// zero value falls back to FullNameEncoder.
	EncodeName zapcore.NameEncoder `json:"nameEncoder" yaml:"nameEncoder" toml:"nameEncoder" mapstructure:"nameEncoder"`
}

// NewProductionEncoderConfig returns an opinionated EncoderConfig for
// production environments.
func NewProductionEncoderConfig() EncoderConfig {
	return EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

// NewProductionConfig is a reasonable production logging configuration.
// Logging is enabled at InfoLevel and above.
//
// It uses a JSON encoder, writes to standard error, and enables sampling.
// Stacktraces are automatically included on logs of ErrorLevel and above.
func NewProductionConfig() Config {
	return Config{
		Level:       "info",
		Development: false,
		Sampling: &SamplingConfig{
			Initial:    100,
			Thereafter: 100,
		},
		Encoding:         "json",
		EncoderConfig:    NewProductionEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
}

// NewDevelopmentEncoderConfig returns an opinionated EncoderConfig for
// development environments.
func NewDevelopmentEncoderConfig() EncoderConfig {
	return EncoderConfig{
		// Keys can be anything except the empty string.
		TimeKey:        "T",
		LevelKey:       "L",
		NameKey:        "N",
		CallerKey:      "C",
		MessageKey:     "M",
		StacktraceKey:  "S",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

// NewDevelopmentConfig is a reasonable development logging configuration.
// Logging is enabled at DebugLevel and above.
//
// It enables development mode (which makes DPanicLevel logs panic), uses a
// console encoder, writes to standard error, and disables sampling.
// Stacktraces are automatically included on logs of WarnLevel and above.
func NewDevelopmentConfig() Config {
	return Config{
		Level:            "debug",
		Development:      true,
		Encoding:         "console",
		EncoderConfig:    NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
}

// Build constructs a logger from the Config and Options.
func (cfg Config) Build(opts ...zap.Option) (*zap.Logger, error) {
	enc, err := cfg.buildEncoder()
	if err != nil {
		return nil, err
	}

	sink, errSink, err := cfg.openSinks()
	if err != nil {
		return nil, err
	}

	cfgLvl := zap.AtomicLevel{}
	cfgLvl.UnmarshalText([]byte(cfg.Level))

	// Define our level-handling logic.
	highPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= cfgLvl.Level() && lvl >= zapcore.ErrorLevel
	})
	lowPriority := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
		return lvl >= cfgLvl.Level() && lvl < zapcore.ErrorLevel
	})

	core := zapcore.NewTee(
		zapcore.NewCore(enc, errSink, highPriority),
		//zapcore.NewCore(enc, sink, cfg.Level),
		zapcore.NewCore(enc, sink, lowPriority),
	)

	log := zap.New(
		core,
		cfg.buildOptions(errSink)...,
	)
	if len(opts) > 0 {
		log = log.WithOptions(opts...)
	}
	return log, nil
}

func (cfg Config) buildOptions(errSink zapcore.WriteSyncer) []zap.Option {
	opts := []zap.Option{zap.ErrorOutput(errSink)}

	if cfg.Development {
		opts = append(opts, zap.Development())
	}

	if !cfg.DisableCaller {
		opts = append(opts, zap.AddCaller())
	}

	stackLevel := zap.ErrorLevel
	if cfg.Development {
		stackLevel = zap.WarnLevel
	}
	if !cfg.DisableStacktrace {
		opts = append(opts, zap.AddStacktrace(stackLevel))
	}

	if cfg.Sampling != nil {
		opts = append(opts, zap.WrapCore(func(core zapcore.Core) zapcore.Core {
			return zapcore.NewSampler(core, time.Second, int(cfg.Sampling.Initial), int(cfg.Sampling.Thereafter))
		}))
	}

	if len(cfg.InitialFields) > 0 {
		fs := make([]zap.Field, 0, len(cfg.InitialFields))
		keys := make([]string, 0, len(cfg.InitialFields))
		for k := range cfg.InitialFields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fs = append(fs, zap.Any(k, cfg.InitialFields[k]))
		}
		opts = append(opts, zap.Fields(fs...))
	}

	return opts
}

func (cfg Config) openSinks() (zapcore.WriteSyncer, zapcore.WriteSyncer, error) {
	sink, closeOut, err := zap.Open(cfg.OutputPaths...)
	if err != nil {
		return nil, nil, err
	}
	errSink, _, err := zap.Open(cfg.ErrorOutputPaths...)
	if err != nil {
		closeOut()
		return nil, nil, err
	}
	return sink, errSink, nil
}

func (cfg Config) buildEncoder() (zapcore.Encoder, error) {
	return newEncoder(cfg.Encoding, cfg.EncoderConfig)
}

var (
	errNoEncoderNameSpecified = errors.New("no encoder name specified")

	_encoderNameToConstructor = map[string]func(EncoderConfig) (zapcore.Encoder, error){

		"console": func(encoderConfig EncoderConfig) (zapcore.Encoder, error) {
			cfg := newDefEncoderConfig(encoderConfig)
			return zapcore.NewConsoleEncoder(cfg), nil
		},
		"json": func(encoderConfig EncoderConfig) (zapcore.Encoder, error) {
			cfg := newDefEncoderConfig(encoderConfig)
			return zapcore.NewJSONEncoder(cfg), nil
		},
	}
	_encoderMutex sync.RWMutex
)

func newDefEncoderConfig(encoderConfig EncoderConfig) zapcore.EncoderConfig {
	if encoderConfig.EncodeLevel == nil {
		encoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
	}

	if encoderConfig.EncodeCaller == nil {
		encoderConfig.EncodeCaller = zapcore.FullCallerEncoder
	}

	if encoderConfig.EncodeDuration == nil {
		encoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder
	}
	if encoderConfig.EncodeName == nil {
		encoderConfig.EncodeName = zapcore.FullNameEncoder
	}

	if encoderConfig.EncodeTime == nil {
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	encoderCfg := zapcore.EncoderConfig{}
	copier.Copy(&encoderCfg, &encoderConfig)
	return encoderCfg
}

func newEncoder(name string, encoderConfig EncoderConfig) (zapcore.Encoder, error) {
	_encoderMutex.RLock()
	defer _encoderMutex.RUnlock()
	if name == "" {
		return nil, errNoEncoderNameSpecified
	}
	constructor, ok := _encoderNameToConstructor[name]
	if !ok {
		return nil, fmt.Errorf("no encoder registered for name %q", name)
	}
	return constructor(encoderConfig)
}

// RegisterEncoder registers an encoder constructor, which the Config struct
// can then reference. By default, the "json" and "console" encoders are
// registered.
//
// Attempting to register an encoder whose name is already taken returns an
// error.
func RegisterEncoder(name string, constructor func(EncoderConfig) (zapcore.Encoder, error)) error {
	_encoderMutex.Lock()
	defer _encoderMutex.Unlock()
	if name == "" {
		return errNoEncoderNameSpecified
	}
	if _, ok := _encoderNameToConstructor[name]; ok {
		return fmt.Errorf("encoder already registered for name %q", name)
	}
	_encoderNameToConstructor[name] = constructor
	return nil
}
