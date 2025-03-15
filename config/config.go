package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
)

type ConfigStruct struct {
	DisableLogCaller bool   `long:"disable-log-caller" description:"Whether to disable log caller location"`
	LogLevel         string `long:"log-level" description:"Log level" default:"debug"`
	LogDir           string `long:"log-dir" description:"Log directory" default:"log"`
	BasePath         string `long:"base-path" description:"Base path" default:"./"`

	SafePrimeGenTimeout time.Duration `long:"safe-prime-gen-timeout" description:"Safe prime generation timeout" default:"5m"`
	DKGTimeout          time.Duration `long:"dkg-timeout" description:"DKG timeout" default:"5m"`
	SigningTimeout      time.Duration `long:"signing-timeout" description:"Signing timeout" default:"10s"`
	PkTimeout           time.Duration `long:"pk-timeout" description:"PK timeout" default:"1s"`
	Port                int           `short:"p" long:"port" description:"Port" default:"29197"`
}

var config *ConfigStruct

func init() {
	config = &ConfigStruct{}
	if err := FromFlags(); err != nil {
		panic(err)
	}
}
func Config() *ConfigStruct {
	return config
}

func FromFlags() error {
	parser := flags.NewParser(config, flags.Default|flags.IgnoreUnknown)
	_, err := parser.Parse()
	if err != nil {
		return err
	}
	return nil
}

func FromFile(filename string) error {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read config file error: %w", err)
	}
	err = json.Unmarshal(fileData, config)
	if err != nil {
		return fmt.Errorf("unmarshal config file error: %w", err)
	}
	return nil
}
