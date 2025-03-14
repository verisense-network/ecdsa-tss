package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig(t *testing.T) {
	Config()
	assert.Equal(t, Config().SafePrimeGenTimeout, 5*time.Minute)
	assert.Equal(t, Config().LogLevel, "debug")
	assert.Equal(t, Config().LogDir, "log")
	assert.Equal(t, Config().BasePath, "./")
	assert.Equal(t, Config().DKGTimeout, 5*time.Minute)
}
