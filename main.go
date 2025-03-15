package main

import (
	"bsctss/config"
	"bsctss/logger"
	"bsctss/signer"
)

func main() {
	err := signer.StartSignerServer(uint16(config.Config().Port))
	if err != nil {
		logger.Errorf("failed to start signer server: %v", err)
	}
}
