package main

import (
	"ecdsa-tss/config"
	"ecdsa-tss/logger"
	"ecdsa-tss/signer"
)

func main() {
	err := signer.StartSignerServer(uint16(config.Config().Port))
	if err != nil {
		logger.Errorf("failed to start signer server: %v", err)
	}
}
