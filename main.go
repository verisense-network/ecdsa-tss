package main

import (
	"bsctss/config"
	"bsctss/signer"
)

func main() {
	signer.StartSignerServer(uint16(config.Config().Port))
}
