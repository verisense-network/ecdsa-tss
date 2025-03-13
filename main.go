package main

import (
	"bsctss/logger"
)

func main() {
	logger.With("a", "b").Info("hello world")
}
