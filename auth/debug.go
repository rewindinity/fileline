package auth

import (
	"log"
	"sync/atomic"
)

var debugMode atomic.Bool

func SetDebug(enabled bool) {
	debugMode.Store(enabled)
}

/**
  Debugf logs formatted debug messages when debug mode is enabled.
  @param format - The message format string.
  @param args - The arguments to format into the message.
  @returns void
*/
func Debugf(format string, args ...interface{}) {
	if !debugMode.Load() {
		return
	}
	log.Printf("DEBUG auth: "+format, args...)
}
