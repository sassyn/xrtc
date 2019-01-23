package main

import (
	"os"

	"github.com/PeterXu/xrtc/exit"
	"github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/webrtc"
)

func init() {
	logging.SetDefault()
}

func main() {
	hub := webrtc.Inst()

	exit.Listen(func(s os.Signal) {
		hub.Close()
	})

	exit.Wait()
}
