package main

import (
	"os"

	"github.com/PeterXu/xrtc/exit"
	"github.com/PeterXu/xrtc/webrtc"
)

func main() {
	hub := webrtc.Inst()

	exit.Listen(func(s os.Signal) {
		hub.Exit()
	})

	exit.Wait()
}
