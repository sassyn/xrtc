package main

import (
	"os"

	"github.com/PeterXu/xrtc/exit"
	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/webrtc"
)

func init() {
	log.SetDefault()
}

func main() {
	hub := webrtc.Inst()

	exit.Listen(func(s os.Signal) {
		hub.Close()
	})

	exit.Wait()
}
