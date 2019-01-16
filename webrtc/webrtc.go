package webrtc

import (
	"sync"

	log "github.com/PeterXu/xrtc/logging"
)

const kDefaultConfig = "/tmp/etc/routes.yml"

// external interfaces

const (
	WebrtcActionUnknown = iota
	WebrtcActionOffer
	WebrtcActionAnswer
)

type WebrtcAction struct {
	data      []byte
	action    int
	tag       string
	iceHost   string
	iceTcp    bool
	iceDirect bool
}

func NewWebrtcActionMessage(wa *WebrtcAction) interface{} {
	return NewHubMessage(nil, nil, nil, wa)
}

type Webrtc interface {
	ChanAdmin() chan interface{}
	Candidates() []string // xRTC candidates for WebRTC client
	Exit()
}

// gloabl variables
var gMutex sync.RWMutex
var gMaxHub *MaxHub
var gConfig *Config

// loadConfig load config parameters.
func loadConfig(fname string) {
	config := NewConfig()
	if !config.Load(fname) {
		log.Fatalf("read config failed")
		return
	}
	gConfig = config
}

// startServers start servers from config.
func startServers(hub *MaxHub) {
	for _, cfg := range gConfig.UdpServers {
		udp := NewUdpServer(hub, cfg)
		go udp.Run()
		hub.AddServer(udp)
	}

	for _, cfg := range gConfig.TcpServers {
		tcp := NewTcpServer(hub, cfg)
		go tcp.Run()
		hub.AddServer(tcp)
	}

	for _, cfg := range gConfig.HttpServers {
		http := NewHttpServer(hub, cfg)
		go http.Run()
		hub.AddServer(http)
	}
}

// Inst the global entry function.
func Inst() Webrtc {
	gMutex.Lock()
	defer gMutex.Unlock()
	if gMaxHub == nil {
		loadConfig(kDefaultConfig)
		hub := NewMaxHub()
		go hub.Run()
		startServers(hub)
		gMaxHub = hub
	}

	return gMaxHub
}
