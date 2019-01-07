package webrtc

import (
	"sync"

	log "github.com/PeterXu/xrtc/logging"
)

const kDefaultConfig = "/tmp/etc/routes.yml"

/// external interfaces

const (
	WebrtcActionUnknown = iota
	WebrtcActionOffer
	WebrtcActionAnswer
)

type WebrtcAction struct {
	action int
	tag    string
}

func NewWebrtcAction(data []byte, action int, tag string) interface{} {
	misc := &WebrtcAction{action, tag}
	return NewHubMessage(data, nil, nil, misc)
}

type Webrtc interface {
	ChanAdmin() chan interface{}
	Candidates() []string
	Exit()
}

/// gloabl variables
var gMutex sync.RWMutex
var gMaxHub *MaxHub
var gConfig *Config

/// module init
func init() {
	log.SetDefault()
}

/// load config
func loadConfig(fname string) {
	config := NewConfig()
	if !config.Load(fname) {
		log.Fatalf("read config failed")
		return
	}
	gConfig = config
}

/// start servers
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

/// entry function
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
