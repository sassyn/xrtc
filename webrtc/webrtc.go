package webrtc

import (
	"sync"

	log "github.com/PeterXu/xrtc/logging"
)

const kDefaultConfig = "/tmp/etc/routes.yml"

/// external interfaces
type WebrtcAction uint32

const (
	WebrtcActionUnknown WebrtcAction = iota
	WebrtcActionOffer
	WebrtcActionAnswer
)

func NewWebrtcAction(data []byte, action WebrtcAction) interface{} {
	return NewHubMessage(data, nil, nil, action)
}

type Webrtc interface {
	ChanAdmin() chan interface{}
	Exit()
}

/// gloabl variables
var gMutex sync.RWMutex
var gMaxHub *MaxHub
var gConfig *Config

/// module init
func init() {
	log.SetLevel(log.DebugLevel)
	log.SetDefaultFlags()
	log.SetDefaultTag()
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
