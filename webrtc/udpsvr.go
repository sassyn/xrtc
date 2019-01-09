package webrtc

import (
	//"fmt"
	"net"
	"time"

	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/util"
)

type UdpServer struct {
	conn   *net.UDPConn
	hub    *MaxHub
	config *UDPConfig

	chanRecv chan interface{}

	sendCount int
	recvCount int

	exitTick chan bool
}

func NewUdpServer(hub *MaxHub, cfg *UDPConfig) *UdpServer {
	//addr := fmt.Sprintf(":%d", port)
	addr := cfg.Net.Addr
	if udpAddr, err := net.ResolveUDPAddr("udp", addr); err == nil {
		if conn, err := net.ListenUDP("udp", udpAddr); err == nil {
			log.Println("[udp_server] listen udp on: ", addr)
			util.SetSocketReuseAddr(conn)
			return &UdpServer{
				conn:     conn,
				hub:      hub,
				config:   cfg,
				chanRecv: make(chan interface{}, 1000),
				exitTick: make(chan bool),
			}
		} else {
			log.Println("[udp_server] listen udp error: ", err)
		}
	} else {
		log.Println("[udp_server] resolve addr error: ", err)
	}
	return nil
}

func (u *UdpServer) Params() *NetParams {
	return &u.config.Net
}

func (u *UdpServer) Exit() {
}

func (u *UdpServer) Run() {
	defer u.conn.Close()
	log.Println("[udp] main begin")

	// write goroutine
	go u.writing()

	buf := make([]byte, kMaxPacketSize)
	sendChan := u.hub.ChanRecvFromOuter()
	for {
		if nret, raddr, err := u.conn.ReadFromUDP(buf[0:]); err == nil {
			//log.Println("[udp] recv msg size: ", nret, ", from ", NetAddrString(raddr))
			u.recvCount += nret
			sendChan <- NewHubMessage(buf[0:nret], raddr, nil, u.chanRecv)
		} else {
			log.Warnln("[udp] read udp error: ", err, ", remote: ", raddr)
			break
		}
	}

	u.exitTick <- true
	log.Println("[udp] main end")
}

func (u *UdpServer) writing() {
	tickChan := time.NewTicker(time.Second * 5).C

	for {
		select {
		case msg, ok := <-u.chanRecv:
			if !ok {
				log.Println("[udp] close channel")
				return
			}

			if umsg, ok := msg.(*HubMessage); ok {
				if nb, err := u.conn.WriteTo(umsg.data, umsg.to); err != nil {
					log.Warnln("[udp] send err:", err, nb)
				} else {
					//log.Println("[udp] send size:", nb)
					u.sendCount += nb
				}
			} else {
				log.Warnln("[udp] not-send invalid msg")
			}
		case <-tickChan:
			//log.Printf("[udp] statistics, sendCount=%d, recvCount=%d\n", u.sendCount, u.recvCount)
		case <-u.exitTick:
			close(u.exitTick)
			log.Println("[udp] udp exit writing")
			return
		}
	}
}
