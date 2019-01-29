package webrtc

import (
	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
)

type User struct {
	tag         string
	iceTcp      bool                   // connect with webrtc server by tcp/udp
	iceDirect   bool                   // xrtc forward ice stun between outer and inner
	connections map[string]*Connection // outer client connections
	chanSend    chan interface{}       // data to inner
	service     *Service               // inner webrtc server

	leave      bool
	activeConn *Connection // active conn
	sendUfrag  string
	sendPasswd string
	recvUfrag  string
	recvPasswd string
	offer      string
	answer     string

	utime uint32 // update time
	ctime uint32 // create time
}

func NewUser(tag string, iceTcp, iceDirect bool) *User {
	return &User{
		rtcProxy:    true,
		tag:         tag,
		iceTcp:      iceTcp,
		iceDirect:   iceDirect,
		connections: make(map[string]*Connection),
		chanSend:    make(chan interface{}, 100),
		utime:       util.NowMs(),
		ctime:       util.NowMs(),
	}
}

func (u *User) getKey() string {
	return u.recvUfrag + ":" + u.sendUfrag
}

func (u *User) setOfferAnswer(host, offer, answer string) bool {
	var desc1 util.MediaDesc
	if desc1.Parse([]byte(offer)) {
		// parsed from offer
		u.recvUfrag = desc1.GetUfrag()
		u.recvPasswd = desc1.GetPasswd()
		u.offer = offer
		log.Println("[user] recv ice from offer:", u.recvUfrag, u.recvPasswd)
	} else {
		log.Warnln("[user] invalid offer")
		return false
	}

	var desc2 util.MediaDesc
	if desc2.Parse([]byte(answer)) {
		// parsed from answer
		u.sendUfrag = desc2.GetUfrag()
		u.sendPasswd = desc2.GetPasswd()
		u.answer = answer
		log.Println("[user] send ice from answer:", u.sendUfrag, u.sendPasswd)
	} else {
		log.Warnln("[user] invalid answer")
		return false
	}

	return u.startService(host, desc2.GetCandidates())
}

func (u *User) getSendIce() (string, string) {
	// parsed from answer
	return u.sendUfrag, u.sendPasswd
}

func (u *User) getRecvIce() (string, string) {
	// parsed from offer
	return u.recvUfrag, u.recvPasswd
}

func (u *User) getOffer() string {
	return u.offer
}

func (u *User) getAnswer() string {
	return u.answer
}

func (u *User) isIceTcp() bool {
	return u.iceTcp
}

func (u *User) isIceDirect() bool {
	return u.iceDirect
}

func (u *User) isProxy() bool {
	return u.rtcProxy
}

func (u *User) addConnection(conn *Connection) {
	if conn != nil && conn.getAddr() != nil {
		u.connections[util.NetAddrString(conn.getAddr())] = conn
		if u.activeConn == nil {
			u.activeConn = conn
		}
	} else {
		log.Warnln("[user] no conn or addr")
	}
}

func (u *User) delConnection(conn *Connection) {
	if conn != nil {
		delete(u.connections, util.NetAddrString(conn.getAddr()))
	}
}

func (u *User) sendToInner(conn *Connection, data []byte) {
	if u.leave {
		return
	}
	u.activeConn = conn
	u.chanSend <- data
}

func (u *User) sendToOuter(data []byte) {
	if u.leave {
		return
	}

	if u.activeConn == nil {
		for k, v := range u.connections {
			if v.isReady() {
				u.activeConn = v
				log.Println("[user] choose active conn, id=", k)
				break
			}
		}
	}

	if u.activeConn == nil {
		log.Warnln("[user] no active connection")
		return
	}

	u.activeConn.sendData(data)
}

func (u *User) isTimeout() bool {
	if len(u.connections) == 0 {
		return true
	}
	return false
}

func (u *User) dispose() {
	log.Println("[user] dispose, connection size=", len(u.connections))
	u.leave = true
	if u.service != nil {
		u.service.dispose()
	}
	if len(u.connections) > 0 {
		u.connections = make(map[string]*Connection)
	}
}

func (u *User) onServiceClose() {
	u.leave = true
}

func (u *User) startService(host string, candidates []string) bool {
	if u.service != nil {
		return true
	}

	hostIp := util.LookupIP(host)
	log.Println("[user] start service: ", hostIp)
	sufrag, spwd := u.getRecvIce()
	rufrag, rpwd := u.getSendIce()
	remoteSdp := genServiceSdp(hostIp, rufrag, rpwd, candidates)
	log.Println("[user] candidates=", candidates, remoteSdp)

	log.Println("[user] init service, sendfragpwd=", sufrag, spwd, len(sufrag), len(spwd))
	log.Println("[user] init service, recvfragpwd=", rufrag, rpwd, len(rufrag), len(rpwd))

	bret := false
	u.service = NewService(u, u.chanSend)
	if u.service.Init(sufrag, spwd, remoteSdp) {
		bret = u.service.Start()
	}
	return bret
}
