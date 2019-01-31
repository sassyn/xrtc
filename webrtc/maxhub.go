package webrtc

import (
	"net"
	"strings"
	"time"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
)

type OneServer interface {
	Run()
	Close()
	Params() *NetParams
}

type NetMisc struct {
	TlsPem   TlsPem
	chanSend chan interface{}
}

type HubMessage struct {
	data []byte
	from net.Addr
	to   net.Addr
	misc interface{}
}

func NewHubMessage(data []byte, from net.Addr, to net.Addr, misc interface{}) *HubMessage {
	return &HubMessage{data, from, to, misc}
}

type MaxHub struct {
	connections map[string]*Connection
	users       map[string]*User
	servers     []OneServer

	// cache control
	cache *Cache

	// data from outer client(over udpsvr/tcpsvr)
	chanRecvFromOuter chan interface{}

	// admin chan
	chanAdmin chan interface{}

	// exit chan
	exitTick chan bool
}

func NewMaxHub() *MaxHub {
	hub := &MaxHub{cache: NewCache(), exitTick: make(chan bool)}
	hub.connections = make(map[string]*Connection)
	hub.users = make(map[string]*User)

	hub.chanRecvFromOuter = make(chan interface{}, 1000) // unblocking mode, data from udpsvr
	hub.chanAdmin = make(chan interface{}, 10)           // data from faibo(admin/control)
	return hub
}

// admin
func (h *MaxHub) OnAdminData(msg *HubMessage) {
	// TODO: process offer/answer
	wa, ok := msg.misc.(*WebrtcAction)
	if !ok {
		log.Warnln("[maxhub] invalid admin message")
		return
	}
	if wa.action == WebrtcActionOffer {
		var desc util.MediaDesc
		if !desc.Parse(wa.data) {
			log.Warnln("[maxhub] invalid offer")
			return
		}
		ufrag := desc.GetUfrag() + "_offer"
		log.Println("[maxhub] outer offer ufrag: ", ufrag)
		h.cache.Set(ufrag, NewCacheItem(wa))
	} else if wa.action == WebrtcActionAnswer {
		var desc util.MediaDesc
		if !desc.Parse(wa.data) {
			log.Warnln("[maxhub] invalid answer")
			return
		}
		ufrag := desc.GetUfrag() + "_answer"
		log.Println("[maxhub] inner answer ufrag: ", ufrag)
		h.cache.Set(ufrag, NewCacheItem(wa))
	} else {
		log.Warnln("[maxhub] invalid admin action=", wa.action)
	}
}

func (h *MaxHub) findConnection(addr net.Addr) *Connection {
	var key string = util.NetAddrString(addr)
	if u, ok := h.connections[key]; ok {
		return u
	}
	return nil
}

func (h *MaxHub) handleStunBindingRequest(data []byte, addr net.Addr, misc interface{}) {
	var msg util.IceMessage
	if !msg.Read(data) {
		log.Warnln("[maxhub] invalid stun message")
		return
	}

	log.Println("[maxhub] proc stun message")
	switch msg.Dtype {
	case util.STUN_BINDING_REQUEST:
		attr := msg.GetAttribute(util.STUN_ATTR_USERNAME)
		if attr == nil {
			log.Warnln("[maxhub] no stun attr of username")
			return
		}

		stunName := string(attr.(*util.StunByteStringAttribute).Data)
		items := strings.Split(stunName, ":")
		if len(items) != 2 {
			log.Warnln("[maxhub] invalid stun name:", stunName)
			return
		}

		log.Println("[maxhub] stun name:", items)

		var offer, answer string
		var route *RouteBase
		user, ok := h.users[stunName]
		if !ok {
			offerUfrag := items[1] + "_offer"
			if item := h.cache.Get(offerUfrag); item != nil {
				if wa, ok := item.data.(*WebrtcAction); ok {
					offer = string(wa.data)
				}
			}

			answerUfrag := items[0] + "_answer"
			if item := h.cache.Get(answerUfrag); item != nil {
				if wa, ok := item.data.(*WebrtcAction); ok {
					answer = string(wa.data)
					route = wa.route
				}
			}
			if len(offer) <= 10 || len(answer) <= 10 {
				log.Warnln("[maxhub] invalid offer or answer:", len(offer), len(answer))
				return
			}
			if route == nil {
				log.Warnln("[maxhub] invalid route:", route)
				return
			}

			user = NewUser(route)
			if !user.setOfferAnswer(offer, answer) {
				log.Warnln("[maxhub] invalid offer/answer for user")
				return
			}
			h.users[stunName] = user
		} else {
			log.Warnln("[maxhub] another connection for user-stun=", stunName)
		}

		if netMisc, ok := misc.(*NetMisc); ok {
			// new conn
			conn := NewConnection(addr, netMisc)
			conn.setUser(user)
			// add conn into user
			user.addConnection(conn)
			h.connections[util.NetAddrString(addr)] = conn
			conn.onRecvData(data)
		} else {
			log.Warnln("[maxhub] no chanSend for this connection")
		}
	default:
		log.Warnln("[maxhub] invalid stun type =", msg.Dtype)
	}
}

func (h *MaxHub) clearConnections() {
	var connKeys []string
	for k, v := range h.connections {
		if v.isTimeout() {
			v.dispose()
			connKeys = append(connKeys, k)
		}
	}

	if len(connKeys) > 0 {
		log.Println("[maxhub] clear connections, size=", len(connKeys))
		for index := range connKeys {
			delete(h.connections, connKeys[index])
		}
	}
}

func (h *MaxHub) clearUsers() {
	var userKeys []string
	for k, v := range h.users {
		if v.isTimeout() {
			v.dispose()
			userKeys = append(userKeys, k)
		}
	}

	if len(userKeys) > 0 {
		log.Println("[maxhub] clear users, size=", len(userKeys))
		for index := range userKeys {
			delete(h.users, userKeys[index])
		}
	}
}

func (h *MaxHub) OnRecvFromOuter(msg *HubMessage) {
	// 1. stun request/response
	// 2. dtls handshake(key)
	// 3. sctp create/srtp init
	//log.Println("[maxhub] data from outer")
	if conn := h.findConnection(msg.from); conn != nil {
		conn.onRecvData(msg.data)
	} else {
		if util.IsStunPacket(msg.data) {
			h.handleStunBindingRequest(msg.data, msg.from, msg.misc)
		} else {
			log.Warnln("[maxhub] invalid data from outer")
		}
	}
}

// request from outer (browser users)
func (h *MaxHub) ChanRecvFromOuter() chan interface{} {
	return h.chanRecvFromOuter
}

// request from admin(fabio)
func (h *MaxHub) ChanAdmin() chan interface{} {
	return h.chanAdmin
}

func (h *MaxHub) AddServer(server OneServer) {
	h.servers = append(h.servers, server)
}

func (h *MaxHub) Candidates() []string {
	var candidates []string
	for _, svr := range h.servers {
		candidates = append(candidates, svr.Params().Candidates...)
	}
	return candidates
}

func (h *MaxHub) Close() {
	for _, svr := range h.servers {
		svr.Close()
	}
	h.exitTick <- true
	h.cache.Close()
}

func (h *MaxHub) Run() {
	log.Println("[maxhub] Run begin")

	errCh := make(chan error)

	go h.loopForOuter(errCh)

	quit := false
	for !quit {
		select {
		case msg, ok := <-h.chanAdmin:
			if ok {
				h.OnAdminData(msg.(*HubMessage))
			}
		case <-h.exitTick:
			quit = true
			errCh <- nil
			log.Println("hub exit...")
		}
	}
	log.Println("[maxhub] Run end")
}

func (h *MaxHub) loopForOuter(errCh chan error) {
	tickChan := time.NewTicker(time.Second * 30).C

	quit := false
	for !quit {
		select {
		case msg, ok := <-h.chanRecvFromOuter:
			if ok {
				h.OnRecvFromOuter(msg.(*HubMessage))
			}
		case <-tickChan:
			h.clearConnections()
			h.clearUsers()
		case <-errCh:
			quit = true
		}
	}
}
