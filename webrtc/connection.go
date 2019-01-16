package webrtc

import (
	"bytes"
	"net"
	"time"

	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/util"
)

const kDefaultConnectionTimeout = 30 * 1000 // ms

type Connection struct {
	addr     net.Addr
	chanSend chan interface{}
	user     *User

	ready                  bool
	stunRequesting         uint32
	hadStunChecking        bool
	hadStunBindingResponse bool
	leave                  bool

	utime uint32 // update time
	ctime uint32 // create time
}

func NewConnection(addr net.Addr, chanSend chan interface{}) *Connection {
	c := &Connection{addr: addr, chanSend: chanSend, utime: util.NowMs(), ctime: util.NowMs()}
	c.ready = false
	c.hadStunChecking = false
	c.hadStunBindingResponse = false
	c.leave = false
	return c
}

func (c *Connection) setUser(user *User) {
	c.user = user
}

func (c *Connection) getAddr() net.Addr {
	return c.addr
}

func (c *Connection) dispose() {
	c.leave = true
	if c.user != nil {
		c.user.delConnection(c)
	}
}

func (c *Connection) isTimeout() bool {
	if util.NowMs() >= (c.utime + kDefaultConnectionTimeout) {
		return true
	}
	return false
}

func (c *Connection) onRecvData(data []byte) {
	c.utime = util.NowMs()

	if !c.user.isIceDirect() && util.IsStunPacket(data) {
		var msg util.IceMessage
		if !msg.Read(data) {
			log.Warnln("[conn] invalid stun message, dtype=", msg.Dtype)
			return
		}

		switch msg.Dtype {
		case util.STUN_BINDING_REQUEST:
			c.onRecvStunBindingRequest(msg.TransId)
		case util.STUN_BINDING_RESPONSE:
			if c.hadStunBindingResponse {
				log.Warnln("[conn] had stun binding response")
				return
			}
			log.Println("[conn] recv stun binding response")
			// init and enable srtp
			c.hadStunBindingResponse = true
			c.ready = true
		case util.STUN_BINDING_ERROR_RESPONSE:
			log.Warnln("[conn] error stun message")
		default:
			log.Warnln("[conn] unknown stun message=", msg.Dtype)
		}
	} else {
		// dtls handshake
		// rtp/rtcp data to inner
		//log.Println("[conn] recv dtls/rtp/rtcp, len=", len(data))
		c.ready = true
		c.user.sendToInner(c, data)
	}
}

func (c *Connection) sendData(data []byte) bool {
	c.chanSend <- NewHubMessage(data, nil, c.addr, nil)
	return true
}

func (c *Connection) isReady() bool {
	return c.ready
}

func (c *Connection) onRecvStunBindingRequest(transId string) {
	if c.leave {
		log.Warnln("[conn] had left!")
		return
	}

	//log.Println("[conn] send stun binding response")
	_, sendPwd := c.user.getSendIce()

	var buf bytes.Buffer
	if !util.GenStunMessageResponse(&buf, sendPwd, transId, c.addr) {
		log.Warnln("[conn] fail to gen stun response")
		return
	}

	//log.Println("[conn] stun response len=", len(buf.Bytes()))
	c.sendData(buf.Bytes())
	c.checkStunBindingRequest()
}

func (c *Connection) sendStunBindingRequest() bool {
	if c.hadStunBindingResponse {
		return false
	}

	//log.Println("[conn] send stun binding request")
	sendUfrag, _ := c.user.getSendIce()
	recvUfrag, recvPwd := c.user.getRecvIce()

	var buf bytes.Buffer
	if util.GenStunMessageRequest(&buf, sendUfrag, recvUfrag, recvPwd) {
		log.Println("[conn] send stun binding request, len=", buf.Len())
		c.sendData(buf.Bytes())
	} else {
		log.Warnln("[conn] fail to get stun request bufffer")
	}
	return true
}

func (c *Connection) checkStunBindingRequest() {
	if !c.sendStunBindingRequest() {
		return
	}

	if c.hadStunChecking {
		return
	}

	c.hadStunChecking = true

	go func() {
		c.stunRequesting = 500
		for {
			select {
			case <-time.After(time.Millisecond * time.Duration(c.stunRequesting)):
				if !c.sendStunBindingRequest() {
					log.Println("[conn] quit stun request interval")
					c.hadStunChecking = false
					return
				}

				if delta := util.NowMs() - c.utime; delta >= (15 * 1000) {
					log.Warnln("[conn] no response from client and quit")
					return
				} else if delta > (5 * 1000) {
					log.Println("[conn] adjust stun request interval")
					c.stunRequesting = delta / 2
				} else if delta < 500 {
					c.stunRequesting = 500
				}
			}
		}
	}()
}
