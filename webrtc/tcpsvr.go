package webrtc

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/util"
)

// default ssl crt/key
const kTlsCrtFile string = "/tmp/etc/cert.pem"
const kTlsKeyFile string = "/tmp/etc/cert.key"

var kSslClientHello = []byte{
	0x80, 0x46, // msg len,MSB is 1 ,indicates a 2 byte header
	0x01,       // CLIENT_HELLO
	0x03, 0x01, // SSL 3.1
	0x00, 0x2d, // ciphersuite len
	0x00, 0x00, // session id len
	0x00, 0x10, // challenge len
	0x01, 0x00, 0x80, 0x03, 0x00, 0x80, 0x07, 0x00, 0xc0, // ciphersuites
	0x06, 0x00, 0x40, 0x02, 0x00, 0x80, 0x04, 0x00, 0x80, //
	0x00, 0x00, 0x04, 0x00, 0xfe, 0xff, 0x00, 0x00, 0x0a, //
	0x00, 0xfe, 0xfe, 0x00, 0x00, 0x09, 0x00, 0x00, 0x64, //
	0x00, 0x00, 0x62, 0x00, 0x00, 0x03, 0x00, 0x00, 0x06, //
	0x1f, 0x17, 0x0c, 0xa6, 0x2f, 0x00, 0x78, 0xfc, // challenge
	0x46, 0x55, 0x2e, 0xb1, 0x83, 0x39, 0xf1, 0xea, //
}

var kSslClientHelloLen = len(kSslClientHello)

var kSslServerHello = []byte{
	0x16,       // handshake message
	0x03, 0x01, // SSL 3.1
	0x00, 0x4a, // message len
	0x02,             // SERVER_HELLO
	0x00, 0x00, 0x46, // handshake len
	0x03, 0x01, // SSL 3.1
	0x42, 0x85, 0x45, 0xa7, 0x27, 0xa9, 0x5d, 0xa0, // server random
	0xb3, 0xc5, 0xe7, 0x53, 0xda, 0x48, 0x2b, 0x3f, //
	0xc6, 0x5a, 0xca, 0x89, 0xc1, 0x58, 0x52, 0xa1, //
	0x78, 0x3c, 0x5b, 0x17, 0x46, 0x00, 0x85, 0x3f, //
	0x20,                                           // session id len
	0x0e, 0xd3, 0x06, 0x72, 0x5b, 0x5b, 0x1b, 0x5f, // session id
	0x15, 0xac, 0x13, 0xf9, 0x88, 0x53, 0x9d, 0x9b, //
	0xe8, 0x3d, 0x7b, 0x0c, 0x30, 0x32, 0x6e, 0x38, //
	0x4d, 0xa2, 0x75, 0x57, 0x41, 0x6c, 0x34, 0x5c, //
	0x00, 0x04, // RSA/RC4-128/MD5
	0x00, // null compression
}

type TcpServer struct {
	hub *MaxHub
	ln  net.Listener
	mtx sync.Mutex

	config *TCPConfig
}

// tcp server (https/wss/webrtc-tcp)
func NewTcpServer(hub *MaxHub, cfg *TCPConfig) *TcpServer {
	//addr := fmt.Sprintf(":%d", port)
	addr := cfg.Net.Addr
	log.Println("[tcp] listen on: ", addr)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("[tcp] listen error=", err)
		return nil
	}

	if tcpL, ok := l.(*net.TCPListener); ok {
		log.Println("[tcp] set reuse addr")
		util.SetSocketReuseAddr(tcpL)
	}
	return &TcpServer{hub: hub, ln: l, config: cfg}
}

func (s *TcpServer) GetSslFile() (string, string) {
	return s.config.Net.TlsCrtFile, s.config.Net.TlsKeyFile
}

func (s *TcpServer) Params() *NetParams {
	return &s.config.Net
}

func (s *TcpServer) Run() {
	defer s.ln.Close()

	// How long to sleep on accept failure??
	var tempDelay time.Duration

	for {
		// Wait for a connection.
		conn, err := s.ln.Accept()
		if err != nil {
			log.Warnln("[tcp] accept error=", err)
			return
		}

		if ne, ok := err.(net.Error); ok && ne.Temporary() {
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if max := 1 * time.Second; tempDelay > max {
				tempDelay = max
			}
			log.Warnf("[tcp] accept error: %v; retrying after %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0

		handler := NewTcpHandler(s, conn)
		go handler.Run()
	}
}

func (s *TcpServer) Exit() {
}

// webrtc tcp data format: len(2B) + data(..)
//  so max packet size is 64*1024.
const kMaxPacketSize = 64 * 1024

type TcpHandler struct {
	svr      *TcpServer
	conn     *util.NetConn
	chanRecv chan interface{}

	sendCount int
	recvCount int
	exitTick  chan bool
}

func NewTcpHandler(svr *TcpServer, conn net.Conn) *TcpHandler {
	return &TcpHandler{
		svr:      svr,
		conn:     util.NewNetConn(conn),
		chanRecv: make(chan interface{}, 100),
		exitTick: make(chan bool),
	}
}

func (h *TcpHandler) Run() {
	if !h.Process() {
		// Close here only when failed
		h.conn.Close()
	}
}

func (h *TcpHandler) Process() bool {
	data, err := h.conn.Peek(kSslClientHelloLen)
	if len(data) < 3 {
		log.Warnf("[tcp] no enough data, err: %v", err)
		return false
	}

	prelen := 3
	prefix := data[0:prelen]

	//FIXME: how many bytes used here? (3bytes??)
	if bytes.Compare(prefix, kSslClientHello[0:prelen]) == 0 {
		if len(data) < kSslClientHelloLen {
			log.Warnf("[tcp] check ssl hello, len(%d) not enough < sslLen(%d)", len(data), kSslClientHelloLen)
			return false
		}
	}

	if len(data) >= kSslClientHelloLen && bytes.Compare(data[0:kSslClientHelloLen], kSslClientHello) == 0 {
		log.Println("[tcp] setup ssltcp handshake for", h.conn.RemoteAddr())
		h.conn.Write(kSslServerHello)
		h.ServeTCP()
	} else if bytes.Compare(prefix, kSslServerHello[0:prelen]) != 0 {
		log.Println("[tcp] setup http/rawtcp handshake for", h.conn.RemoteAddr())
		if checkHttpRequest(prefix) {
			http.Serve(NewHttpListener(h.conn), NewHTTPHandler(h.svr.config.Name, &h.svr.config.Http))
		} else {
			h.ServeTCP()
		}
	} else {
		log.Println("[tcp] setup tls key/cert for", h.conn.RemoteAddr())
		cer, err := tls.LoadX509KeyPair(h.svr.GetSslFile())
		if err != nil {
			log.Warnf("[tcp] load tls key/cert err: %v", err)
			return false
		}

		// fake tls.conn to plain conn here
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		conn2 := tls.Server(h.conn, config)
		if err := conn2.Handshake(); err != nil {
			log.Warnf("[tcp] check tls handshake err: %v", err)
			return false
		}

		conn3 := util.NewNetConn(conn2)
		if prefix, err = conn3.Peek(3); err != nil {
			log.Warnf("[tcp] check tls read err: %v", err)
			return false
		}

		// now it is plain conn for tcp/http
		log.Println("[tcp] setup tls (http/tcp) for", h.conn.RemoteAddr(), string(prefix))
		h.conn = conn3
		if checkHttpRequest(prefix) {
			http.Serve(NewHttpListener(h.conn), NewHTTPHandler(h.svr.config.Name, &h.svr.config.Http))
		} else {
			h.ServeTCP()
		}
	}

	log.Println("[tcp] success")
	return true
}

func (h *TcpHandler) ServeTCP() {
	defer h.conn.Close()
	log.Println("[tcp] tcp main begin")

	// write goroutine
	go h.writing()

	// reading
	head := make([]byte, 2)
	rbuf := make([]byte, kMaxPacketSize)
	sendChan := h.svr.hub.ChanRecvFromOuter()
	quit := false

loopTcpRead:
	for !quit {
		// read head(2bytes)
		if nret, err := h.conn.Read(head[0:2]); err != nil {
			log.Warnln("[tcp] tcp read head fail, err=", err)
			break
		} else {
			h.recvCount += nret
			if nret != 2 {
				log.Warnln("[tcp] tcp read head < 2bytes and quit")
				break
			}
		}

		// body size
		dsize := util.HostToNet16(util.BytesToUint16(head))
		if dsize == 0 {
			log.Warnln("[tcp] tcp invalid body")
			continue
		}
		//log.Println("[tcp] tcp body size:", dsize)

		// read body packet
		rpos := 0
		for rpos < int(dsize) {
			need := int(dsize) - rpos
			if nret, err := h.conn.Read(rbuf[rpos : rpos+need]); err != nil {
				log.Warnln("[tcp] tcp error reading:", err)
				quit = true
				break loopTcpRead
			} else {
				rpos += nret
				h.recvCount += nret
			}
		}

		// forward
		sendChan <- NewHubMessage(rbuf[0:dsize], h.conn.RemoteAddr(), nil, h.chanRecv)
	}

	h.exitTick <- true
	log.Println("[tcp] tcp main end")
}

func (h *TcpHandler) writing() {
	raddrStr := "client"
	//raddrStr := util.NetAddrString(h.conn.RemoteAddr())
	tickChan := time.NewTicker(time.Second * 10).C
	for {
		select {
		case msg, ok := <-h.chanRecv:
			if !ok {
				log.Println("[tcp] tcp close channel")
				return
			}

			if umsg, ok := msg.(*HubMessage); ok {
				pktLen := len(umsg.data)
				if pktLen > kMaxPacketSize {
					log.Warnln("[tcp] tcp too much data, size=", pktLen)
					continue
				}

				var wbuf bytes.Buffer
				util.WriteBig(&wbuf, uint16(pktLen))
				wbuf.Write(umsg.data)

				if nb, err := h.conn.Write(wbuf.Bytes()); err != nil {
					log.Warnln("[tcp] tcp send err:", err, nb)
					return
				} else {
					//log.Println("[tcp] tcp send size:", nb)
					h.sendCount += nb
				}
			} else {
				log.Warnln("[tcp] not-send invalid msg")
			}
		case <-tickChan:
			log.Printf("[tcp] statistics[%s], sendCount=%d, recvCount=%d\n", raddrStr, h.sendCount, h.recvCount)
		case <-h.exitTick:
			close(h.exitTick)
			log.Println("[tcp] tcp exit writing")
			return
		}
	}
}

// check http command

var kHttpMethodGET = []byte{0x47, 0x45, 0x54}
var kHttpMethodPOST = []byte{0x50, 0x4F, 0x53}
var kHttpMethodOPTIONS = []byte{0x4F, 0x50, 0x54}
var kHttpMethodHEAD = []byte{0x48, 0x45, 0x41}
var kHttpMethodPUT = []byte{0x50, 0x55, 0x54}
var kHttpMethodDELETE = []byte{0x44, 0x45, 0x4C}

func checkHttpRequest(data []byte) bool {
	if len(data) != 3 {
		return false
	}
	if bytes.Compare(data, kHttpMethodGET) == 0 ||
		bytes.Compare(data, kHttpMethodPOST) == 0 ||
		bytes.Compare(data, kHttpMethodHEAD) == 0 ||
		bytes.Compare(data, kHttpMethodPUT) == 0 ||
		bytes.Compare(data, kHttpMethodDELETE) == 0 ||
		bytes.Compare(data, kHttpMethodOPTIONS) == 0 {
		return true
	} else {
		return false
	}
}
