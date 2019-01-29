package webrtc

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
)

type HttpServer struct {
	hub *MaxHub
	ln  net.Listener

	config *HTTPConfig
}

// http server (http/https/ws/wss)
func NewHttpServer(hub *MaxHub, cfg *HTTPConfig) *HttpServer {
	//addr := fmt.Sprintf(":%d", port)
	addr := cfg.Net.Addr
	log.Println("[http] listen on: ", addr)

	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal("[http] listen error=", err)
		return nil
	}
	return &HttpServer{hub: hub, ln: l, config: cfg}
}

func (s *HttpServer) GetSslFile() (string, string) {
	return s.config.Net.TlsCrtFile, s.config.Net.TlsKeyFile
}

func (s *HttpServer) Params() *NetParams {
	return &s.config.Net
}

func (s *HttpServer) Run() {
	s.config.Http.Cache = NewCache()
	defer s.config.Http.Cache.Close()

	defer s.ln.Close()

	// How long to sleep on accept failure??
	var tempDelay time.Duration

	for {
		// Wait for a connection.
		conn, err := s.ln.Accept()
		if err != nil {
			log.Warnln("[http] accept error=", err)
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
			log.Printf("[http] accept error: %v; retrying after %v", err, tempDelay)
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0

		handler := NewHttpHandler(s, conn)
		go handler.Run()
	}
}

func (s *HttpServer) Close() {
	//s.ln.Close()
}

type HttpHandler struct {
	svr  *HttpServer
	conn *util.NetConn
}

func NewHttpHandler(svr *HttpServer, conn net.Conn) *HttpHandler {
	return &HttpHandler{svr: svr, conn: util.NewNetConn(conn)}
}

func (h *HttpHandler) Run() {
	if !h.Process() {
		// Close here only when failed
		h.conn.Close()
	}
}

func (h *HttpHandler) Process() bool {
	data, err := h.conn.Peek(kSslClientHelloLen)
	if len(data) < 3 {
		log.Printf("[http] no enough data, err: %v", err)
		return false
	}

	prelen := 3
	prefix := data[0:prelen]

	//FIXME: how many bytes used here? (3bytes??)
	if bytes.Compare(prefix, kSslClientHello[0:prelen]) == 0 {
		if len(data) < kSslClientHelloLen {
			log.Warnf("[http] check ssl hello, len(%d) not enough < sslLen(%d)", len(data), kSslClientHelloLen)
			return false
		}
	}

	isSsl := false
	if len(data) >= kSslClientHelloLen && bytes.Compare(data[0:kSslClientHelloLen], kSslClientHello) == 0 {
		isSsl = true
	} else if bytes.Compare(prefix, kSslServerHello[0:prelen]) != 0 {
		isSsl = false
	} else {
		isSsl = true
	}

	if isSsl {
		//log.Println("[http] setup tls key/cert for", h.conn.RemoteAddr())
		cer, err := tls.LoadX509KeyPair(h.svr.GetSslFile())
		if err != nil {
			log.Warnf("[http] load tls key/cert err: %v", err)
			return false
		}

		// fake tls.conn to plain conn here
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		conn2 := tls.Server(h.conn, config)
		if err := conn2.Handshake(); err != nil {
			log.Warnf("[http] check tls handshake err: %v", err)
			return false
		}

		// set new conn(tls)
		h.conn = util.NewNetConn(conn2)
	}

	// now it is plain conn for tcp/http
	//log.Println("[http] setup http/https for", h.conn.RemoteAddr())
	http.Serve(
		NewHttpListener(h.conn),
		NewHttpServeHandler(h.svr.config.Name, &h.svr.config.Http),
	)
	//log.Println("[http] setup success")
	return true
}

func NewHttpListener(c *util.NetConn) *HttpListener {
	return &HttpListener{c, false, false}
}

type HttpListener struct {
	conn    *util.NetConn
	used    bool
	closing bool
}

func (l *HttpListener) Accept() (net.Conn, error) {
	//log.Println("[http] HttpListener Accept.., ", l.used)
	if !l.used {
		l.used = true
		return l.conn, nil
	} else {
		return nil, errors.New("[http] HttpListener Quit")
	}
}

func (l *HttpListener) Close() error {
	//log.Println("[http] HttpListener Close..,", l.closing)
	if l.closing {
		l.conn.Close()
	} else {
	}
	return nil
}

func (l *HttpListener) Addr() net.Addr {
	return l.conn.RemoteAddr()
}
