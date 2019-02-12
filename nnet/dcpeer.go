// Based-on https://github.com/xhs/gortcdc
package nnet

import (
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/PeterXu/xrtc/log"
)

const (
	dcRoleClient = 0
	dcRoleServer = 1

	dcStateClosed     = 0
	dcStateConnecting = 1
	dcStateConnected  = 2
)

type DtlsConnSink interface {
	RecvDataChan() chan []byte
	SendData(data []byte) bool
}

// datachannel peer
type DcPeer struct {
	ctx        *DtlsContext
	dtls       *DtlsTransport
	sctp       *SctpTransport
	role       int
	remotePort int
	state      int
}

func NewDcPeer(pem, key, passwd string) (*DcPeer, error) {
	ctx, err := NewContextEx(pem, key, passwd)
	if err != nil {
		return nil, err
	}
	dtls, err := ctx.NewTransport()
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	rand.Seed(time.Now().UnixNano())
	sctp, err := NewTransport(rand.Intn(50001) + 10000)
	if err != nil {
		ctx.Destroy()
		dtls.Destroy()
		return nil, err
	}
	p := &DcPeer{
		ctx:   ctx,
		dtls:  dtls,
		sctp:  sctp,
		role:  dcRoleServer,
		state: dcStateClosed,
	}
	return p, nil
}

func (p *DcPeer) Destroy() {
	p.dtls.Destroy()
	p.ctx.Destroy()
	p.sctp.Destroy()
}

func (p *DcPeer) Run(sink DtlsConnSink) error {
	if p.role == dcRoleClient {
		log.Println("[nnet] DTLS client connecting")
		p.dtls.SetConnectState()
	} else {
		log.Println("[nnet] DTLS server accepting")
		p.dtls.SetAcceptState()
	}

	recvChan := sink.RecvDataChan()

	// feed data to dtls/sctp
	go func() {
		var buf [1 << 16]byte
		for {
			data := <-recvChan
			//log.Println("[nnet] feed DTLS data:", len(data))
			p.dtls.Feed(data)

			if n, _ := p.dtls.Read(buf[:]); n > 0 {
				//log.Println("[nnet] feed SCTP data:", n)
				p.sctp.Feed(buf[0:n])
			}
		}
	}()

	// check dtls data
	exitTick := make(chan bool)
	go func() {
		var buf [1 << 16]byte
		tick := time.Tick(4 * time.Millisecond)
		for {
			select {
			case <-tick:
				if n, _ := p.dtls.Spew(buf[:]); n > 0 {
					log.Println("[nnet] reply DTLS(handshake) data:", n)
					sink.SendData(buf[0:n])
				}
				continue
			case <-exitTick:
				close(exitTick)
				// flush data
				if n, _ := p.dtls.Spew(buf[:]); n > 0 {
					log.Println("[nnet] flush DTLS(handshake) data:", n)
					sink.SendData(buf[0:n])
				}
			}
			break
		}
	}()

	if err := p.dtls.Handshake(); err != nil {
		log.Errorln("[nnet] DTLS handshake error:", err)
		return err
	}
	exitTick <- true
	log.Println("[nnet] DTLS handshake done")

	// check sctp data
	go func() {
		var buf [1 << 16]byte
		for {
			data := <-p.sctp.BufferChannel
			log.Println("[nnet] read DTLS-SCTP data:", len(data))
			p.dtls.Write(data)

			if n, _ := p.dtls.Spew(buf[:]); n > 0 {
				log.Println("[nnet] reply DTLS-SCTP data:", n)
				sink.SendData(buf[0:n])
			}
		}
	}()

	if p.role == dcRoleClient {
		if err := p.sctp.Connect(p.remotePort); err != nil {
			log.Errorln("[nnet] SCTP Connect error:", err)
			return err
		}
	} else {
		if err := p.sctp.Accept(); err != nil {
			log.Errorln("[nnet] SCTP Accept error:", err)
			return err
		}
	}
	p.state = dcStateConnected
	log.Println("[nnet] SCTP handshake done")

	for {
		select {
		case d := <-p.sctp.DataChannel:
			log.Printf("[nnet] sid: %d, ppid: %d, data: %v", d.Sid, d.Ppid, d.Data)
		}
	}

	return nil
}

var numbers = []rune("0123456789")

func randSession() string {
	s := make([]rune, 16)
	rand.Seed(time.Now().UnixNano())
	for i := range s {
		s[i] = numbers[rand.Intn(10)]
	}
	return string(s)
}

func (p *DcPeer) ParseOfferSdp(offer string) (int, error) {
	sdps := strings.Split(offer, "\r\n")
	if len(sdps) <= 2 {
		sdps = strings.Split(offer, "\n")
	}
	for i := range sdps {
		// a=sctp-port:5000
		// a=sctpmap:5000 webrtc-datachannel 1024
		if strings.HasPrefix(sdps[i], "a=sctp-port:") || strings.HasPrefix(sdps[i], "a=sctpmap:") {
			sctpmap := strings.Split(sdps[i], " ")[0]
			port, err := strconv.Atoi(strings.Split(sctpmap, ":")[1])
			if err != nil {
				return 0, err
			}
			p.remotePort = port
		} else if strings.HasPrefix(sdps[i], "a=setup:active") {
			if p.role == dcRoleClient {
				p.role = dcRoleServer
			}
		} else if strings.HasPrefix(sdps[i], "a=setup:passive") {
			if p.role == dcRoleServer {
				p.role = dcRoleClient
			}
		}
	}

	p.state = dcStateConnecting

	return 0, nil
}
