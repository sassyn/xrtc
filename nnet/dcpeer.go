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

// datachannel peer
type DcPeer struct {
	ctx        *DtlsContext
	dtls       *DtlsTransport
	sctp       *SctpTransport
	role       int
	remotePort int
	state      int
}

func NewDcPeer() (*DcPeer, error) {
	ctx, err := NewContext("gortcdc", 365)
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

type Signaller interface {
	Send(data []byte) error
	ReceiveFrom() <-chan []byte
}

func (p *DcPeer) Run(s Signaller) error {
	recvChan := s.ReceiveFrom()

	if p.role == dcRoleClient {
		log.Println("DTLS connecting")
		p.dtls.SetConnectState()
	} else {
		log.Println("DTLS accepting")
		p.dtls.SetAcceptState()
	}

	// feed data to dtls
	go func() {
		var buf [1 << 16]byte
		for {
			data := <-recvChan
			log.Println(len(data), " bytes of DTLS data received")
			p.dtls.Feed(data)

			n, _ := p.dtls.Read(buf[:])
			if n > 0 {
				log.Println(n, " bytes of SCTP data received")
				p.sctp.Feed(buf[:n])
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
				n, _ := p.dtls.Spew(buf[:])
				if n > 0 {
					log.Println(n, " bytes of DTLS data ready")
				}
				continue
			case <-exitTick:
				close(exitTick)
				// flush data
				n, _ := p.dtls.Spew(buf[:])
				if n > 0 {
					log.Println(n, " bytes of DTLS data ready")
				}
				break
			}
			break
		}
	}()

	if err := p.dtls.Handshake(); err != nil {
		return err
	}
	exitTick <- true
	log.Println("DTLS handshake done")

	// check sctp data
	go func() {
		var buf [1 << 16]byte
		for {
			data := <-p.sctp.BufferChannel
			log.Println(len(data), " bytes of SCTP data ready")
			p.dtls.Write(data)

			n, _ := p.dtls.Spew(buf[:])
			if n > 0 {
				log.Println(n, " bytes of DTLS data ready")
			}
		}
	}()

	if p.role == dcRoleClient {
		if err := p.sctp.Connect(p.remotePort); err != nil {
			return err
		}
	} else {
		if err := p.sctp.Accept(); err != nil {
			return err
		}
	}
	p.state = dcStateConnected
	log.Println("SCTP handshake done")

	for {
		select {
		case d := <-p.sctp.DataChannel:
			log.Printf("sid: %d, ppid: %d, data: %v", d.Sid, d.Ppid, d.Data)
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
	for i := range sdps {
		if strings.HasPrefix(sdps[i], "a=sctp-port:") {
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

func (p *DcPeer) ParseCandidateSdp(cands string) int {
	sdps := strings.Split(cands, "\r\n")
	count := 0
	for i := range sdps {
		if sdps[i] == "" {
			continue
		}
		count++
	}
	return count
}
