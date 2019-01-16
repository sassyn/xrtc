package webrtc

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/util"
)

type Service struct {
	agent *Agent
	user  *User

	// when iceDirect == true
	iceInChan  chan []byte
	iceOutChan chan []byte
	iceCands   []util.Candidate
	remoteAddr net.Addr

	ready    bool
	chanRecv chan interface{}

	sendCount int
	recvCount int

	// exit chan
	exitTick chan bool

	utime uint32 // update time
	ctime uint32 // create time
}

func NewService(user *User, chanRecv chan interface{}) *Service {
	s := &Service{
		ready:    false,
		user:     user,
		chanRecv: chanRecv,
		exitTick: make(chan bool),
		utime:    util.NowMs(),
		ctime:    util.NowMs(),
	}
	return s
}

func (s *Service) Init(ufrag, pwd, remote string) bool {
	if s.user.isIceDirect() {
		var desc util.MediaDesc
		if desc.Parse([]byte(remote)) {
			s.iceCands = util.ParseCandidates(desc.GetCandidates())
			log.Println("[service] cands", s.iceCands)
			// connect server with cands
			s.iceInChan = make(chan []byte, 100)
			s.iceOutChan = make(chan []byte, 100)
		} else {
			log.Warnln("[service] fail to parse sdp:", remote)
			return false
		}
		return true
	}

	//iceDebugEnable(true)
	s.agent, _ = NewAgent()
	s.agent.SetMinMaxPort(40000, 50000)
	s.agent.SetLocalCredentials(ufrag, pwd)
	if err := s.agent.GatherCandidates(); err != nil {
		log.Warnln("[service] gather error:", err)
		return false
	}

	//local := s.agent.GenerateSdp()
	//log.Println("[service] local sdp:", local)

	//log.Println("[service] remote sdp:", remote)
	// required to get ice ufrag/password
	if _, err := s.agent.ParseSdp(remote); err != nil {
		log.Warnln("[service] ParseSdp, err=", err)
		return false
	}

	// optional if ParseSdp contains condidates
	//s.agent.ParseCandidateSdp(cand)

	log.Println("[service] Init ok")
	return true
}

func (s *Service) onRecvData(data []byte) {
	s.recvCount += len(data)
	s.user.sendToOuter(data)
}

// sendData sends stun/dtls/srtp/srtcp packets to inner(webrtc server)
func (s *Service) sendData(data []byte) {
	if !s.ready {
		log.Warnln("[service] inner not ready")
		return
	}

	s.sendCount += len(data)
	if s.agent != nil {
		s.agent.Send(data)
	} else {
		if !s.user.iceDirect {
			log.Warnln("[service] not agent/iceDirect")
			return
		}
		s.iceOutChan <- data
	}
}

func (s *Service) eventChannel() chan *GoEvent {
	if s.agent != nil {
		return s.agent.EventChannel
	} else {
		return nil
	}
}

func (s *Service) candidateChannel() chan string {
	if s.agent != nil {
		return s.agent.CandidateChannel
	} else {
		return nil
	}
}

func (s *Service) dataChannel() chan []byte {
	if s.agent != nil {
		return s.agent.DataChannel
	} else {
		if !s.ready {
			return nil
		}
		return s.iceInChan
	}
}

func (s *Service) Start() bool {
	if s.agent != nil {
		go s.agent.Run()
	} else {
		retCh := make(chan error)
		go s.iceLoop(retCh)
		if err := <-retCh; err != nil {
			log.Warnln("[service] failed:", err)
			return false
		}
	}

	go s.Run()

	return true
}

func (s *Service) dispose() {
	log.Println("[service] dispose begin")
	if s.agent != nil {
		s.agent.Destroy()
		s.agent = nil
	}
	s.exitTick <- true
	log.Println("[service] dispose end")
}

func (s *Service) ChanRecv() chan interface{} {
	if s.ready {
		return s.chanRecv
	}
	return nil
}

// iceLoop works when iceDirect is on
func (s *Service) iceLoop(retCh chan error) {
	var tcpCands []util.Candidate
	var udpCands []util.Candidate
	for _, cand := range s.iceCands {
		if cand.CandType != "typ host" {
			continue
		}
		if cand.Transport == "tcp" {
			if cand.NetType == "tcptype passive" {
				tcpCands = append(tcpCands, cand)
			}
		} else {
			udpCands = append(udpCands, cand)
		}
	}

	var cands []util.Candidate
	if s.user.isIceTcp() {
		cands = append(cands, tcpCands...)
		cands = append(cands, udpCands...)
	} else {
		cands = append(cands, udpCands...)
		cands = append(cands, tcpCands...)
	}

	var isTcp bool
	var conn net.Conn
	for _, cand := range cands {
		isTcp = (cand.Transport == "tcp")

		var err error
		addr := fmt.Sprintf("%s:%s", cand.RelAddr, cand.RelPort)
		if conn, err = net.Dial(cand.Transport, addr); err != nil {
			log.Warnln("[service] connect fail", addr, err)
			continue
		}

		log.Println("[service] connect ok to", cand.Transport, addr)
		s.ready = true
		break
	}

	if !s.ready {
		log.Warnln("[service] no success conn for ice")
		retCh <- errors.New("ice to server failed")
		return
	} else {
		log.Println("[service] success conn for ice, isTcp:", isTcp)
		s.remoteAddr = conn.RemoteAddr()
		retCh <- nil
	}

	defer conn.Close()

	errCh := make(chan error)

	// read loop
	go func(errCh chan error) {
		rbuf := make([]byte, kMaxPacketSize)
		for {
			var nret int
			var err error
			if isTcp {
				nret, err = ReadIceTcpPacket(conn, rbuf[0:])
			} else {
				nret, err = conn.Read(rbuf)
			}
			//log.Println("[service] read loop, isTcp:", isTcp, nret)
			if err == nil {
				if nret > 0 {
					data := make([]byte, nret)
					copy(data, rbuf[0:nret])
					s.iceInChan <- data
				} else {
					log.Warnln("[service] read data nothing")
				}
			} else {
				errCh <- err
				break
			}
		}
	}(errCh)

	// write loop
	for {
		select {
		case data := <-s.iceOutChan:
			var nb int
			var err error
			if isTcp {
				nb, err = WriteIceTcpPacket(conn, data)
			} else {
				nb, err = conn.Write(data)
			}
			if err != nil {
				log.Warnln("[service] write data err:", err)
			} else {
				//log.Println("[service] write data nb:", nb, len(data), isTcp)
				_ = nb
			}
		case err := <-errCh:
			log.Warnln("[service] read data err:", err)
			return
		}
	}
}

func (s *Service) Run() {
	log.Println("[service] begin")

	agentKey := s.user.getKey()
	_ = agentKey

	tickChan := time.NewTicker(time.Second * 10).C

	for {
		select {
		case msg, ok := <-s.ChanRecv():
			if !ok {
				log.Println("[service] close chanRecv")
				return
			}
			if data, ok := msg.([]byte); ok {
				//log.Println("[service] forward data to inner, size=", len(data))
				s.sendData(data)
			}
			continue
		case cand := <-s.candidateChannel():
			//log.Println("[service] agent candidate:", cand)
			// send to server
			_ = cand
			continue
		case e := <-s.eventChannel():
			if e.Event == EventNegotiationDone {
				log.Println("[service] agent negotiation done")
				// dtls handshake/sctp
				//s.agent.Send([]byte("hello"))
			} else if e.Event == EventStateChanged {
				switch e.State {
				case EventStateNiceDisconnected:
					s.ready = false
					log.Println("[service] agent ice disconnected")
				case EventStateNiceConnected:
					s.ready = true
					log.Println("[service] agent ice connected")
				case EventStateNiceReady:
					s.ready = true
					log.Println("[service] agent ice ready")
				default:
					s.ready = false
					log.Println("[service] agent ice state:", e.State)
				}
			} else {
				log.Warnln("[service] unknown agent event:", e)
			}
			continue
		case d := <-s.dataChannel():
			// dtls handshake/sctp
			//log.Println("[service] agent received:", len(d))
			s.onRecvData(d)
			continue
		case <-tickChan:
			//log.Printf("[service] agent[%s] statistics, sendCount=%d, recvCount=%d\n", agentKey, s.sendCount, s.recvCount)
			continue
		case <-s.exitTick:
			close(s.exitTick)
			break
		}
		break
	}
	log.Println("[service] end")
}

func genServiceSdp(hostIp, ufrag, pwd string, candidates []string) string {
	const kDefaultUdpCandidate = "a=candidate:1 1 udp 2113937151 %s 5000 typ host"
	const kDefaultTcpCandidate = "a=candidate:2 1 tcp 1518280447 %s 443 typ host tcptype passive"

	var lines []string
	lines = append(lines, "m=application")
	lines = append(lines, "c=IN IP4 0.0.0.0")
	lines = append(lines, "a=ice-ufrag:"+ufrag)
	lines = append(lines, "a=ice-pwd:"+pwd)
	if candidates != nil && len(candidates) > 0 {
		lines = append(lines, candidates...)
	} else {
		lines = append(lines, fmt.Sprintf(kDefaultUdpCandidate, hostIp))
		lines = append(lines, fmt.Sprintf(kDefaultTcpCandidate, hostIp))
	}
	return strings.Join(lines, "\n")
}
