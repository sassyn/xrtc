// Package proto parses sdp offer/answer/candidate from REST request/response.
// You can support different WebRTC servers(Janus/..) by registering here.
package proto

import (
	log "github.com/PeterXu/xrtc/logging"
)

// REST request packet from webrtc client
type ProtoRequest struct {
	Hijack string // input hijack
	Data   []byte // input data (http body)
}

// REST response packet from webrtc server
type ProtoResponse struct {
	Hijack     string   // input hijack
	Data       []byte   // input data (http body)
	Candidates []string // input candidates of xrtc
}

// Parsed result from ProtoRequest/ProtoResponse
type ProtoResult struct {
	Type string // output type (offer/answer)
	Sdp  []byte // output sdp
	Data []byte // output data (new http body)
}

// ProtoFactory manages all registed protos(janus/ums)
type ProtoFactory struct {
	protos map[string]Proto
}

var gProtoFactory *ProtoFactory

// Inst returns the single ProtoFactory instance.
func Inst() *ProtoFactory {
	if gProtoFactory == nil {
		gProtoFactory = &ProtoFactory{protos: make(map[string]Proto)}
	}
	return gProtoFactory
}

func (p *ProtoFactory) register(hijack string, proto Proto) {
	log.Println("[proto] register hijack=", hijack, proto)
	p.protos[hijack] = proto
}

func (p *ProtoFactory) unregister(hijack string) {
	delete(p.protos, hijack)
}

// ParseRequest parse REST request packet from webrtc client
func (p *ProtoFactory) ParseRequest(req *ProtoRequest) (*ProtoResult, error) {
	if proto, ok := p.protos[req.Hijack]; ok {
		return proto.parseRequest(req)
	}
	return nil, nil
}

// ParseResponse parse REST response packet from webrtc server
func (p *ProtoFactory) ParseResponse(resp *ProtoResponse) (*ProtoResult, error) {
	if proto, ok := p.protos[resp.Hijack]; ok {
		return proto.parseResponse(resp)
	}
	return nil, nil
}

// Proto internal interfce
type Proto interface {
	parseRequest(req *ProtoRequest) (*ProtoResult, error)
	parseResponse(resp *ProtoResponse) (*ProtoResult, error)
}
