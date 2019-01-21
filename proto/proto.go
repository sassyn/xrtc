// Package proto parses sdp offer/answer/candidate from REST request/response.
// You can support different WebRTC servers(Janus/..) by registering here.
package proto

import (
	log "github.com/PeterXu/xrtc/logging"
)

// REST request packet from webrtc client
type ProtoRequest struct {
	Tag  string // input tag for webrtc server
	Data []byte // input data (http body)
}

// REST response packet from webrtc server
type ProtoResponse struct {
	Tag        string   // input tag for webrtc server
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

func (p *ProtoFactory) register(tag string, proto Proto) {
	log.Println("[proto] register proto tag=", tag, proto)
	p.protos[tag] = proto
}

func (p *ProtoFactory) unregister(tag string) {
	delete(p.protos, tag)
}

// ParseRequest parse REST request packet from webrtc client
func (p *ProtoFactory) ParseRequest(req *ProtoRequest) (*ProtoResult, error) {
	if proto, ok := p.protos[req.Tag]; ok {
		return proto.parseRequest(req)
	}
	return nil, nil
}

// ParseResponse parse REST response packet from webrtc server
func (p *ProtoFactory) ParseResponse(resp *ProtoResponse) (*ProtoResult, error) {
	if proto, ok := p.protos[resp.Tag]; ok {
		return proto.parseResponse(resp)
	}
	return nil, nil
}

// Proto internal interfce
type Proto interface {
	parseRequest(req *ProtoRequest) (*ProtoResult, error)
	parseResponse(resp *ProtoResponse) (*ProtoResult, error)
}
