package proto

import (
	log "github.com/PeterXu/xrtc/logging"
)

/// proto args/return

type ProtoRequest struct {
	Hijack string // input hijack
	Data   []byte // input data (http body)
}

type ProtoResponse struct {
	Hijack     string   // input hijack
	Data       []byte   // input data (http body)
	Candidates []string // input candidates of xrtc
}

type ProtoResult struct {
	Type string // output type (offer/answer)
	Sdp  []byte // output sdp
	Data []byte // output data (new http body)
}

/// ProtoFactory

type ProtoFactory struct {
	protos map[string]Proto
}

var gProtoFactory *ProtoFactory

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

func (p *ProtoFactory) ParseRequest(req *ProtoRequest) (*ProtoResult, error) {
	if proto, ok := p.protos[req.Hijack]; ok {
		return proto.parseRequest(req)
	}
	return nil, nil
}

func (p *ProtoFactory) ParseResponse(resp *ProtoResponse) (*ProtoResult, error) {
	if proto, ok := p.protos[resp.Hijack]; ok {
		return proto.parseResponse(resp)
	}
	return nil, nil
}

/// internal interfces
type Proto interface {
	parseRequest(req *ProtoRequest) (*ProtoResult, error)
	parseResponse(resp *ProtoResponse) (*ProtoResult, error)
}
