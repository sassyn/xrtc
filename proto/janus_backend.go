package proto

import (
	"encoding/json"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
)

// init regsiter Janus proto, auto-loading.
func init() {
	Inst().register("janus", &JanusProto{})
}

type JanusProto struct {
}

// parseRequest parse Janus REST-API request from Janus client.
// return sdp offer without new HTTP-body if ok, else return nil
func (p *JanusProto) parseRequest(req *ProtoRequest) (*ProtoResult, error) {
	if jreq, err := ParseJanusRequest(req.Data); err == nil {
		if jreq.Janus == kJanusMessage && jreq.Jsep != nil {
			offer := []byte(jreq.Jsep.Sdp)
			//log.Println("[proto] janus-request offer:", len(offer), string(offer))
			// NOTE: donot required to update request
			return &ProtoResult{"offer", offer, nil}, nil
		} else if jreq.Janus == kJanusTrickle {
			//log.Println("[proto] janus-request candidate:", string(req.Data))
			return nil, nil
		} else {
			//log.Println("[proto] janus-request:", jresp.Janus)
			return nil, nil
		}
	} else {
		log.Warnln("[proto] janus-request error:", err, string(req.Data))
		return nil, err
	}
}

// parseResponse parse REST-API response from Janus server.
// return sdp answer with new HTTP-body if ok, else return nil
func (p *JanusProto) parseResponse(resp *ProtoResponse) (*ProtoResult, error) {
	if jresp, err := ParseJanusResponse(resp.Data); err == nil {
		if jresp.Janus == kJanusEvent && jresp.Jsep != nil {
			answer := []byte(jresp.Jsep.Sdp)
			//log.Println("[proto] janus-response answer: ", len(answer), string(answer))
			jresp.Jsep.Sdp = string(util.UpdateSdpCandidates(answer, resp.Candidates))
			// Generate new response data(http body)
			data := EncodeJanusResponse(jresp)
			//log.Println("[proto] janus-response answer2:", len(jresp.Jsep.Sdp), jresp.Jsep.Sdp)
			return &ProtoResult{"answer", answer, data}, nil
		} else {
			//log.Println("[proto] janus-response:", jresp.Janus)
			return nil, nil
		}
	} else {
		log.Warnln("[proxy] janus-response error:", err, string(resp.Data))
		return nil, err
	}
}

// These are the type of Janus json message formats
const (
	kJanusMessage = "message" // sdp offer in this message
	kJanusTrickle = "trickle" // candidate in this message
	kJanusEvent   = "event"   // sdp answer in this message
)

func ParseJanusRequest(data []byte) (*JanusRequestJson, error) {
	var jreq JanusRequestJson
	err := json.Unmarshal(data, &jreq)
	return &jreq, err
}

// JanusRequestJson
type JanusRequestJson struct {
	Janus       string          `json:"janus"`
	Body        *JanusBody      `json:"body, omitempty"`
	Transaction string          `json:"transaction"`
	Jsep        *JanusJsep      `json:"jsep, omitempty"`
	Candidate   *JanusCandidate `json:"candidate, omitempty"`
}

func ParseJanusResponse(data []byte) (*JanusResponseJson, error) {
	var jresp JanusResponseJson
	err := json.Unmarshal(data, &jresp)
	return &jresp, err
}

func EncodeJanusResponse(resp *JanusResponseJson) []byte {
	if data, err := json.Marshal(resp); err == nil {
		return data
	} else {
		return nil
	}
}

// JanusResponseJson
type JanusResponseJson struct {
	Janus       string                 `json:"janus"`
	SessionId   int                    `json:"session_id"`
	Transaction string                 `json:"transaction"`
	Sender      int64                  `json:"sender"`
	Plugindata  map[string]interface{} `json:"plugindata"`
	Jsep        *JanusJsep             `json:"jsep, omitempty"`
	misc        map[string]interface{} `json:"-, omitempty"`
}

type JanusBody struct {
	Audio bool `json:"audio"`
	Video bool `json:"video"`
}

type JanusJsep struct {
	Type string `json:"type"`
	Sdp  string `json:"sdp"`
}

type JanusCandidate struct {
	Candidate     string `json:"candidate"`
	SdpMid        string `json:"sdpMid"`
	SdpMLineIndex int    `json:"sdpMLineIndex"`
}
