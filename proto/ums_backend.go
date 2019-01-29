package proto

import (
	"encoding/json"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
)

// init regsiter UMS proto, auto-loading.
func init() {
	Inst().register("ums", &UmsProto{})
}

type UmsProto struct {
}

// parseRequest parse UMS REST request from UMS client.
// return sdp offer without new HTTP-body if ok, else return nil
func (p *UmsProto) parseRequest(req *ProtoRequest) (*ProtoResult, error) {
	if jreq, err := ParseUmsRequest(req.Data); err == nil {
		offer := []byte(jreq.GetOffer())
		//log.Println("[proto] ums-request offer: ", len(offer))
		if len(offer) < 10 {
			return nil, nil
		}
		return &ProtoResult{"offer", offer, nil}, nil
	} else {
		log.Warnln("[proto] ums-resquest error:", err)
		return nil, err
	}
}

// parseResponse parse UMS REST response from UMS server.
// return sdp answer with new HTTP-body if ok, else return nil
func (p *UmsProto) parseResponse(resp *ProtoResponse) (*ProtoResult, error) {
	if jresp, err := ParseUmsResponse(resp.Data); err == nil {
		answer := []byte(jresp.GetAnswer())
		//log.Println("[proto] ums-response answer: ", len(answer), string(answer))
		if len(answer) < 10 {
			return nil, nil
		}
		// Generate new response data(http body)
		answer2 := util.UpdateSdpCandidates(answer, resp.Candidates)
		jresp.SetAnswer(string(answer2))
		data := EncodeUmsResponse(jresp)
		//log.Println("[proto] ums-response answer2:", len(answer2), string(answer2))
		return &ProtoResult{"answer", answer, data}, nil
	} else {
		log.Warnln("[proto] ums-response error:", err)
		return nil, err
	}
}

// UMS Offer/Answer json format

func ParseUmsRequest(data []byte) (*UmsRequestJson, error) {
	var jreq UmsRequestJson
	err := json.Unmarshal(data, &jreq)
	return &jreq, err
}

func (r *UmsRequestJson) GetOffer() string {
	log.Println("[json] ums request type:", r.Type, ", session:", r.Action.SessionKey)
	user_roster := r.Action.UserRoster
	if user_roster == nil || len(user_roster) == 0 {
		//log.Warnln("[json] ums no user_roster in json")
		return ""
	}

	channels := user_roster[0].AudioStatus.Channels
	if channels == nil || len(channels) == 0 {
		log.Warnln("[json] ums no channels in json")
		return ""
	}

	webrtc_offer := channels[0].WebrtcOffer
	return webrtc_offer
}

func ParseUmsResponse(data []byte) (*UmsResponseJson, error) {
	var jreq UmsResponseJson
	err := json.Unmarshal(data, &jreq)
	return &jreq, err
}

func EncodeUmsResponse(resp *UmsResponseJson) []byte {
	if data, err := json.Marshal(resp); err == nil {
		return data
	} else {
		return nil
	}
}

func (r *UmsResponseJson) GetAnswer() string {
	//log.Println("[json] ums response code:", r.Code)
	user_roster := r.Action.UserRoster
	if user_roster == nil || len(user_roster) == 0 {
		//log.Warnln("[json] ums no user_roster in json")
		return ""
	}

	channels := user_roster[0].AudioStatus.Channels
	if channels == nil || len(channels) == 0 {
		log.Warnln("[json] ums no channels in json")
		return ""
	}

	webrtc_answer := channels[0].WebrtcAnswer
	return webrtc_answer
}

func (r *UmsResponseJson) SetAnswer(data string) {
	user_roster := r.Action.UserRoster
	if user_roster == nil || len(user_roster) == 0 {
		log.Warnln("[json] ums no user_roster in json")
		return
	}

	channels := user_roster[0].AudioStatus.Channels
	if channels == nil || len(channels) == 0 {
		log.Warnln("[json] ums no channels in json")
		return
	}

	channels[0].WebrtcAnswer = data
}

type UmsChannel struct {
	ChannelId     int    `json:"channel_id,omitempty"`
	WebrtcOffer   string `json:"webrtc_offer"`
	WebrtcServers string `json:"webrtc_servers"`
	WebrtcAnswer  string `json:"webrtc_answer"`
}

type UmsAudioStatus struct {
	Channels []UmsChannel `json:"channels"`
}

type UmsUserRoster struct {
	AudioStatus UmsAudioStatus `json:"audio_status"`
}

type UmsAction struct {
	SessionKey string          `json:"session_key,omitempty"`
	UserRoster []UmsUserRoster `json:"user_roster"`
}

type UmsRequestJson struct {
	Type          string    `json:"type"` // SESSION_REQUEST_WEBRTC_OFFER
	Action        UmsAction `json:"action"`
	MultiConn     bool      `json:"multi_webrtc_conn"`
	Agent         string    `json:"agent"`                 // chrome/firefox
	Version       int       `json:"version"`               // browser version
	WebrtcVersion int       `json:"webrtc_client_version"` // webrtc version
}

type UmsResponseJson struct {
	Action UmsAction              `json:"action"`
	Code   string                 `json:"code"`
	misc   map[string]interface{} `json:"-, omitempty"`
}
