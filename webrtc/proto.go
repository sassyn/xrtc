package webrtc

import (
	"encoding/json"

	log "github.com/PeterXu/xrtc/logging"
)

/// UMS Offer/Answer

func ParseUmsRequest(data []byte) (*UmsRequestJson, error) {
	var jreq UmsRequestJson
	err := json.Unmarshal(data, &jreq)
	return &jreq, err
}

func (r *UmsRequestJson) GetOffer() string {
	log.Println("[json] ums request type:", r.Type, ", session:", r.Action.SessionKey)
	user_roster := r.Action.UserRoster
	if user_roster == nil || len(user_roster) == 0 {
		log.Warnln("[json] ums no user_roster in json")
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

func (r *UmsResponseJson) GetAnswer() string {
	log.Println("[json] ums response code:", r.Code)
	user_roster := r.Action.UserRoster
	if user_roster == nil || len(user_roster) == 0 {
		log.Warnln("[json] ums no user_roster in json")
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
	Action UmsAction `json:"action"`
	Code   string    `json:"code"`
}

/// Janus Offer/Answer/Candidate

const kJanusMessage = "message" // offer
const kJanusTrickle = "trickle" // candidate
const kJanusEvent = "event"     // answer

func ParseJanusRequest(data []byte) (*JanusRequestJson, error) {
	var jreq JanusRequestJson
	err := json.Unmarshal(data, &jreq)
	return &jreq, err
}

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

type JanusResponseJson struct {
	Janus       string                 `json:"janus"`
	SessionId   int                    `json:"session_id"`
	Transaction string                 `json:"transaction"`
	Sender      int64                  `json:"sender"`
	Plugindata  map[string]interface{} `json:"plugindata"`
	Jsep        *JanusJsep             `json:"jsep, omitempty"`
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
