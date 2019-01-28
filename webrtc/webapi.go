package webrtc

import (
	"errors"
	"net/http"
	"strings"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/proto"
	"github.com/PeterXu/xrtc/util"
)

func newWebapi(upgrade string, t *RouteTarget) *Webapi {
	return &Webapi{upgrade: upgrade, route: t}
}

type Webapi struct {
	upgrade string
	route   *RouteTarget
}

const kWebapiSuccess string = `{"code":"RESPONSE_SUCCESS"}`
const kWebapiFailure string = `{"code":"RESPONSE_FAILURE"}`

const kWebapiVersion string = `{
"code": "RESPONSE_SUCCESS",
"sequence": "d94905a4-ea16-486d-90a1-d58af19beb57",
"data": "trunk 2019-02-01",
"server": "devcn001"
}`

// REST API,
// a. /xrtc/$cid[?token=]
// b. /xrtc/order/$time/$dur?token=
// c. /xrtc/leave[?token=]
func (api *Webapi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/board"):
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(kWebapiFailure))
			break
		}
		encoding := r.Header.Get("Content-Encoding")
		body, err := procHTTPBody(r.Body, encoding)
		if body == nil || err != nil {
			log.Warnln("[webapi] http invalid reqeust body, err=", err)
			w.Write([]byte(kWebapiFailure))
			break
		}
		agent, ok := r.Header["User-Agent"]
		if !ok {
			log.Warnln("[webapi] http no user-agent")
			w.Write([]byte(kWebapiFailure))
			break
		}
		if err := api.handleOffer(w, util.ParseAgent(agent[0]), body); err != nil {
			log.Warnln("[webapi] handle offer error:", err)
			w.Write([]byte(kWebapiFailure))
			break
		}
	case strings.HasPrefix(path, "/status"):
		w.Write([]byte(kWebapiSuccess))
	case strings.HasPrefix(path, "/object/version"):
		w.Write([]byte(kWebapiVersion))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (api *Webapi) handleOffer(w http.ResponseWriter, agent string, body []byte) error {
	req := &proto.ProtoRequest{"ums", body}
	if ret, err := proto.Inst().ParseRequest(req); err != nil {
		return err
	} else {
		if ret == nil {
			return errors.New("no offer in body")
		}
		var desc util.MediaDesc
		if !desc.Parse([]byte(ret.Sdp)) {
			return errors.New("invalid offer in body")
		}

		tlsPem := api.route.TlsPem
		if !desc.CreateAnswer(agent, tlsPem.CrtFile) {
			return errors.New("fail to create answer")
		}

		answer1 := desc.AnswerSdp()
		answer2 := util.UpdateSdpCandidates([]byte(answer1), Inst().Candidates())
		answer := string(answer2) + "\r\n"

		resp := proto.GetEmptyUmsResponse()
		if resp == nil {
			return errors.New("invalid ums proto")
		}
		resp.SetAnswer(answer)
		data := proto.EncodeUmsResponse(resp)
		log.Println("[webapi] response, data:", string(data))
		w.Write(data)

		wa1 := &WebrtcAction{
			data:   ret.Sdp,
			action: WebrtcActionOffer,
		}
		Inst().ChanAdmin() <- NewWebrtcActionMessage(wa1)

		routeBase := api.route.Base
		wa2 := &WebrtcAction{
			data:   []byte(answer),
			action: WebrtcActionAnswer,
			route:  &routeBase,
		}
		Inst().ChanAdmin() <- NewWebrtcActionMessage(wa2)
	}

	return nil
}
