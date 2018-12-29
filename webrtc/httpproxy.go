package webrtc

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	gziph "github.com/PeterXu/xrtc/gzip"
	log "github.com/PeterXu/xrtc/logging"
	uuid "github.com/PeterXu/xrtc/uuid"
)

const kHttpHeaderWebrtcHijack string = "X-Webrtc-Hijack"

func readHTTPBody(httpBody io.ReadCloser) ([]byte, error) {
	if body, err := ioutil.ReadAll(httpBody); err == nil {
		err = httpBody.Close()
		return body, err
	} else {
		return nil, err
	}
}

func procHTTPBody(httpBody io.ReadCloser, encoding string) ([]byte, error) {
	var body []byte
	var err error

	if body, err = readHTTPBody(httpBody); err != nil {
		log.Println("invalid http body, err=", err)
		return nil, err
	}

	//log.Println("http body encoding: ", encoding)
	if encoding == "gzip" {
		var zr *gzip.Reader
		if zr, err = gzip.NewReader(bytes.NewReader(body)); err == nil {
			body, err = ioutil.ReadAll(zr)
			zr.Close()
		}
	} else if encoding == "deflate" {
		var zr io.ReadCloser
		if zr = flate.NewReader(bytes.NewReader(body)); zr != nil {
			body, err = ioutil.ReadAll(zr)
			zr.Close()
		}
	} else if len(encoding) > 0 {
		err = errors.New("unsupport encoding:" + encoding)
	}

	return body, err
}

func newHTTPProxy(target *url.URL, tr http.RoundTripper, flush time.Duration, cfg HttpParams) http.Handler {
	return &httputil.ReverseProxy{
		// this is a simplified director function based on the
		// httputil.NewSingleHostReverseProxy() which does not
		// mangle the request and target URL since the target
		// URL is already in the correct format.
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = target.Path
			req.URL.RawQuery = target.RawQuery
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}

			if req.Method != http.MethodPost || req.ContentLength <= 0 {
				return
			}

			// TODO: process request body
			hijack := ""
			for k, v := range cfg.Hijacks {
				if strings.HasPrefix(req.URL.Path, k) {
					hijack = v
					break
				}
			}
			if len(hijack) == 0 {
				log.Warnln("[proxy] no hijack for path=", req.URL.Path)
				return
			}

			req.Header.Add(kHttpHeaderWebrtcHijack, hijack)
			encoding := req.Header.Get("Content-Encoding")
			body, err := procHTTPBody(req.Body, encoding)
			if body == nil || err != nil {
				log.Println("[proxy] invalid reqeust body, err=", err)
				return
			}

			adminChan := Inst().ChanAdmin()
			if hijack == "ums" {
				if jreq, err := ParseUmsRequest(body); err == nil {
					offer := []byte(jreq.GetOffer())
					//log.Println("ums-request offer: ", len(offer))
					adminChan <- NewWebrtcAction(offer, WebrtcActionOffer, hijack)
				} else {
					log.Println("[proxy] ums-request error:", err)
				}
			} else if hijack == "janus" {
				//log.Println("janus-request: ", len(body))
				if jreq, err := ParseJanusRequest(body); err == nil {
					if jreq.Janus == kJanusMessage && jreq.Jsep != nil {
						//log.Println("[proxy] parse janus-request offer:", jreq.Jsep.Sdp)
						offer := []byte(jreq.Jsep.Sdp)
						adminChan <- NewWebrtcAction(offer, WebrtcActionOffer, hijack)
					} else if jreq.Janus == kJanusTrickle && jreq.Candidate != nil {
						log.Println("[proxy] janus-request candidate, sdpMid:", jreq.Candidate.SdpMid)
					} else {
						//log.Println("[proxy] janus-request others:", jreq.Janus)
					}
				} else {
					log.Println("[proxy] parse janus-request error:", err, string(body))
				}
			}
			//log.Println("http request len: ", len(body))
			req.Body = ioutil.NopCloser(bytes.NewReader(body))
		},
		FlushInterval: flush,
		Transport:     tr,
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode != http.StatusOK || resp.ContentLength <= 0 {
				return nil
			}

			hijack := resp.Request.Header.Get(kHttpHeaderWebrtcHijack)
			//hijack = "janus"
			if len(hijack) == 0 {
				for k, v := range cfg.Hijacks {
					if strings.HasPrefix(resp.Request.URL.Path, k) {
						hijack = v
						break
					}
				}
				if len(hijack) == 0 {
					log.Warnln("[proxy] no hijack for path=", resp.Request.URL.Path)
					return nil
				}
			}

			// TODO: process response body
			encoding := resp.Request.Header.Get("Content-Encoding")
			body, err := procHTTPBody(resp.Body, encoding)
			if body == nil || err != nil {
				log.Println("[proxy] invalid response body, err:", err)
				return nil
			}

			adminChan := Inst().ChanAdmin()
			if hijack == "ums" {
				if jresp, err := ParseUmsResponse(body); err == nil {
					answer := []byte(jresp.GetAnswer())
					//log.Println("ums-response answer: ", len(answer))
					adminChan <- NewWebrtcAction(answer, WebrtcActionAnswer, hijack)
				} else {
					log.Println("[proxy] ums-response error:", err)
				}
			} else if hijack == "janus" {
				//log.Println("parse janus response: ", len(body))
				if jresp, err := ParseJanusResponse(body); err == nil {
					if jresp.Janus == kJanusEvent && jresp.Jsep != nil {
						answer := ReplaceSdpCandidates([]byte(jresp.Jsep.Sdp), Inst().Candidates())
						adminChan <- NewWebrtcAction(answer, WebrtcActionAnswer, hijack)
						jresp.Jsep.Sdp = string(answer)
						body = EncodeJanusResponse(jresp)
						log.Println("[proxy] janus-response answer:", len(answer), string(body))
					} else {
						//log.Println("[proxy] janus-response:", jresp.Janus)
					}
				} else {
					log.Warnln("[proxy] janus-response error:", err, string(body))
				}
			}

			//log.Println("[proxy] http response body: ", len(body))
			resp.Body = ioutil.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			resp.Header.Del("Content-Encoding")
			return nil
		},
	}
}

var kDefaultRouteTarget = &RouteTarget{
	Service:       "default",
	TLSSkipVerify: true,
	URL: &url.URL{
		Scheme: "http",
		Host:   "127.0.0.1:8080",
		Path:   "/",
	},
}

type RouteTarget struct {
	// Service is the name of the service the targetURL points to
	Service string

	// StripPath will be removed from the front of the outgoing
	// request path
	StripPath string

	// TLSSkipVerify disables certificate validation for upstream
	// TLS connections.
	TLSSkipVerify bool

	// Host signifies what the proxy will set the Host header to.
	// The proxy does not modify the Host header by default.
	// When Host is set to 'dst' the proxy will use the host name
	// of the target host for the outgoing request.
	Host string

	// URL is the endpoint the service instance listens on
	URL *url.URL

	// RedirectCode is the HTTP status code used for redirects.
	// When set to a value > 0 the client is redirected to the target url.
	RedirectCode int

	// RedirectURL is the redirect target based on the request.
	// This is cached here to prevent multiple generations per request.
	RedirectURL *url.URL
}

type HTTPProxyHandler struct {
	Config HttpParams

	// Transport is the http connection pool configured with timeouts.
	// The proxy will panic if this value is nil.
	Transport http.RoundTripper

	// InsecureTransport is the http connection pool configured with
	// InsecureSkipVerify set. This is used for https proxies with
	// self-signed certs.
	InsecureTransport http.RoundTripper

	// Lookup returns a target host for the given request.
	// The proxy will panic if this value is nil.
	Lookup func(*http.Request) *RouteTarget

	// UUID returns a unique id in uuid format.
	// If UUID is nil, uuid.NewUUID() is used.
	UUID func() string
}

func NewHTTPProxyHandle(cfg HttpParams, lookup func(*http.Request) *RouteTarget) http.Handler {
	return &HTTPProxyHandler{
		Config:            cfg,
		Transport:         newHTTPTransport(nil, cfg),
		InsecureTransport: newHTTPTransport(&tls.Config{InsecureSkipVerify: true}, cfg),
		Lookup:            lookup,
	}
}

func (p *HTTPProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.Lookup == nil {
		panic("no lookup function")
		return
	}

	//log.Printf("[proxy] ServeHTTP, http/https req: %v, method:%v", r.URL.Path, r.Method)

	if p.Config.RequestID != "" {
		id := p.UUID
		if id == nil {
			id = uuid.NewUUID
		}
		r.Header.Set(p.Config.RequestID, id())
	}

	t := p.Lookup(r)

	if t == nil {
		log.Warnln("[proxy] ServeHTTP, no route for path=", r.URL.Path)
		status := p.Config.NoRouteStatus
		if status < 100 || status > 999 {
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
		html := p.Config.NoRouteHTML
		if html != "" {
			io.WriteString(w, html)
		}
		return
	}

	// build the request url since r.URL will get modified
	// by the reverse proxy and contains only the RequestURI anyway
	requestURL := &url.URL{
		Scheme:   scheme(r),
		Host:     r.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	_ = requestURL
	//log.Println("[proxy] requestURL:", requestURL)

	if t.RedirectCode != 0 && t.RedirectURL != nil {
		http.Redirect(w, r, t.RedirectURL.String(), t.RedirectCode)
		return
	}

	// build the real target url that is passed to the proxy
	targetURL := &url.URL{
		Scheme: t.URL.Scheme,
		Host:   t.URL.Host,
		Path:   r.URL.Path,
	}
	if t.URL.RawQuery == "" || r.URL.RawQuery == "" {
		targetURL.RawQuery = t.URL.RawQuery + r.URL.RawQuery
	} else {
		targetURL.RawQuery = t.URL.RawQuery + "&" + r.URL.RawQuery
	}
	//log.Println("[proxy] targetURL:", targetURL)

	if t.Host == "dst" {
		r.Host = targetURL.Host
	} else if t.Host != "" {
		r.Host = t.Host
	}

	// TODO(fs): The HasPrefix check seems redundant since the lookup function should
	// TODO(fs): have found the target based on the prefix but there may be other
	// TODO(fs): matchers which may have different rules. I'll keep this for
	// TODO(fs): a defensive approach.
	if t.StripPath != "" && strings.HasPrefix(r.URL.Path, t.StripPath) {
		targetURL.Path = targetURL.Path[len(t.StripPath):]
	}

	if err := addHeaders(r, p.Config, t.StripPath); err != nil {
		http.Error(w, "cannot parse "+r.RemoteAddr, http.StatusInternalServerError)
		return
	}

	if err := addResponseHeaders(w, r, p.Config); err != nil {
		http.Error(w, "cannot add response headers", http.StatusInternalServerError)
		return
	}

	upgrade, accept := r.Header.Get("Upgrade"), r.Header.Get("Accept")

	tr := p.Transport
	if t.TLSSkipVerify {
		tr = p.InsecureTransport
	}

	var h http.Handler
	switch {
	case upgrade == "websocket" || upgrade == "Websocket":
		r.URL = targetURL
		if targetURL.Scheme == "https" || targetURL.Scheme == "wss" {
			h = newWSHandler(targetURL.Host, func(network, address string) (net.Conn, error) {
				return tls.Dial(network, address, tr.(*http.Transport).TLSClientConfig)
			})
		} else {
			h = newWSHandler(targetURL.Host, net.Dial)
		}
	case accept == "text/event-stream":
		// use the flush interval for SSE (server-sent events)
		// must be > 0s to be effective
		h = newHTTPProxy(targetURL, tr, p.Config.FlushInterval, p.Config)
	default:
		h = newHTTPProxy(targetURL, tr, p.Config.GlobalFlushInterval, p.Config)
	}

	if p.Config.GZIPContentTypes != nil {
		h = gziph.NewGzipHandler(h, p.Config.GZIPContentTypes)
	}

	//log.Println("[proxy] http proxy begin")
	rw := &responseWriter{w: w}
	h.ServeHTTP(rw, r)
	//log.Println("[proxy] http proxy ret=", rw.code)
	if rw.code <= 0 {
		log.Warnln("[proxy] http proxy error=", rw.code)
		return
	}
}

// responseWriter wraps an http.ResponseWriter to capture the status code and
// the size of the response. It also implements http.Hijacker to forward
// hijacking the connection to the wrapped writer if supported.
type responseWriter struct {
	w    http.ResponseWriter
	code int
	size int
}

func (rw *responseWriter) Header() http.Header {
	return rw.w.Header()
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.w.Write(b)
	rw.size += n
	return n, err
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.w.WriteHeader(statusCode)
	rw.code = statusCode
}

var errNoHijacker = errors.New("not a hijacker")

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.w.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errNoHijacker
}
