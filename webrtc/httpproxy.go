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
	"path"
	"strconv"
	"strings"
	"time"

	gziph "github.com/PeterXu/xrtc/gzip"
	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/proto"
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
		//log.Warnln("[proxy] http invalid body, err=", err)
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

func procWebrtcRequest(hijack string, body []byte) []byte {
	adminChan := Inst().ChanAdmin()

	req := &proto.ProtoRequest{hijack, body}
	if ret, err := proto.Inst().ParseRequest(req); err == nil {
		if ret != nil {
			adminChan <- NewWebrtcAction(ret.Sdp, WebrtcActionOffer, hijack)
			return ret.Data
		}
	} else {
		log.Warnln("[proxy] resquest error:", hijack, err, string(body))
	}
	return nil
}

func procWebrtcResponse(hijack, host string, body []byte) []byte {
	adminChan := Inst().ChanAdmin()

	resp := &proto.ProtoResponse{hijack, body, Inst().Candidates()}
	if ret, err := proto.Inst().ParseResponse(resp); err == nil {
		if ret != nil {
			adminChan <- NewWebrtcAction(ret.Sdp, WebrtcActionAnswer, host)
			return ret.Data
		}
	} else {
		log.Warnln("[proxy] response error:", hijack, err, string(body))
	}
	return nil
}

func newHTTPProxy(hijack string, target *url.URL, tr http.RoundTripper, flush time.Duration, cfg HttpParams) http.Handler {
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
			if len(hijack) == 0 {
				//log.Warnln("[proxy] no hijack for path=", req.URL.Path)
				return
			}

			req.Header.Add(kHttpHeaderWebrtcHijack, hijack)
			encoding := req.Header.Get("Content-Encoding")
			body, err := procHTTPBody(req.Body, encoding)
			if body == nil || err != nil {
				log.Println("[proxy] http invalid reqeust body, err=", err)
				return
			}

			if newdata := procWebrtcRequest(hijack, body); newdata != nil {
				body = newdata
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

			if len(hijack) == 0 {
				//log.Warnln("[proxy] no hijack for path=", resp.Request.URL.Path)
				return nil
			}

			// TODO: process response body
			encoding := resp.Request.Header.Get("Content-Encoding")
			body, err := procHTTPBody(resp.Body, encoding)
			if body == nil || err != nil {
				log.Warnln("[proxy] invalid response body, err:", err)
				return nil
			}

			if newdata := procWebrtcResponse(hijack, target.Host, body); newdata != nil {
				body = newdata
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

	// Hijack code
	Hijack string
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
	//log.Println("[proxy] route lookup=", t)

	if t == nil {
		log.Println("[proxy] ServeFile, no route and static for path=", r.URL.Path, p.Config.Root)
		fname := path.Join(p.Config.Root, r.URL.Path)
		rw := &responseWriter{w: w}
		http.ServeFile(rw, r, fname)
		log.Println("[proxy] ServeFile, err=", rw.code)
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
			h = newWSHandler(t.Hijack, targetURL.Host, func(network, address string) (net.Conn, error) {
				return tls.Dial(network, address, tr.(*http.Transport).TLSClientConfig)
			})
		} else {
			h = newWSHandler(t.Hijack, targetURL.Host, net.Dial)
		}
	case accept == "text/event-stream":
		// use the flush interval for SSE (server-sent events)
		// must be > 0s to be effective
		h = newHTTPProxy(t.Hijack, targetURL, tr, p.Config.FlushInterval, p.Config)
	default:
		h = newHTTPProxy(t.Hijack, targetURL, tr, p.Config.GlobalFlushInterval, p.Config)
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

func NewHTTPHandler(name string, cfg *HttpParams) http.Handler {
	// Pass HttpParams object not by pointer
	//  When http params changed, only applys to subsequent requests not old
	return NewHTTPProxyHandle(*cfg, func(r *http.Request) *RouteTarget {
		//log.Println("[proxy] route, req:", r.Header, r.URL, r.Host)
		var routePath string
		var routeUri string

		for {
			// check host@
			if host, _, err := net.SplitHostPort(r.Host); err == nil {
				host = "host@" + host
				//log.Println("[proxy] route check host=", host)
				if r, ok := cfg.HostRoutes[host]; ok {
					routePath = host
					routeUri = r
					break
				}
			}

			// check ws@
			if proto := r.Header.Get("Sec-Websocket-Protocol"); len(proto) > 0 {
				proto = "ws@" + proto
				//log.Println("[proxy] route check proto=", proto)
				if r, ok := cfg.ProtoRoutes[proto]; ok {
					routePath = proto
					routeUri = r
					break
				}
			}

			// check common path: prefix-only
			for _, item := range cfg.Routes {
				//log.Println("[proxy] route check path,", item, r.URL.Path)
				if strings.HasPrefix(r.URL.Path, item.First) {
					routePath = r.URL.Path
					routeUri = item.Second
					break
				}
			}
			break
		}

		if len(routeUri) <= 1 {
			return nil
		}

		// check routeUri is valid
		uri, err := url.Parse(routeUri)
		if err != nil {
			log.Warnln("[proxy] route invalid uri=", routeUri)
			return nil
		}

		// check hijack
		var hijack string
		for key, val := range cfg.Hijacks {
			if strings.HasPrefix(routePath, key) {
				hijack = val
				break
			}
		}

		return &RouteTarget{
			Service:       name,
			Hijack:        hijack,
			TLSSkipVerify: true,
			URL:           uri,
		}
	})
}
