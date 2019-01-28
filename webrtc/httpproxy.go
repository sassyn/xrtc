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
	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/proto"
	"github.com/PeterXu/xrtc/util"
	uuid "github.com/PeterXu/xrtc/uuid"
)

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

func procWebrtcRequest(route *RouteTarget, body []byte) []byte {
	req := &proto.ProtoRequest{route.Base.Tag, body}
	if ret, err := proto.Inst().ParseRequest(req); err == nil {
		if ret != nil {
			wa := &WebrtcAction{
				data:   ret.Sdp,
				action: WebrtcActionOffer,
			}
			Inst().ChanAdmin() <- NewWebrtcActionMessage(wa)
			return ret.Data
		}
	} else {
		log.Warnln("[proxy] resquest error:", route.Base.Tag, err, string(body))
	}
	return nil
}

func procWebrtcResponse(route *RouteTarget, host string, body []byte) []byte {
	resp := &proto.ProtoResponse{route.Base.Tag, body, Inst().Candidates()}
	if ret, err := proto.Inst().ParseResponse(resp); err == nil {
		if ret != nil {
			routeBase := route.Base
			routeBase.IceHost = host
			wa := &WebrtcAction{
				data:   ret.Sdp,
				action: WebrtcActionAnswer,
				route:  &routeBase,
			}
			Inst().ChanAdmin() <- NewWebrtcActionMessage(wa)
			return ret.Data
		}
	} else {
		log.Warnln("[proxy] response error:", route.Base.Tag, err, string(body))
	}
	return nil
}

func newHTTPProxy(route *RouteTarget, target *url.URL, tr http.RoundTripper, flush time.Duration, cfg HttpParams) http.Handler {
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

			if req.Method != http.MethodPost || req.ContentLength <= 10 {
				//log.Warnln("[proxy] req status:", req.Method, req.ContentLength, req.URL)
				return
			}

			// TODO: process request body
			if len(route.Base.Tag) == 0 {
				//log.Warnln("[proxy] no tag for path=", req.URL.Path)
				return
			}

			encoding := req.Header.Get("Content-Encoding")
			body, err := procHTTPBody(req.Body, encoding)
			if body == nil || err != nil {
				log.Warnln("[proxy] http invalid reqeust body, err=", err)
				return
			}

			if newdata := procWebrtcRequest(route, body); newdata != nil {
				body = newdata
			}

			//log.Println("http request len: ", len(body))
			req.Body = ioutil.NopCloser(bytes.NewReader(body))
		},
		FlushInterval: flush,
		Transport:     tr,
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode != http.StatusOK || resp.ContentLength <= 10 {
				log.Println("[proxy] resp status:", resp.StatusCode, resp.ContentLength)
				return nil
			}

			if len(route.Base.Tag) == 0 {
				//log.Warnln("[proxy] no tag for path=", resp.Request.URL.Path)
				return nil
			}

			// TODO: process response body
			encoding := resp.Request.Header.Get("Content-Encoding")
			body, err := procHTTPBody(resp.Body, encoding)
			if body == nil || err != nil {
				log.Warnln("[proxy] invalid response body, err:", err)
				return nil
			}

			if newdata := procWebrtcResponse(route, target.Host, body); newdata != nil {
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

	// Route base info
	Base   RouteBase
	TlsPem TlsPem
}

type HttpProxyHandler struct {
	Config HttpParams

	// Cache
	Cache *Cache

	// Transport is the http connection pool configured with timeouts.
	// The proxy will panic if this value is nil.
	Transport http.RoundTripper

	// InsecureTransport is the http connection pool configured with
	// InsecureSkipVerify set. This is used for https proxies with
	// self-signed certs.
	InsecureTransport http.RoundTripper

	// Lookup returns a target host for the given request.
	// The proxy will panic if this value is nil.
	Lookup func(w http.ResponseWriter, r *http.Request) *RouteTarget

	// UUID returns a unique id in uuid format.
	// If UUID is nil, uuid.NewUUID() is used.
	UUID func() string
}

func NewHttpProxyHandle(cfg HttpParams,
	lookup func(w http.ResponseWriter, r *http.Request) *RouteTarget) http.Handler {
	return &HttpProxyHandler{
		Config:            cfg,
		Transport:         newHTTPTransport(nil, cfg),
		InsecureTransport: newHTTPTransport(&tls.Config{InsecureSkipVerify: true}, cfg),
		Lookup:            lookup,
	}
}

func (p *HttpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	t := p.Lookup(w, r)
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
	upgrade = strings.ToLower(upgrade)

	tr := p.Transport
	if t.TLSSkipVerify {
		tr = p.InsecureTransport
	}

	var h http.Handler
	switch {
	case t.Base.Autonomy == true:
		h = newWebapi(upgrade, t)
	case upgrade == "websocket":
		r.URL = targetURL
		if targetURL.Scheme == "https" || targetURL.Scheme == "wss" {
			h = newWSHandler(t, targetURL.Host, func(network, address string) (net.Conn, error) {
				return tls.Dial(network, address, tr.(*http.Transport).TLSClientConfig)
			})
		} else {
			h = newWSHandler(t, targetURL.Host, net.Dial)
		}
	case accept == "text/event-stream":
		// use the flush interval for SSE (server-sent events)
		// must be > 0s to be effective
		h = newHTTPProxy(t, targetURL, tr, p.Config.FlushInterval, p.Config)
	default:
		h = newHTTPProxy(t, targetURL, tr, p.Config.GlobalFlushInterval, p.Config)
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

func NewHttpServeHandler(name string, cfg *HttpParams) http.Handler {
	// Pass HttpParams object not by pointer
	//  When http params changed, only applys to subsequent requests not old
	return NewHttpProxyHandle(*cfg, func(w http.ResponseWriter, r *http.Request) *RouteTarget {
		//log.Println("[proxy] route, req:", r.Header, r.URL, r.Host)

		var rtbase RouteBase
		var routeUri string

		hostname := strings.Split(r.Host, ":")[0]

		// check default host
		if cfg.Servername != kDefaultServerName {
			if cfg.Servername != hostname {
				log.Warnln("[proxy] not matching servername:", cfg.Servername, r.Host)
				return nil
			}
		}

		// request scheme
		sch := scheme(r)

		// Check session and cache, route by session rid
		rid, err := sessionRoute(w, r)
		if err == nil {
			rid = "rid_" + rid
			if item := cfg.Cache.Get(rid); item != nil {
				if rt, ok := item.data.(*util.StringPair); ok {
					//tag = rt.First
					routeUri = rt.Second
					log.Println("[proxy] get route by rid=", rid, routeUri, r.URL)
				}
			}
			//log.Println("[proxy] route by rid=", rid, routeUri, r.URL)
		} else {
			log.Warnln("[proxy] fail to create session:", r.URL, err)
		}

		if len(routeUri) == 0 {
			// check route from request
			var route *RouteTable
			for {
				// check matching host
				//log.Println("[proxy] route check host=", hostname)
				if rt, ok := cfg.HostRoutes[hostname]; ok {
					route = rt
					break
				}

				// check ws@
				if proto := r.Header.Get("Sec-Websocket-Protocol"); len(proto) > 0 {
					proto = "ws@" + proto
					//log.Println("[proxy] route check proto=", proto)
					if rt, ok := cfg.ProtoRoutes[proto]; ok {
						route = rt
						break
					}
				}

				// check common path: prefix-only
				for _, rt := range cfg.PathRoutes {
					//log.Println("[proxy] route check path:", r.URL.Path, rt.Paths)
					for _, item := range rt.Paths {
						if strings.HasPrefix(r.URL.Path, item.First) {
							route = rt
							break
						}
					}
					if route != nil {
						break
					}
				}

				break
			}

			if route == nil {
				return nil
			}

			//log.Println("[proxy] route check:", route)
			if route.UpStream == nil {
				// use a seperate host not upstream
				routeUri = route.UpStreamId
			} else {
				// choose a upstream random
				switch {
				case sch == "http" || sch == "https":
					for _, v := range route.UpStream.HttpServers {
						routeUri = v
						break
					}
				case sch == "ws" || sch == "wss":
					for _, v := range route.UpStream.WsServers {
						routeUri = v
						break
					}
				}
			}

			rtbase = route.Base
			if len(rid) > 0 {
				// store route by rid
				//cfg.Cache.Set(rid, NewCacheItemEx(&util.StringPair{tag, routeUri}, 600*1000))
			}

			// disable now
			if rtbase.Tag == "janus0" {
				paths := strings.Split(r.URL.Path, "/")
				//log.Println("[proxy] split path=", len(paths), paths, r.URL)
				if len(paths) >= 3 && paths[1] == "janus" {
					jid := "jid_" + paths[2]
					if item := cfg.Cache.Get(jid); item != nil {
						if rt, ok := item.data.(*util.StringPair); ok {
							//tag = rt.First
							routeUri = rt.Second
							//log.Println("[proxy] get route by jid=", jid, routeUri)
						}
					} else {
						// sotre route by jid
						log.Println("[proxy] store route by jid=", jid, routeUri)
						//cfg.Cache.Set(jid, NewCacheItemEx(&util.StringPair{tag, routeUri}, 600*1000))
					}
				}
			}
		}

		// check routeUri is valid
		uri, err := url.Parse(routeUri)
		if err != nil {
			log.Warnln("[proxy] route invalid uri=", routeUri)
			return nil
		}

		//log.Println("[proxy] route webrtc-tag=", tag, ", routeUri=", routeUri, ", reqUri=", r.URL)

		return &RouteTarget{
			Service:       name,
			Base:          rtbase,
			TlsPem:        cfg.TlsPem,
			TLSSkipVerify: true,
			URL:           uri,
		}
	})
}
