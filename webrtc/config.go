package webrtc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
	"github.com/PeterXu/xrtc/yaml"
)

// Config contains all services(udp/tcp/http)
type Config struct {
	UpStreams   map[string]*UPSConfig
	UdpServers  map[string]*UDPConfig
	TcpServers  map[string]*TCPConfig
	HttpServers map[string]*HTTPConfig
}

func NewConfig() *Config {
	return &Config{
		UpStreams:   make(map[string]*UPSConfig),
		UdpServers:  make(map[string]*UDPConfig),
		TcpServers:  make(map[string]*TCPConfig),
		HttpServers: make(map[string]*HTTPConfig),
	}
}

// Load loads all service from config file.
func (c *Config) Load(fname string) bool {
	ycfg, err := yaml.ReadFile(fname)
	if err != nil {
		log.Error("[config] read failed, err=", err)
		return false
	}

	var services yaml.Map

	// check root and services
	if root, err := yaml.ToMap(ycfg.Root); err != nil {
		log.Error("[config] check root, err=", err)
		return false
	} else {
		if services, err = yaml.ToMap(root.Key("services")); err != nil {
			log.Error("[config] check services, err=", err)
			return false
		}
	}

	// check services
	for _, key := range yaml.Keys(services) {
		service, err := yaml.ToMap(services.Key(key))
		if err != nil {
			log.Warn("[config] check service [", key, "], err=", err)
			continue
		}

		var proto yaml.Scalar
		if proto, err = yaml.ToScalar(service.Key("proto")); err != nil {
			log.Warn("[config] check service proto, err=", err)
			continue
		}

		log.Printf("[config] parse service [%s]: proto[%s]", key, proto)

		if proto.String() == "upstream" {
			var servers yaml.List
			if servers, err = yaml.ToList(service.Key("servers")); err != nil {
				log.Warn("[config] check upstream servers, err=", err)
				continue
			}

			ups := NewUPSConfig()
			ups.Load(servers)
			c.UpStreams[key] = ups
			fmt.Println()
			continue
		}

		var netp yaml.Map
		if netp, err = yaml.ToMap(service.Key("net")); err != nil {
			log.Warn("[config] check service net, err=", err)
			continue
		}

		switch proto.String() {
		case "udp":
			udpsvr := NewUDPConfig(key)
			udpsvr.Net.Load(netp, "udp")
			c.UdpServers[key] = udpsvr
		case "tcp":
			tcpsvr := NewTCPConfig(key)
			tcpsvr.Net.Load(netp, "tcp")
			enableHttp := yaml.ToString(service.Key("enable_http"))
			//log.Println("[config] check tcp's enable_http=", enableHttp)
			tcpsvr.EnableHttp = (enableHttp == "true")
			if tcpsvr.EnableHttp {
				if httpp, err := yaml.ToMap(service.Key("http")); err == nil {
					tcpsvr.Http.Load(httpp)
				}
			}
			c.TcpServers[key] = tcpsvr
		case "http":
			httpsvr := NewHTTPConfig(key)
			httpsvr.Net.Load(netp, "")
			if httpp, err := yaml.ToMap(service.Key("http")); err == nil {
				httpsvr.Http.Load(httpp)
			}
			c.HttpServers[key] = httpsvr
		default:
			log.Warn("[config] unsupported proto=", proto)
		}
		fmt.Println()
	}
	fmt.Println()

	// Init HTTP upstreams
	for _, svr := range c.HttpServers {
		svr.Http.InitUpstream(c.UpStreams)
	}
	fmt.Println()
	for _, svr := range c.TcpServers {
		svr.Http.InitUpstream(c.UpStreams)
	}
	fmt.Println()

	return true
}

// UPStream config
type UPSConfig struct {
	HttpServers []string
	WsServers   []string
}

func NewUPSConfig() *UPSConfig {
	return &UPSConfig{}
}

func (u *UPSConfig) Load(node yaml.List) {
	for _, s := range node {
		if _, err := yaml.ToScalar(s); err == nil {
			svr := yaml.ToString(s)
			if uri, err := url.Parse(svr); err == nil {
				switch {
				case uri.Scheme == "http" || uri.Scheme == "https":
					u.HttpServers = append(u.HttpServers, svr)
				case uri.Scheme == "ws" || uri.Scheme == "wss":
					u.WsServers = append(u.WsServers, svr)
				default:
					log.Warnln("[config] invalid upstream:", svr)
				}
			} else {
				log.Warnln("[config] invalid upstream uri:", svr, err)
			}
		} else {
			log.Warnln("[config] invalid upstream svr:", s, err)
		}
	}
	log.Println("[config] upstream servers:", u)
}

// Net basic params
type NetParams struct {
	Addr       string // "host:port"
	TlsCrtFile string
	TlsKeyFile string
	EnableIce  bool     // enable for ice
	Candidates []string // ice candidates, valid when EnableIce is true
}

// Load loads the "net:" parameters under one service.
func (n *NetParams) Load(node yaml.Map, proto string) {
	n.Addr = yaml.ToString(node.Key("addr"))
	n.TlsCrtFile = yaml.ToString(node.Key("tls_crt_file"))
	n.TlsKeyFile = yaml.ToString(node.Key("tls_key_file"))

	n.EnableIce = (yaml.ToString(node.Key("enable_ice")) == "true")
	for n.EnableIce {
		var port string
		var err error
		if _, port, err = net.SplitHostPort(n.Addr); err != nil {
			log.Warnln("[config] wrong addr:", n.Addr, err)
			break
		}
		var ips yaml.List
		if ips, err = yaml.ToList(node.Key("candidate_ips")); err != nil {
			break
		}
		for idx, ip := range ips {
			szip0 := yaml.ToString(ip)
			if len(szip0) == 0 {
				continue
			}
			szip := util.LookupIP(szip0)
			log.Println("[config] candidate_ip: ", szip0, szip)

			var candidate string
			if proto == "udp" {
				candidate = fmt.Sprintf("a=candidate:%d 1 udp 2013266431 %s %s typ host", (idx + 1), szip, port)
			} else if proto == "tcp" {
				candidate = fmt.Sprintf("a=candidate:%d 1 tcp 1010827775 %s %s typ host tcptype passive", (idx + 1), szip, port)
			} else {
				continue
			}
			n.Candidates = append(n.Candidates, candidate)
		}
		break
	}
	log.Println("[config] net:", n)
}

func NewUDPConfig(name string) *UDPConfig {
	cfg := &UDPConfig{Name: name}
	return cfg
}

// UDP config
type UDPConfig struct {
	Name string
	Net  NetParams
}

func NewTCPConfig(name string) *TCPConfig {
	cfg := &TCPConfig{Name: name}
	cfg.Http = kDefaultHttpParams
	cfg.Http.Routes = make(map[string]*RouteTable)
	cfg.Http.HostRoutes = make(map[string]*RouteTable)
	cfg.Http.ProtoRoutes = make(map[string]*RouteTable)
	cfg.Http.SessionRids = make(map[string]util.StringPair)
	return cfg
}

// TCP config
type TCPConfig struct {
	Name       string
	Net        NetParams
	EnableHttp bool
	Http       HttpParams
}

func NewHTTPConfig(name string) *HTTPConfig {
	cfg := &HTTPConfig{Name: name}
	cfg.Http = kDefaultHttpParams
	cfg.Http.Routes = make(map[string]*RouteTable)
	cfg.Http.HostRoutes = make(map[string]*RouteTable)
	cfg.Http.ProtoRoutes = make(map[string]*RouteTable)
	cfg.Http.SessionRids = make(map[string]util.StringPair)
	return cfg
}

// HTTP config
type HTTPConfig struct {
	Name string
	Net  NetParams
	Http HttpParams
}

// HTTP default params
var kDefaultHttpParams = HttpParams{
	MaxConns:              100,
	IdleConnTimeout:       time.Second * 30,
	DialTimeout:           time.Second * 10,
	ResponseHeaderTimeout: time.Second * 300,
	KeepAliveTimeout:      time.Second * 1200,
	GlobalFlushInterval:   time.Millisecond * 100,
	FlushInterval:         time.Millisecond * 100,
	RequestID:             "X-Request-Id",
	STSHeader:             STSHeader{},
}

type RouteTable struct {
	Tag        string // backend tag
	UpStreamId string // backend upstream
	IceTcp     bool   // tcp with high priority if true
	IceDirect  bool   // wether to enable iceDirect
	Paths      []util.StringPair
	UpStream   *UPSConfig
}

func NewRouteTable(tag string) *RouteTable {
	return &RouteTable{
		Tag: tag,
	}
}

const kDefaultServerName = "_"

// HttpParams for http configuration.
type HttpParams struct {
	Servername  string                 // server name
	Root        string                 // static root dir
	Routes      map[string]*RouteTable // all routes(upstream=>)
	HostRoutes  map[string]*RouteTable // host routes
	ProtoRoutes map[string]*RouteTable // proto routes
	PathRoutes  []*RouteTable          // path routes

	SessionRids map[string]util.StringPair // upstream by session rid
	Cache       *Cache                     // session cache

	MaxConns              int           // max idle conns
	IdleConnTimeout       time.Duration // the maximum amount of time an idle conn (keep-alive) connection
	DialTimeout           time.Duration // the maximum amount of time a dial completes, system has around 3min
	ResponseHeaderTimeout time.Duration // response waiting time
	KeepAliveTimeout      time.Duration // tcp keepalive(default disable)
	GlobalFlushInterval   time.Duration // reverse proxy:
	FlushInterval         time.Duration //		the flush interval to the client while copying the response body.

	LocalIP          string
	ClientIPHeader   string
	TLSHeader        string
	TLSHeaderValue   string
	GZIPContentTypes *regexp.Regexp
	RequestID        string
	STSHeader        STSHeader
}

type STSHeader struct {
	MaxAge     int
	Subdomains bool
	Preload    bool
}

// Load loads the http parameters(routes/..) under a service.
func (h *HttpParams) Load(node yaml.Map) {
	h.Servername = yaml.ToString(node.Key("servername"))
	if len(h.Servername) == 0 {
		h.Servername = "_"
	}

	h.Root = yaml.ToString(node.Key("root"))
	if len(h.Root) == 0 {
		h.Root = "/tmp"
	}

	h.MaxConns = yaml.ToInt(node.Key("max_conns"), h.MaxConns)
	h.IdleConnTimeout = yaml.ToDuration(node.Key("idle_conn_timeout"), h.IdleConnTimeout)
	h.DialTimeout = yaml.ToDuration(node.Key("dial_timeout"), h.DialTimeout)
	h.ResponseHeaderTimeout = yaml.ToDuration(node.Key("response_header_timeout"), h.ResponseHeaderTimeout)
	h.KeepAliveTimeout = yaml.ToDuration(node.Key("keepalive_timeout"), h.KeepAliveTimeout)
	h.FlushInterval = yaml.ToDuration(node.Key("flush_interval"), h.FlushInterval)
	h.GlobalFlushInterval = yaml.ToDuration(node.Key("global_flush_interval"), h.GlobalFlushInterval)

	if routes, err := yaml.ToMap(node.Key("routes")); err == nil {
		h.loadHttpRoutes(routes)
	}
	log.Println("[config] http parameters:", h)
}

func (h *HttpParams) loadHttpRoutes(node yaml.Map) {
	//log.Println("[config] load routes, ", node)
	for tag, v := range node {
		item, err := yaml.ToMap(v)
		if err != nil {
			log.Warnln("[config] http routes, invalid routes:", v)
			break
		}

		// Create route table
		table := NewRouteTable(tag)

		// Process host/proto/path routes
		for prop, v := range item {
			switch prop {
			case "upstream":
				if _, err := yaml.ToScalar(v); err == nil {
					table.UpStreamId = yaml.ToString(v)
				} else {
					log.Warn("[config] http routes, invalid upstream=", v)
				}
			case "icetcp":
				if _, err := yaml.ToScalar(v); err == nil {
					table.IceTcp = (yaml.ToString(v) == "true")
				} else {
					log.Warn("[config] http routes, invalid iceTcp=", v)
				}
			case "icedirect":
				if _, err := yaml.ToScalar(v); err == nil {
					table.IceDirect = (yaml.ToString(v) == "true")
				} else {
					log.Warn("[config] http routes, invalid iceDirect=", v)
				}
			case "hosts":
				if hosts, err := yaml.ToList(v); err == nil {
					for _, host := range hosts {
						h.HostRoutes[yaml.ToString(host)] = table
					}
				} else {
					log.Warn("[config] http routes, invalid hosts=", v)
				}
			case "protos":
				if protos, err := yaml.ToList(v); err == nil {
					for _, proto := range protos {
						h.ProtoRoutes[yaml.ToString(proto)] = table
					}
				} else {
					log.Warn("[config] http routes, invalid protos=", v)
				}
			case "paths":
				if paths, err := yaml.ToList(v); err == nil {
					for _, path := range paths {
						if _, err := yaml.ToScalar(path); err == nil {
							table.Paths = append(table.Paths, util.StringPair{yaml.ToString(path), ""})
						} else if pair, err := yaml.ToMap(path); err == nil {
							for k, v := range pair {
								table.Paths = append(table.Paths, util.StringPair{k, yaml.ToString(v)})
							}
						} else {
							log.Warn("[config] http routes, invalid path=", path)
						}
					}
					h.PathRoutes = append(h.PathRoutes, table)
				} else {
					log.Warn("[config] http routes, invalid paths=", v)
				}
			default:
				log.Warn("[config] http routes, unsupported prop=", prop)
			}
		}

		log.Println("[config] http routing:", table)
		h.Routes[tag] = table
	}
}

func (h *HttpParams) InitUpstream(upstreams map[string]*UPSConfig) {
	for _, table := range h.Routes {
		if uri, err := url.Parse(table.UpStreamId); err != nil {
			log.Error("[config] invalid upstreamId=", table.UpStreamId, err)
			break
		} else {
			if uri.Scheme != "http" && uri.Scheme != "https" {
				log.Error("[config] only support http(s):// in upstream")
				break
			}

			var host, port string
			hostPort := strings.Split(uri.Host, ":")
			if len(hostPort) > 2 {
				log.Error("[config] invalid host in upstreamId=", table.UpStreamId)
				break
			} else if len(hostPort) == 2 {
				host = hostPort[0]
				port = hostPort[1]
			} else {
				host = hostPort[0]
			}
			if stream, ok := upstreams[host]; ok {
				if len(port) > 0 {
					log.Error("[config] upstreamId should not contain port:", table.UpStreamId)
					break
				}
				table.UpStream = stream
			} else {
				// table.UpStreamId is a valid http host, not upstream
				table.UpStream = nil
			}
		}

		log.Println("[config] table upstream=", table)
	}
}

// addResponseHeaders adds/updates headers in the response
func addResponseHeaders(w http.ResponseWriter, r *http.Request, cfg HttpParams) error {
	if r.TLS != nil && cfg.STSHeader.MaxAge > 0 {
		sts := "max-age=" + i32toa(int32(cfg.STSHeader.MaxAge))
		if cfg.STSHeader.Subdomains {
			sts += "; includeSubdomains"
		}
		if cfg.STSHeader.Preload {
			sts += "; preload"
		}
		w.Header().Set("Strict-Transport-Security", sts)
	}

	return nil
}

// addHeaders adds/updates headers in request
//
// * add/update `Forwarded` header
// * add X-Forwarded-Proto header, if not present
// * add X-Real-Ip, if not present
// * ClientIPHeader != "": Set header with that name to <remote ip>
// * TLS connection: Set header with name from `cfg.TLSHeader` to `cfg.TLSHeaderValue`
//
func addHeaders(r *http.Request, cfg HttpParams, stripPath string) error {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return errors.New("cannot parse " + r.RemoteAddr)
	}

	// set configurable ClientIPHeader
	// X-Real-Ip is set later and X-Forwarded-For is set
	// by the Go HTTP reverse proxy.
	if cfg.ClientIPHeader != "" &&
		cfg.ClientIPHeader != "X-Forwarded-For" &&
		cfg.ClientIPHeader != "X-Real-Ip" {
		r.Header.Set(cfg.ClientIPHeader, remoteIP)
	}

	if r.Header.Get("X-Real-Ip") == "" {
		r.Header.Set("X-Real-Ip", remoteIP)
	}

	// set the X-Forwarded-For header for websocket
	// connections since they aren't handled by the
	// http proxy which sets it.
	ws := r.Header.Get("Upgrade") == "websocket"
	if ws {
		r.Header.Set("X-Forwarded-For", remoteIP)
	}

	// Issue #133: Setting the X-Forwarded-Proto header to
	// anything other than 'http' or 'https' breaks java
	// websocket clients which use java.net.URL for composing
	// the forwarded URL. Since X-Forwarded-Proto is not
	// specified the common practice is to set it to either
	// 'http' for 'ws' and 'https' for 'wss' connections.
	proto := scheme(r)
	if r.Header.Get("X-Forwarded-Proto") == "" {
		switch proto {
		case "ws":
			r.Header.Set("X-Forwarded-Proto", "http")
		case "wss":
			r.Header.Set("X-Forwarded-Proto", "https")
		default:
			r.Header.Set("X-Forwarded-Proto", proto)
		}
	}

	if r.Header.Get("X-Forwarded-Port") == "" {
		r.Header.Set("X-Forwarded-Port", localPort(r))
	}

	if r.Header.Get("X-Forwarded-Host") == "" && r.Host != "" {
		r.Header.Set("X-Forwarded-Host", r.Host)
	}

	if stripPath != "" {
		r.Header.Set("X-Forwarded-Prefix", stripPath)
	}

	fwd := r.Header.Get("Forwarded")
	if fwd == "" {
		fwd = "for=" + remoteIP + "; proto=" + proto
	}
	if cfg.LocalIP != "" {
		fwd += "; by=" + cfg.LocalIP
	}
	if r.Proto != "" {
		fwd += "; httpproto=" + strings.ToLower(r.Proto)
	}
	if r.TLS != nil && r.TLS.Version > 0 {
		v := tlsver[r.TLS.Version]
		if v == "" {
			v = uint16base16(r.TLS.Version)
		}
		fwd += "; tlsver=" + v
	}
	if r.TLS != nil && r.TLS.CipherSuite != 0 {
		fwd += "; tlscipher=" + uint16base16(r.TLS.CipherSuite)
	}
	r.Header.Set("Forwarded", fwd)

	if cfg.TLSHeader != "" {
		if r.TLS != nil {
			r.Header.Set(cfg.TLSHeader, cfg.TLSHeaderValue)
		} else {
			r.Header.Del(cfg.TLSHeader)
		}
	}

	return nil
}

var tlsver = map[uint16]string{
	tls.VersionSSL30: "ssl30",
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
}

var digit16 = []byte("0123456789abcdef")

// uint16base64 is a faster version of fmt.Sprintf("0x%04x", n)
//
// BenchmarkUint16Base16/fmt.Sprintf-8         	10000000	       154 ns/op	       8 B/op	       2 allocs/op
// BenchmarkUint16Base16/uint16base16-8        	50000000	        35.0 ns/op	       8 B/op	       1 allocs/op
func uint16base16(n uint16) string {
	b := []byte("0x0000")
	b[5] = digit16[n&0x000f]
	b[4] = digit16[n&0x00f0>>4]
	b[3] = digit16[n&0x0f00>>8]
	b[2] = digit16[n&0xf000>>12]
	return string(b)
}

// i32toa is a faster implentation of strconv.Itoa() without importing another library
// https://stackoverflow.com/a/39444005
func i32toa(n int32) string {
	buf := [11]byte{}
	pos := len(buf)
	i := int64(n)
	signed := i < 0
	if signed {
		i = -i
	}
	for {
		pos--
		buf[pos], i = '0'+byte(i%10), i/10
		if i == 0 {
			if signed {
				pos--
				buf[pos] = '-'
			}
			return string(buf[pos:])
		}
	}
}

// scheme derives the request scheme used on the initial
// request first from headers and then from the connection
// using the following heuristic:
//
// If either X-Forwarded-Proto or Forwarded is set then use
// its value to set the other header. If both headers are
// set do not modify the protocol. If none are set derive
// the protocol from the connection.
func scheme(r *http.Request) string {
	xfp := r.Header.Get("X-Forwarded-Proto")
	fwd := r.Header.Get("Forwarded")
	switch {
	case xfp != "" && fwd == "":
		return xfp

	case fwd != "" && xfp == "":
		p := strings.SplitAfterN(fwd, "proto=", 2)
		if len(p) == 1 {
			break
		}
		n := strings.IndexRune(p[1], ';')
		if n >= 0 {
			return p[1][:n]
		}
		return p[1]
	}

	ws := r.Header.Get("Upgrade") == "websocket"
	switch {
	case ws && r.TLS != nil:
		return "wss"
	case ws && r.TLS == nil:
		return "ws"
	case r.TLS != nil:
		return "https"
	default:
		return "http"
	}
}

func localPort(r *http.Request) string {
	if r == nil {
		return ""
	}
	n := strings.Index(r.Host, ":")
	if n > 0 && n < len(r.Host)-1 {
		return r.Host[n+1:]
	}
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

func newHTTPTransport(tlscfg *tls.Config, cfg HttpParams) *http.Transport {
	return &http.Transport{
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		MaxIdleConnsPerHost:   cfg.MaxConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		Dial: (&net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.KeepAliveTimeout,
		}).Dial,
		TLSClientConfig: tlscfg,
	}
}
