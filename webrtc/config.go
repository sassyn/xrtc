package webrtc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	//"net/url"
	"regexp"
	"strings"
	"time"

	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/yaml"
)

type Config struct {
	UdpServers  map[string]*UDPConfig
	TcpServers  map[string]*TCPConfig
	HttpServers map[string]*HTTPConfig
}

func NewConfig() *Config {
	return &Config{
		UdpServers:  make(map[string]*UDPConfig),
		TcpServers:  make(map[string]*TCPConfig),
		HttpServers: make(map[string]*HTTPConfig),
	}
}

func YamlKeys(node yaml.Map) []string {
	var keys []string
	for k, _ := range node {
		keys = append(keys, k)
	}
	return keys
}

func IsYamlMap(node yaml.Node) (yaml.Map, error) {
	if m, ok := node.(yaml.Map); ok {
		return m, nil
	}
	return nil, errors.New("Not yaml.Map")
}

func IsYamlList(node yaml.Node) (yaml.List, error) {
	if l, ok := node.(yaml.List); ok {
		return l, nil
	}
	return nil, errors.New("Not yaml.List")
}

func IsYamlScalar(node yaml.Node) (yaml.Scalar, error) {
	if s, ok := node.(yaml.Scalar); ok {
		return s, nil
	}
	return "", errors.New("Not yaml.Scalar")
}

func IsYamlString(node yaml.Node) string {
	if s, err := IsYamlScalar(node); err != nil {
		return ""
	} else {
		return strings.TrimSpace(s.String())
	}
}

func (c *Config) Load(fname string) bool {
	ycfg, err := yaml.ReadFile(fname)
	if err != nil {
		log.Fatal("[config] read failed, err=", err)
		return false
	}

	var services yaml.Map

	// check root and services
	if root, err := IsYamlMap(ycfg.Root); err != nil {
		log.Fatal("[config] check root, err=", err)
		return false
	} else {
		if services, err = IsYamlMap(root.Key("services")); err != nil {
			log.Fatal("[config] check services, err=", err)
			return false
		}
	}

	// check servers
	for _, key := range YamlKeys(services) {
		server, err := IsYamlMap(services.Key(key))
		if err != nil {
			log.Warn("[config] check server [", key, "], err=", err)
			continue
		}

		var proto yaml.Scalar
		if proto, err = IsYamlScalar(server.Key("proto")); err != nil {
			log.Warn("[config] check server proto, err=", err)
			continue
		}

		var netp yaml.Map
		if netp, err = IsYamlMap(server.Key("net")); err != nil {
			log.Warn("[config] check server net, err=", err)
			continue
		}

		log.Printf("[config] parse server [%s]: proto[%s]", key, proto)
		switch proto.String() {
		case "udp":
			udpsvr := NewUDPConfig(key)
			udpsvr.Net.Load(netp, "udp")
			c.UdpServers[key] = udpsvr
		case "tcp":
			tcpsvr := NewTCPConfig(key)
			tcpsvr.Net.Load(netp, "tcp")
			enableHttp := IsYamlString(server.Key("enable_http"))
			log.Println("[config] check tcp's enable_http=", enableHttp)
			tcpsvr.EnableHttp = (enableHttp == "true")
			if tcpsvr.EnableHttp {
				if httpp, err := IsYamlMap(server.Key("http")); err == nil {
					tcpsvr.Http.Load(httpp)
				}
			}
			c.TcpServers[key] = tcpsvr
		case "http":
			httpsvr := NewHTTPConfig(key)
			httpsvr.Net.Load(netp, "")
			if httpp, err := IsYamlMap(server.Key("http")); err == nil {
				httpsvr.Http.Load(httpp)
			}
			c.HttpServers[key] = httpsvr
		default:
			log.Warn("[config] unsupported proto=", proto)
		}
		fmt.Println()
	}

	return true
}

func loadCandidateIP(node yaml.List, err error) []string {
	var ips []string
	if err == nil {
		for _, ip := range node {
			ips = append(ips, IsYamlString(ip))
		}
	}
	return ips
}

/// Net basic params
type NetParams struct {
	Addr       string // "host:port"
	TlsCrtFile string
	TlsKeyFile string
	Candidates []string // candidate ip
}

func (n *NetParams) Load(node yaml.Map, proto string) {
	n.Addr = IsYamlString(node.Key("addr"))
	n.TlsCrtFile = IsYamlString(node.Key("tls_crt_file"))
	n.TlsKeyFile = IsYamlString(node.Key("tls_key_file"))

	for {
		var port string
		var err error
		if _, port, err = net.SplitHostPort(n.Addr); err != nil {
			log.Warnln("[config] wrong addr:", n.Addr, err)
			break
		}
		var ips yaml.List
		if ips, err = IsYamlList(node.Key("ips")); err != nil {
			break
		}
		for idx, ip := range ips {
			szip := IsYamlString(ip)
			if len(szip) == 0 {
				continue
			}
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

/// UDP config
func NewUDPConfig(name string) *UDPConfig {
	cfg := &UDPConfig{Name: name}
	return cfg
}

type UDPConfig struct {
	Name string
	Net  NetParams
}

/// TCP config
func NewTCPConfig(name string) *TCPConfig {
	cfg := &TCPConfig{Name: name}
	cfg.Http = kDefaultHttpParams
	cfg.Http.Hijacks = make(map[string]string)
	return cfg
}

type TCPConfig struct {
	Name       string
	Net        NetParams
	EnableHttp bool
	Http       HttpParams
}

/// HTTP config
func NewHTTPConfig(name string) *HTTPConfig {
	cfg := &HTTPConfig{Name: name}
	cfg.Http = kDefaultHttpParams
	cfg.Http.Hijacks = make(map[string]string)
	return cfg
}

type HTTPConfig struct {
	Name string
	Net  NetParams
	Http HttpParams
}

/// HTTP params
var kDefaultHttpParams = HttpParams{
	MaxConns:              100,
	IdleConnTimeout:       time.Second * 30,
	DialTimeout:           time.Second * 30,
	ResponseHeaderTimeout: time.Second * 30,
	KeepAliveTimeout:      time.Second * 120,
	GlobalFlushInterval:   time.Millisecond * 10,
	FlushInterval:         time.Millisecond * 10,
	RequestID:             "X-Request-Id",
	STSHeader:             STSHeader{},
}

type HttpParams struct {
	Routes  []StringPair
	Hijacks map[string]string

	NoRouteStatus int
	NoRouteHTML   string

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

func (h *HttpParams) Load(node yaml.Map) {
	if routes, err := IsYamlList(node.Key("routes")); err == nil {
		h.loadHttpRoutes(routes)
	}
	if hijacks, err := IsYamlList(node.Key("hijacks")); err == nil {
		h.loadHttpHijacks(hijacks)
	}
}
func (h *HttpParams) loadHttpRoutes(node yaml.List) {
	//log.Println("[config] load routes, ", node)
	for _, r := range node {
		if item, err := IsYamlMap(r); err == nil {
			for k, v := range item {
				log.Println("[config] route=", k, v)
				//log.Println(url.Parse(IsYamlString(v)))
				h.Routes = append(h.Routes, StringPair{k, IsYamlString(v)})
			}
		} else {
			log.Warnln("[config] invalid route:", r)
		}
	}
}

func (h *HttpParams) loadHttpHijacks(node yaml.List) {
	for _, r := range node {
		if item, err := IsYamlMap(r); err == nil {
			for k, v := range item {
				log.Println("[config] hijack=", k, v)
				h.Hijacks[k] = IsYamlString(v)
			}
		} else {
			log.Warnln("[config] invalid hijack:", r)
		}
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
