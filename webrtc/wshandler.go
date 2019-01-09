package webrtc

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/PeterXu/xrtc/logging"
)

type dialFunc func(network, address string) (net.Conn, error)

// newWSHandler returns an HTTP handler which forwards data between
// an incoming and outgoing websocket connection. It checks whether
// the handshake was completed successfully before forwarding data
// between the client and server.
func newWSHandler(hijack string, host string, dial dialFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "not a hijacker", http.StatusInternalServerError)
			return
		}

		in, _, err := hj.Hijack()
		if err != nil {
			log.Warnf("[ws] Hijack error for %s. %s", r.URL, err)
			http.Error(w, "hijack error", http.StatusInternalServerError)
			return
		}
		defer in.Close()

		out, err := dial("tcp", host)
		if err != nil {
			log.Warnf("[ws] WS error for %s. %s", r.URL, err)
			http.Error(w, "error contacting backend server", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		err = r.Write(out)
		if err != nil {
			log.Warnf("[ws] Error copying request for %s. %s", r.URL, err)
			http.Error(w, "error copying request", http.StatusInternalServerError)
			return
		}

		// read the initial response to check whether we get an HTTP/1.1 101 ... response
		// to determine whether the handshake worked.
		b := make([]byte, 1024)
		if err := out.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			log.Warnf("[ws] Error setting read timeout for %s: %s", r.URL, err)
			http.Error(w, "error setting read timeout", http.StatusInternalServerError)
			return
		}

		n, err := out.Read(b)
		if err != nil {
			log.Warnf("[ws] Error reading handshake for %s: %s", r.URL, err)
			http.Error(w, "error reading handshake", http.StatusInternalServerError)
			return
		}

		b = b[:n]
		if m, err := in.Write(b); err != nil || n != m {
			log.Warnf("[ws] Error sending handshake for %s: %s", r.URL, err)
			http.Error(w, "error sending handshake", http.StatusInternalServerError)
			return
		}

		// https://tools.ietf.org/html/rfc6455#section-1.3
		// The websocket server must respond with HTTP/1.1 101 on successful handshake
		if !bytes.HasPrefix(b, []byte("HTTP/1.1 101")) {
			firstLine := strings.SplitN(string(b), "\n", 1)
			log.Warnf("[ws] Websocket upgrade failed for %s: %s", r.URL, firstLine)
			http.Error(w, "websocket upgrade failed", http.StatusInternalServerError)
			return
		}

		out.SetReadDeadline(time.Time{})

		errc := make(chan error, 2)
		cp := func(hijack string, dst io.Writer, src io.Reader, req bool) {
			rw := bufio.NewReadWriter(bufio.NewReader(src), bufio.NewWriter(dst))
			conn := newHybiServerConn(rw)
			frame := make([]byte, 64*1024)
			for {
				if n, err := conn.ReadFrame(frame[0:]); err != nil {
					log.Warnf("[ws] req=%v, read error=", req, err)
					break
				} else if n > 0 {
					body := frame[0:n]
					//log.Warnf("[ws] hijack=%s, req=%v, read body=%s", hijack, req, len(body))
					if req {
						if newdata := procWebrtcRequest(hijack, body); newdata != nil {
							body = newdata
						}
					} else {
						if newdata := procWebrtcResponse(hijack, host, body); newdata != nil {
							body = newdata
						}
					}
					//log.Warnf("[ws] hijack=%s, req=%v, read body=%s", hijack, req, string(body))
					if _, err := conn.Write(body); err != nil {
						log.Warnf("[ws] req=%v, write error=", req, err)
						break
					}
				}
			}
			errc <- err
		}

		go cp(hijack, out, in, true)
		go cp(hijack, in, out, false)
		err = <-errc
		if err != nil && err != io.EOF {
			log.Warnf("[ws] WS error for %s. %s", r.URL, err)
		}
	})
}
