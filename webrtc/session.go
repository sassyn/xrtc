package webrtc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	//"fmt"
	"io"
	"net/http"

	"gopkg.in/session.v3"
	//"github.com/go-session/session"
)

var globalSession *session.Manager

// Then, initialize the session manager
func init() {
	globalSession = session.NewManager(
		session.SetCookieLifeTime(3600),        // seconds
		session.SetCookieName("gosessionid"),   // cookiename
		session.SetEnableSIDInHTTPHeader(true), // enable in header
		session.SetEnableSIDInURLQuery(false),  // enable default
		session.SetEnableSetCookie(true),       // enable default
	)
}

func routeId() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(b)
}

func sessionRoute(w http.ResponseWriter, r *http.Request) (string, error) {
	store, err := globalSession.Start(context.Background(), w, r)
	if err != nil {
		return "", err
	}

	//fmt.Println("[session] sid=", store.SessionID())

	var rid string
	if data, ok := store.Get("rid"); ok {
		rid, _ = data.(string)
	}
	if len(rid) < 32 {
		rid = routeId()
		store.Set("rid", rid)
	}
	return rid, nil
}

func sessionDestroy(w http.ResponseWriter, r *http.Request) {
	globalSession.Destroy(context.Background(), w, r)
}
