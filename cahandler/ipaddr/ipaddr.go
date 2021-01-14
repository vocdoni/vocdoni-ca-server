package ipaddr

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/skip2/go-qrcode"
	"github.com/vocdoni/vocdoni-ca-server/cahandler"
	"go.vocdoni.io/dvote/log"
)

func IPaddrAuthHandler(w http.ResponseWriter, r *http.Request, getToken cahandler.GetTokenFunc) {
	w.Header().Set("Content-Type", "text/html")
	log.Infof(r.UserAgent())
	orgID := strings.TrimPrefix(r.URL.EscapedPath(), "/auth/")
	if len(orgID) == 0 {
		w.Write([]byte("<p>error: no organization provided</p>"))
		return
	}
	var ipaddr string
	if ipPort := strings.Split(r.RemoteAddr, ":"); len(ipPort) != 2 {
		w.Write([]byte("<p>error: cannot fetch IP from request</p>"))
		log.Warnf("cannot get ip from request: %s", r.RemoteAddr)
		return
	} else {
		ipaddr = ipPort[0]
	}
	token, isNew, err := getToken(orgID, ipaddr)
	if err != nil {
		log.Warnf("cannot get token %v", err)
		w.Write([]byte("<p>internal error</p>"))
		return
	}
	if !isNew {
		log.Infof("ip %s already registered on entity %s", ipaddr, orgID)
		pngQR, err := qrcode.Encode(fmt.Sprintf("https://vocdoni.link/validation/%s/%s", orgID, token), qrcode.Medium, 256)
		if err != nil {
			log.Errorf("cannot generate qr: %v", err)
			return
		}
		w.Write([]byte(fmt.Sprintf("<p>already registered, your token is %s</p>", token)))
		w.Write([]byte(fmt.Sprintf("\n<div><img src=\"data:image/png;base64, %s\" /></div>", base64.StdEncoding.EncodeToString(pngQR))))
		return
	}
	// Register certificate and give it a new token
	pngQR, err := qrcode.Encode(fmt.Sprintf("https://vocdoni.link/validation/%s/%s", orgID, token), qrcode.Medium, 256)
	if err != nil {
		log.Errorf("error generating qr code: %v", err)
		return
	}
	if _, err := w.Write([]byte(
		fmt.Sprintf("<p><strong>Registration successful</strong> for %s.<br/>Your token for organization %s is %s</p>",
			ipaddr, orgID, token))); err != nil {
		log.Errorf("error writing: %v", err)
		return
	}
	w.Write([]byte(fmt.Sprintf("\n<div><img src=\"data:image/png;base64, %s\" /></div>", base64.StdEncoding.EncodeToString(pngQR))))
	log.Infof("new user registered with ip %s", ipaddr)
}
