package idcat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/vocdoni/vocdoni-ca-server/cahandler"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/log"
)

func IDcatAuthHandler(w http.ResponseWriter, r *http.Request, getToken cahandler.GetTokenFunc) {
	w.Header().Set("Content-Type", "text/html")
	log.Infof(r.UserAgent())
	orgID := strings.TrimPrefix(r.URL.EscapedPath(), "/auth/")
	if len(orgID) == 0 {
		w.Write([]byte("<p>error: no organization provided</p>"))
		return
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// Get client certificate content
		content, err := json.MarshalIndent(r.TLS.PeerCertificates[0], "", " ")
		if err != nil {
			log.Warnf("cannot marshal TLS identity: %v", err)
			w.Write([]byte(err.Error()))
			return
		}
		// Unmarshal certificate content
		ic := new(idCat)
		if err := json.Unmarshal(content, ic); err != nil {
			log.Debugf("%s", content)
			log.Errorf("json unmarshal error: %v", err)
			w.Write([]byte("<p>error: cannot parse json certificate data</p>"))
			return
		}
		// Check certificate time
		if time.Now().Unix() > ic.NotAfter.Unix() || time.Now().Unix() < ic.NotBefore.Unix() {
			log.Warnf("certificate issued for wrong date")
			w.Write([]byte("<p>error: wrong certificate validity date</p>"))
			return
		}
		// Compute unique hash and check if already exist
		ichash := ic.Hash()
		token, isNew, err := getToken(orgID, string(ichash))

		if err != nil {
			log.Warnf("cannot get token %v", err)
			w.Write([]byte("<p>internal error</p>"))
			return
		}
		if !isNew {
			log.Infof("user already registered on entity %s (hash id: %x", orgID, ichash)
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
				ic.Subject.CommonName, orgID, token))); err != nil {
			log.Errorf("error writing: %v", err)
			return
		}
		w.Write([]byte(fmt.Sprintf("\n<div><img src=\"data:image/png;base64, %s\" /></div>", base64.StdEncoding.EncodeToString(pngQR))))
		// For console log pretty printing
		content, err = json.Marshal(ic)
		if err != nil {
			log.Errorf("json marshal error: %v", err)
			return
		}
		fmt.Printf("%s\n", content)
	} else {
		log.Warnf("no certificate found")
		w.Write([]byte("<p>error: no certificates found</p>"))
	}
}

type idCat struct {
	Issuer struct {
		Country            []string
		Organization       []string
		OrganizationalUnit []string
		Locality           string
		Province           string
		StreetAddress      string
		PostalCode         string
		SerialNumber       string
		CommonName         string
	}
	Subject struct {
		Country            []string
		Organization       []string
		OrganizationalUnit []string
		Locality           string
		Province           string
		StreetAddress      string
		PostalCode         string
		SerialNumber       string
		CommonName         string
	}
	NotBefore time.Time
	NotAfter  time.Time
}

func (ic *idCat) Hash() []byte {
	b := bytes.Buffer{}
	b.WriteString(ic.Subject.CommonName)
	b.WriteString(ic.Subject.SerialNumber)
	return ethereum.HashRaw(b.Bytes())
}
