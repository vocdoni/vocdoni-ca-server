package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"flag"

	"github.com/vocdoni/multirpc/transports/mhttp"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

func main() {
	domain := flag.String("domain", "", "domain name for tls")
	loglevel := flag.String("loglevel", "info", "log level")
	port := flag.Int("port", 443, "port to listen")
	flag.Parse()
	log.Init(*loglevel, "stdout")
	var ah authHandler
	var err error
	ah.kv, err = db.NewBadgerDB("./db")
	if err != nil {
		log.Fatal(err)
	}
	pxy, err := proxy("0.0.0.0", int32(*port), *domain, "./tls")
	if err != nil {
		log.Fatal(err)
	}
	pxy.AddHandler("/", ah.AuthHandler)
	select {}
}

type authHandler struct {
	kv *db.BadgerDB
}

func (ah *authHandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof(r.UserAgent())
	w.Header().Set("Content-Type", "text/html")
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		content, err := json.MarshalIndent(r.TLS.PeerCertificates[0], "", " ")
		if err != nil {
			io.WriteString(w, err.Error())
			return
		}
		ic := new(idCat)
		if err := json.Unmarshal(content, ic); err != nil {
			log.Debugf("%s", content)
			log.Errorf("json unmarshal error: %v", err)
			return
		}
		ichash := ic.Hash()
		exist, err := ah.kv.Has(ichash)
		if err != nil {
			log.Errorf("cannot feth db: %v", err)
			return
		}
		if exist {
			log.Infof("user already registered (hash id: %x", ichash)
			w.Write([]byte("error: already registered"))
			return
		}

		if _, err := w.Write([]byte(fmt.Sprintf("Registration successful for %s, your token %x", ic.Subject.CommonName, ichash))); err != nil {
			log.Errorf("error writing: %v", err)
			return
		}
		if err := ah.kv.Put(ichash, []byte{}); err != nil {
			log.Errorf("error storing hash: %v", err)
			return
		}

		content, err = json.Marshal(ic)
		if err != nil {
			log.Errorf("json marshal error: %v", err)
			return
		}
		fmt.Printf("%s\n", content)
	} else {
		log.Warnf("no certificate found")
		w.Write([]byte("error: no certificates found"))
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
	NotBefore string
	NotAfter  string
}

func (ic *idCat) Hash() []byte {
	b := bytes.Buffer{}
	b.WriteString(ic.Subject.CommonName)
	b.WriteString(ic.Subject.SerialNumber)
	return ethereum.HashRaw(b.Bytes())
}

func proxy(host string, port int32, tlsDomain, tlsDir string) (*mhttp.Proxy, error) {
	caCert, err := ioutil.ReadFile("ec_ciutadania.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("unable to load EC-Ciutadania CA")
	}
	tlsConfig := &tls.Config{ClientCAs: caCertPool, ClientAuth: tls.RequestClientCert}
	tlsConfig.BuildNameToCertificate()

	pxy := mhttp.NewProxy()
	pxy.Conn.TLSdomain = tlsDomain
	pxy.Conn.TLScertDir = tlsDir
	pxy.Conn.Address = host
	pxy.Conn.Port = port
	pxy.TLSConfig = tlsConfig
	log.Infof("creating proxy service, listening on %s:%d", host, port)
	if pxy.Conn.TLSdomain != "" {
		log.Infof("configuring proxy with TLS domain %s", tlsDomain)
	}
	return pxy, pxy.Init()
}
