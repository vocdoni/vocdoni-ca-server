package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"flag"

	"github.com/vocdoni/multirpc/transports/mhttp"
	"go.vocdoni.io/dvote/log"
)

func main() {
	domain := flag.String("domain", "", "domain name for tls")
	loglevel := flag.String("loglevel", "info", "log level")
	port := flag.Int("port", 443, "port to listen")
	flag.Parse()
	log.Init(*loglevel, "stdout")
	pxy, err := proxy("0.0.0.0", int32(*port), *domain, "./tls")
	if err != nil {
		log.Fatal(err)
	}
	pxy.AddHandler("/", AuthHandler)
	select {}
}

func AuthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		content, err := json.MarshalIndent(r.TLS.PeerCertificates[0], "", " ")
		if err != nil {
			io.WriteString(w, err.Error())
			return
		}
		ic := new(idCat)
		json.Unmarshal(content, ic)
		content, err = json.Marshal(ic)
		if err != nil {
			log.Errorf("json error: %v", err)
		}
		fmt.Printf("%s\n", content)
		w.Write(content)
	} else {
		w.Write([]byte("{\"error\":\"no certificates found\"}"))
	}
}

type idCat struct {
	Issuer struct {
		Country            []string
		Organization       string
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
		Organization       string
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
