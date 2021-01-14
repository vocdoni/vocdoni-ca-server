package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/vocdoni/multirpc/transports/mhttp"
	"github.com/vocdoni/vocdoni-ca-server/cahandler"
	"github.com/vocdoni/vocdoni-ca-server/handlers"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

const managerURL = "https://manager.vocdoni.net/api/token"

type handlersCfg struct {
	Entities []handlerCfg `json:"entities"`
}

type handlerCfg struct {
	EntityID string `json:"entityId"`
	Handler  string `json:"handler"`
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("cannot get user home directory")
	}

	datadir := flag.String("dataDir", home+"/.vocdoni-ca", "datadir for storing database files and config")
	domain := flag.String("domain", "", "domain name for tls")
	loglevel := flag.String("loglevel", "info", "log level")
	port := flag.Int("port", 443, "port to listen")
	secret := flag.String("secret", "", "vocdoni manager api secret")
	certificates := flag.StringArray("certs", []string{}, "list of PEM certificates to import to the HTTP server")
	managerAPI := flag.String("manager", managerURL, "vocdoni manager api endpoint")
	flag.Parse()

	log.Init(*loglevel, "stdout")

	var ca cahandler.CAhandler
	// Start key value store
	kv, err := db.NewBadgerDB(*datadir + "/db")
	if err != nil {
		log.Fatal(err)
	}
	// Create the HTTP proxy service with letsencrypt
	pxy, err := proxy("0.0.0.0", int32(*port), *domain, *datadir+"/tls", *certificates)
	if err != nil {
		log.Fatal(err)
	}

	// Load handler config
	var hs handlersCfg
	hconfigFile := *datadir + "/handlers.json"
	log.Infof("loading handlers configuration from %s", hconfigFile)
	if _, err := os.Stat(hconfigFile); os.IsNotExist(err) {
		log.Info("creating new handlers config file")
		hs.Entities = append(hs.Entities, handlerCfg{EntityID: "", Handler: ""})
		data, _ := json.Marshal(hs)
		ioutil.WriteFile(hconfigFile, data, 0644)
		log.Warnf("no handlers defined, please configure %s", hconfigFile)
		os.Exit(0)
	}
	jsonBytes, err := ioutil.ReadFile(hconfigFile)
	if err != nil {
		log.Fatalf("cannot read config file %v", err)
	}
	if err := json.Unmarshal(jsonBytes, &hs); err != nil {
		log.Fatalf("could not unmarshal json handlers config file: %v", err)
	}

	entities := 0
	for _, e := range hs.Entities {
		if len(e.Handler) == 0 {
			continue
		}
		if h, ok := handlers.Handlers[e.Handler]; ok {
			log.Infof("creating %s handler for entity %s", e.Handler, e.EntityID)
			ca.Init(e.EntityID, *secret, *managerAPI, kv, pxy, h)
			entities++
		} else {
			log.Fatalf("handler %s is unknown", e.Handler)
		}
	}
	if entities == 0 {
		log.Fatalf("no valid handlers found at %s", hconfigFile)
	}

	// Wait for SIGTERM
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Warnf("received SIGTERM, exiting at %s", time.Now().Format(time.RFC850))
	os.Exit(0)
}

func proxy(host string, port int32, tlsDomain, tlsDir string, certificates []string) (*mhttp.Proxy, error) {
	caCertPool := x509.NewCertPool()
	for _, c := range certificates {
		caCert, err := ioutil.ReadFile(c)
		if err != nil {
			log.Fatal(err)
		}
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			log.Fatal("unable to load %s CA certificate", c)
		}
		log.Infof("imported CA certificate %s", c)
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
