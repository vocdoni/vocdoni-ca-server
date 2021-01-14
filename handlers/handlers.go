package handlers

import (
	"github.com/vocdoni/vocdoni-ca-server/cahandler"
	"github.com/vocdoni/vocdoni-ca-server/cahandler/idcat"
	"github.com/vocdoni/vocdoni-ca-server/cahandler/ipaddr"
)

var Handlers = map[string]cahandler.CAcallbackFunc{
	"ip":    ipaddr.IPaddrAuthHandler,
	"idcat": idcat.IDcatAuthHandler,
}
