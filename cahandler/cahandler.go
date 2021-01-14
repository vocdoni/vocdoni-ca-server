package cahandler

import (
	"bytes"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/vocdoni/multirpc/transports/mhttp"
	"github.com/vocdoni/vocdoni-ca-server/tokenapi"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/log"
)

const (
	kvUserKey   = "u_"
	kvTokenKey  = "t_"
	kvSeparator = "_"
)

type GetTokenFunc = func(orgID string, userID string) (token []byte, new bool, err error)
type CAcallbackFunc = func(w http.ResponseWriter, r *http.Request, getToken GetTokenFunc)

type CAhandler struct {
	TokenCount         int64
	kv                 *db.BadgerDB
	Callback           CAcallbackFunc
	ManagerAPIendpoint string
}

/*
 Key Value structure:
  u_<orgId><user1Hash> = <user1Token>
  t_<orgId>_<freeToken1> = nil
  t_<orgId>_<freeToken2> = nil
  ...
*/

func (ah *CAhandler) Init(entityID, apisecret, apiendpoint string, kv *db.BadgerDB, pxy *mhttp.Proxy, handler CAcallbackFunc) {
	// Start key value store
	ah.kv = kv
	ah.Callback = handler
	ah.ManagerAPIendpoint = apiendpoint
	// Always have at least 100 tokens available (testing)
	ah.CountFreeTokens(entityID)
	go ah.TokenCollector(entityID, apisecret, 10)
	pxy.AddHandler("/auth/"+entityID, ah.AuthHandler)
}

// TokenCollector constantly collects tokens when the available number of stored tokens is below min.
// Blocking function, use a goroutine.
func (ah *CAhandler) TokenCollector(entityID, secret string, min int64) {
	i := 0
	for {
		if v := atomic.LoadInt64(&ah.TokenCount); v < min {
			log.Infof("fetching new batch of %d tokens", min)
			if err := ah.generateTokens(entityID, secret, int(min)); err != nil {
				log.Warnf("error fetching tokens: %v", err)
			}
		} else {
			if i > 10 {
				log.Debugf("available tokens for %s: %d", entityID, v)
				i = 0
			}
		}
		i++
		time.Sleep(5 * time.Second)
	}
}

func (ah *CAhandler) generateTokens(entityID, secret string, n int) error {
	tokens, err := tokenapi.Generate(ah.ManagerAPIendpoint, entityID, secret, int(n))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, token := range tokens {
		buf.Reset()
		buf.WriteString(kvTokenKey)
		buf.WriteString(entityID)
		buf.WriteString(kvSeparator)
		buf.WriteString(token.String())
		if err = ah.kv.Put(buf.Bytes(), nil); err != nil {
			return err
		}
	}
	atomic.AddInt64(&ah.TokenCount, int64(n))
	return nil
}

func (ah *CAhandler) getFreeToken(orgID string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(kvTokenKey)
	buf.WriteString(orgID)
	buf.WriteString(kvSeparator)

	iter := ah.kv.NewIterator().(*db.BadgerIterator)
	token := []byte{}
	key := []byte{}
	for iter.Iter.Seek(buf.Bytes()); iter.Iter.ValidForPrefix(buf.Bytes()); iter.Iter.Next() {
		key = iter.Key()
		token = key[len(buf.Bytes()):]
		break
	}
	iter.Release()
	if len(token) == 0 {
		return nil, fmt.Errorf("no tokens available")
	}
	return token, nil
}

func (ah *CAhandler) GetToken(orgID, userID string) ([]byte, bool, error) {
	var dbkey bytes.Buffer
	dbkey.Write([]byte(kvUserKey))
	dbkey.Write([]byte(orgID))
	dbkey.Write([]byte(userID))
	token, err := ah.kv.Get(dbkey.Bytes())
	if err != nil && err.Error() != "Key not found" {
		return nil, false, fmt.Errorf("cannot fetch db: %v", err)
	}
	// if token exist for user, just return it
	if len(token) > 0 {
		return token, false, nil
	}
	// if not, get a new one
	token, err = ah.getFreeToken(orgID)
	if err != nil {
		return nil, false, fmt.Errorf("no tokens available for %s: %v", orgID, err)
	}
	// and save it for the userID
	if err := ah.kv.Put(dbkey.Bytes(), token); err != nil {
		return nil, false, fmt.Errorf("error storing hash: %v", err)
	}
	// finally delete the free token
	if err := ah.delToken(orgID, token); err != nil {
		return nil, false, fmt.Errorf("cannot delete token: %v", err)
	}
	return token, true, nil
}

func (ah *CAhandler) delToken(orgID string, token []byte) error {
	var buf bytes.Buffer
	buf.WriteString(kvTokenKey)
	buf.WriteString(orgID)
	buf.WriteString(kvSeparator)
	buf.Write(token)
	atomic.AddInt64(&ah.TokenCount, -1)
	return ah.kv.Del(buf.Bytes())
}

func (ah *CAhandler) freeTokens(orgID string) int64 {
	return atomic.LoadInt64(&ah.TokenCount)
}

func (ah *CAhandler) CountFreeTokens(orgID string) int64 {
	var buf bytes.Buffer
	buf.WriteString(kvTokenKey)
	buf.WriteString(orgID)
	buf.WriteString(kvSeparator)
	iter := ah.kv.NewIterator().(*db.BadgerIterator)
	count := int64(0)
	for iter.Iter.Seek(buf.Bytes()); iter.Iter.ValidForPrefix(buf.Bytes()); iter.Iter.Next() {
		count++
	}
	iter.Release()
	atomic.StoreInt64(&ah.TokenCount, int64(count))
	return count
}

func (ah *CAhandler) AuthHandler(w http.ResponseWriter, r *http.Request) {
	ah.Callback(w, r, ah.GetToken)
}
