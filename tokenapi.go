package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"time"

	"github.com/google/uuid"
	"gitlab.com/vocdoni/manager/manager-backend/types"
	"go.vocdoni.io/dvote/crypto"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/log"
	"nhooyr.io/websocket"
)

// APIConnection holds an API websocket connection
type APIConnection struct {
	WS      *websocket.Conn
	HTTP    *http.Client
	Address string
}

// NewHTTPapiConnection starts a connection with the given endpoint address. The
// connection is closed automatically when the test or benchmark finishes.
func NewHTTPapiConnection(addr string) (*APIConnection, error) {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    10 * time.Second,
		DisableCompression: false,
	}
	r := &APIConnection{Address: addr, HTTP: &http.Client{Transport: tr, Timeout: time.Second * 2}}
	return r, nil
}

// Request makes a request to the previously connected endpoint
func (r *APIConnection) Request(req types.MetaRequest, signer *ethereum.SignKeys) (*types.MetaResponse, error) {
	method := req.Method

	req.Timestamp = int32(time.Now().Unix())
	reqInner, err := crypto.SortedMarshalJSON(req)
	if err != nil {
		return nil, err
	}
	var signature []byte
	if signer != nil {
		signature, err = signer.Sign(reqInner)
		if err != nil {
			return nil, err
		}
	}

	reqOuter := types.RequestMessage{
		ID:          fmt.Sprintf("%d", rand.Intn(1000)),
		Signature:   fmt.Sprintf("%x", signature),
		MetaRequest: reqInner,
	}
	reqBody, err := json.Marshal(reqOuter)
	if err != nil {
		return nil, err
	}

	log.Debugf("request: %s", reqBody)
	var message []byte
	if r.WS != nil {
		if err := r.WS.Write(context.TODO(), websocket.MessageText, reqBody); err != nil {
			return nil, err
		}
		_, message, err = r.WS.Read(context.TODO())
		if err != nil {
			return nil, err
		}
	}
	if r.HTTP != nil {
		resp, err := r.HTTP.Post(r.Address, "application/json", bytes.NewBuffer(reqBody))
		if err != nil {
			return nil, err
		}
		message, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
	}
	log.Debugf("response: %s", message)
	var respOuter types.ResponseMessage
	if err := json.Unmarshal(message, &respOuter); err != nil {
		return nil, err
	}
	if respOuter.ID != reqOuter.ID {
		return nil, fmt.Errorf("%s: %v", method, "request ID doesn'tb match")
	}
	if respOuter.Signature == "" {
		return nil, fmt.Errorf("%s: empty signature in response: %s", method, message)
	}
	var respInner types.MetaResponse
	if err := json.Unmarshal(respOuter.MetaResponse, &respInner); err != nil {
		return nil, fmt.Errorf("%s: %v", method, err)
	}
	return &respInner, nil
}

// http://127.0.0.1:%d/api/token
func Generate(url, eid, secret string, amount int) ([]uuid.UUID, error) {
	// connect to endpoint
	wsc, err := NewHTTPapiConnection(url)
	// check connected successfully
	if err != nil {
		return nil, fmt.Errorf("unable to connect with endpoint :%s", err)
	}
	// create and make request
	var req types.MetaRequest
	req.EntityID = eid
	req.Amount = amount
	req.Method = "generate"
	req.Timestamp = int32(time.Now().Unix())
	auth := calculateAuth(fmt.Sprintf("%d", req.Amount), req.EntityID, req.Method, fmt.Sprintf("%d", req.Timestamp), secret)
	req.AuthHash = auth
	resp, err := wsc.Request(req, nil)
	if err != nil {
		return nil, err
	}
	if !resp.Ok {
		return nil, fmt.Errorf("request failed: %s", resp.Message)
	}
	if len(resp.Tokens) != amount {
		return nil, fmt.Errorf("expected %d tokens, got %d", amount, len(resp.Tokens))
	}
	return resp.Tokens, nil
}

func calculateAuth(fields ...interface{}) string {
	if len(fields) == 0 {
		return ""
	}
	var toHash bytes.Buffer
	for _, f := range fields {
		switch v := f.(type) {
		case string:
			toHash.WriteString(v)
		case []string:
			for _, key := range v {
				toHash.WriteString(key)
			}
		}
	}
	return hex.EncodeToString(ethereum.HashRaw(toHash.Bytes()))
}
