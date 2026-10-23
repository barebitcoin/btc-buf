// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package rpcclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"

	"github.com/barebitcoin/btc-buf/rpcclient/btcjson"
)

// Client represents a Bitcoin RPC client which allows easy access to the
// various RPC methods available on a Bitcoin RPC server.  Each of the wrapper
// functions handle the details of converting the passed and return types to and
// from the underlying JSON types which are required for the JSON-RPC
// invocations
//
// The client provides each RPC in both synchronous (blocking) and asynchronous
// forms.  The asynchronous forms are based on the concept of futures where they
// return an instance of a type that promises to deliver the result of the
// invocation.  The request is made before the future is returned, so they're
// only asynchronous in name.
//
// A client is safe for concurrent use, and requests are sent concurrently. It
// holds no resources that need releasing.
type Client struct {
	id uint64 // atomic, so must stay 64-bit aligned

	// config holds the connection configuration associated with this client.
	config *ConnConfig

	// chainParams holds the params for the chain that this client is using,
	// and is used for many wallet methods.
	chainParams *chaincfg.Params

	// httpClient is the underlying HTTP client used to make requests.
	httpClient *http.Client

	// backendVersion is the version of the backend the client is currently
	// connected to. This should be retrieved through GetVersion.
	backendVersionMu sync.Mutex
	backendVersion   BackendVersion

	// Credentials last read from config.CookiePath.
	cookieMu            sync.Mutex
	cookieLastCheckTime time.Time
	cookieLastModTime   time.Time
	cookieLastUser      string
	cookieLastPass      string
	cookieLastErr       error
}

// NextID returns the next id to be used when sending a JSON-RPC message.  This
// ID allows responses to be associated with particular requests per the
// JSON-RPC specification.  Typically the consumer of the client does not need
// to call this function, however, if a custom request is being created and used
// this function should be used to ensure the ID is unique amongst all requests
// being made.
func (c *Client) NextID() uint64 {
	return atomic.AddUint64(&c.id, 1)
}

func (c *Client) jsonID(ctx context.Context, numericID uint64) any {
	if c.config.RequestID != nil {
		if id := c.config.RequestID(ctx); id != "" {
			return id
		}
	}
	return numericID
}

// ErrUnauthorized is returned when Core rejects the credentials.
var ErrUnauthorized = errors.New("unauthorized")

// rawResponse is a partially-unmarshaled JSON-RPC response.  For this
// to be valid (according to JSON-RPC 1.0 spec), ID may not be nil.
type rawResponse struct {
	Result json.RawMessage   `json:"result"`
	Error  *btcjson.RPCError `json:"error"`
}

// Response is the raw bytes of a JSON-RPC result, or the error if the response
// error object was non-null.
type Response struct {
	result []byte
	err    error
}

// result checks whether the unmarshaled response contains a non-nil error,
// returning an unmarshaled btcjson.RPCError (or an unmarshalling error) if so.
// If the response is not an error, the raw bytes of the request are
// returned for further unmashaling into specific result types.
func (r rawResponse) result() (result []byte, err error) {
	if r.Error != nil {
		return nil, r.Error
	}
	return r.Result, nil
}

// post sends the marshalled JSON-RPC request to the server, and returns the
// raw result.
func (c *Client) post(ctx context.Context, marshalledJSON []byte) ([]byte, error) {
	protocol := "http"
	if !c.config.DisableTLS {
		protocol = "https"
	}

	url := protocol + "://" + c.config.Host

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(marshalledJSON))
	if err != nil {
		return nil, err
	}
	httpReq.Close = true
	httpReq.Header.Set("Content-Type", "application/json")
	for key, value := range c.config.ExtraHeaders {
		httpReq.Header.Set(key, value)
	}

	// Configure basic access authorization.
	user, pass, err := c.getAuth()
	if err != nil {
		return nil, err
	}
	httpReq.SetBasicAuth(user, pass)

	httpResponse, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	// Read the raw bytes and close the response.
	respBytes, err := io.ReadAll(httpResponse.Body)
	_ = httpResponse.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("error reading json reply: %v", err)
	}

	if httpResponse.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}

	// Try to unmarshal the response as a regular JSON-RPC response.
	var resp rawResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		// When the response itself isn't a valid JSON-RPC response
		// return an error which includes the HTTP status code and raw
		// response bytes.
		return nil, fmt.Errorf("status code: %d, response: %q",
			httpResponse.StatusCode, string(respBytes))
	}
	return resp.result()
}

// sendPost sends the marshalled JSON-RPC request to the server, and returns a
// future already holding the reply.
func (c *Client) sendPost(ctx context.Context, marshalledJSON []byte) chan *Response {
	result, err := c.post(ctx, marshalledJSON)
	responseChan := make(chan *Response, 1)
	responseChan <- &Response{result: result, err: err}
	return responseChan
}

// newFutureError returns a new future result channel that already has the
// passed error waitin on the channel with the reply set to nil.  This is useful
// to easily return errors from the various Async functions.
func newFutureError(err error) chan *Response {
	responseChan := make(chan *Response, 1)
	responseChan <- &Response{err: err}
	return responseChan
}

// Expose newFutureError for developer usage when creating custom commands.
func NewFutureError(err error) chan *Response {
	return newFutureError(err)
}

// ReceiveFuture receives from the passed futureResult channel to extract a
// reply or any errors.  The examined errors include an error in the
// futureResult and the error in the reply from the server.  This will block
// until the result is available on the passed channel.
func ReceiveFuture(f chan *Response) ([]byte, error) {
	// Wait for a response on the returned channel.
	r := <-f
	return r.result, r.err
}

// SendCmd sends the passed command to the associated server and returns a
// response channel holding the reply.
func (c *Client) SendCmd(ctx context.Context, cmd interface{}) chan *Response {
	// Get the method associated with the command.
	method, err := btcjson.CmdMethod(cmd)
	if err != nil {
		return newFutureError(err)
	}

	// Marshal the command.
	id := c.NextID()
	marshalledJSON, err := btcjson.MarshalCmd(btcjson.RpcVersion1, c.jsonID(ctx, id), cmd)
	if err != nil {
		return newFutureError(err)
	}

	// Not the request itself: it can hold private keys and passphrases.
	c.log(ctx).DebugContext(ctx, "sending request", "method", method, "id", id)

	return c.sendPost(ctx, marshalledJSON)
}

// sendCmdAndWait sends the passed command to the associated server, waits
// for the reply, and returns the result from it.  It will return the error
// field in the reply if there is one.
func (c *Client) sendCmdAndWait(ctx context.Context, cmd interface{}) (interface{}, error) {
	// Marshal the command to JSON-RPC, send it to the connected server, and
	// wait for a response on the returned channel.
	return ReceiveFuture(c.SendCmd(ctx, cmd))
}

// ConnConfig describes the connection configuration parameters for the client.
type ConnConfig struct {
	// Host is the IP address and port of the RPC server you want to connect
	// to.
	Host string

	// User is the username to use to authenticate to the RPC server.
	User string

	// Pass is the passphrase to use to authenticate to the RPC server.
	Pass string

	// CookiePath is the path to a cookie file containing the username and
	// passphrase to use to authenticate to the RPC server.  It is used
	// instead of User and Pass if non-empty.
	CookiePath string

	// Params is the string representing the network that the server
	// is running. If there is no parameter set in the config, then
	// mainnet will be used by default.
	Params string

	// DisableTLS specifies whether transport layer security should be
	// disabled.  It is recommended to always use TLS if the RPC server
	// supports it as otherwise your username and password is sent across
	// the wire in cleartext.
	DisableTLS bool

	// Certificates are the bytes for a PEM-encoded certificate chain used
	// for the TLS connection.  It has no effect if the DisableTLS parameter
	// is true.
	Certificates []byte

	// Proxy specifies to connect through a SOCKS 5 proxy server.  It may
	// be an empty string if a proxy is not required.
	Proxy string

	// ProxyUser is an optional username to use for the proxy server if it
	// requires authentication.  It has no effect if the Proxy parameter
	// is not set.
	ProxyUser string

	// ProxyPass is an optional password to use for the proxy server if it
	// requires authentication.  It has no effect if the Proxy parameter
	// is not set.
	ProxyPass string

	// ExtraHeaders specifies the extra headers when perform request. It's
	// useful when RPC provider need customized headers.
	ExtraHeaders map[string]string

	// EnableBCInfoHacks is an option provided to enable compatibility hacks
	// when connecting to blockchain.info RPC server
	EnableBCInfoHacks bool

	// RequestID, if set, derives the JSON-RPC request "id" sent to the
	// server from the request context.
	RequestID func(ctx context.Context) string

	// Logger, if set, returns the logger to use for a request context.
	// Defaults to slog.Default.
	Logger func(ctx context.Context) *slog.Logger
}

// log returns the logger to use for ctx.
func (c *Client) log(ctx context.Context) *slog.Logger {
	if c.config.Logger != nil {
		return c.config.Logger(ctx)
	}
	return slog.Default()
}

// getAuth returns the username and passphrase that will actually be used for
// this connection.  This will be the result of checking the cookie if a cookie
// path is configured; if not, it will be the user-configured username and
// passphrase.
func (c *Client) getAuth() (username, passphrase string, err error) {
	// Try username+passphrase auth first.
	if c.config.Pass != "" {
		return c.config.User, c.config.Pass, nil
	}

	// If no username or passphrase is set, try cookie auth.
	return c.retrieveCookie()
}

// retrieveCookie returns the cookie username and passphrase.
func (c *Client) retrieveCookie() (username, passphrase string, err error) {
	c.cookieMu.Lock()
	defer c.cookieMu.Unlock()

	if !c.cookieLastCheckTime.IsZero() && time.Now().Before(c.cookieLastCheckTime.Add(30*time.Second)) {
		return c.cookieLastUser, c.cookieLastPass, c.cookieLastErr
	}

	c.cookieLastCheckTime = time.Now()

	st, err := os.Stat(c.config.CookiePath)
	if err != nil {
		c.cookieLastErr = err
		return c.cookieLastUser, c.cookieLastPass, c.cookieLastErr
	}

	modTime := st.ModTime()
	if !modTime.Equal(c.cookieLastModTime) {
		c.cookieLastModTime = modTime
		c.cookieLastUser, c.cookieLastPass, c.cookieLastErr = readCookieFile(c.config.CookiePath)
	}

	return c.cookieLastUser, c.cookieLastPass, c.cookieLastErr
}

// newHTTPClient returns a new http client that is configured according to the
// proxy and TLS settings in the associated connection configuration.
func newHTTPClient(config *ConnConfig) (*http.Client, error) {
	// Set proxy function if there is a proxy configured.
	var proxyFunc func(*http.Request) (*url.URL, error)
	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return nil, err
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	// Configure TLS if needed.
	var tlsConfig *tls.Config
	if !config.DisableTLS {
		if len(config.Certificates) > 0 {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(config.Certificates)
			tlsConfig = &tls.Config{
				RootCAs: pool,
			}
		}
	}

	client := http.Client{
		Transport: &http.Transport{
			Proxy:           proxyFunc,
			TLSClientConfig: tlsConfig,
		},
	}

	return &client, nil
}

// New creates a new RPC client based on the provided connection configuration
// details.
func New(config *ConnConfig) (*Client, error) {
	httpClient, err := newHTTPClient(config)
	if err != nil {
		return nil, err
	}

	client := &Client{
		config:     config,
		httpClient: httpClient,
	}

	// Default network is mainnet, no parameters are necessary but if mainnet
	// is specified it will be the param
	switch config.Params {
	case "":
		fallthrough
	case chaincfg.MainNetParams.Name:
		client.chainParams = &chaincfg.MainNetParams
	case chaincfg.TestNet3Params.Name:
		client.chainParams = &chaincfg.TestNet3Params
	case chaincfg.RegressionNetParams.Name:
		client.chainParams = &chaincfg.RegressionNetParams
	case chaincfg.SigNetParams.Name:
		client.chainParams = &chaincfg.SigNetParams
	case chaincfg.SimNetParams.Name:
		client.chainParams = &chaincfg.SimNetParams
	default:
		return nil, fmt.Errorf("rpcclient.New: Unknown chain %s", config.Params)
	}

	return client, nil
}

// BackendVersion retrieves the version of the backend the client is currently
// connected to.
func (c *Client) BackendVersion(ctx context.Context) (BackendVersion, error) {
	c.backendVersionMu.Lock()
	defer c.backendVersionMu.Unlock()

	if c.backendVersion != nil {
		return c.backendVersion, nil
	}

	// We'll start by calling GetInfo. This method doesn't exist for
	// bitcoind nodes as of v0.16.0, so we'll assume the client is connected
	// to a btcd backend if it does exist.
	info, err := c.GetInfo(ctx)

	switch err := err.(type) {
	// Parse the btcd version and cache it.
	case nil:
		c.log(ctx).DebugContext(ctx, "detected btcd version", "version", info.Version)
		version := parseBtcdVersion(info.Version)
		c.backendVersion = version
		return c.backendVersion, nil

	// Inspect the RPC error to ensure the method was not found, otherwise
	// we actually ran into an error.
	case *btcjson.RPCError:
		if err.Code != btcjson.ErrRPCMethodNotFound.Code {
			return nil, fmt.Errorf("unable to detect btcd version: "+
				"%v", err)
		}

	default:
		return nil, fmt.Errorf("unable to detect btcd version: %v", err)
	}

	// Since the GetInfo method was not found, we assume the client is
	// connected to a bitcoind backend, which exposes its version through
	// GetNetworkInfo.
	networkInfo, err := c.GetNetworkInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to detect bitcoind version: %v",
			err)
	}

	// Parse the bitcoind version and cache it.
	c.log(ctx).DebugContext(ctx, "detected bitcoind version", "version", networkInfo.SubVersion)
	version := parseBitcoindVersion(networkInfo.SubVersion)
	c.backendVersion = &version

	return c.backendVersion, nil
}
