package sdk

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const (
	defaultDialTimeout         = 5 * time.Second
	defaultRequestTimeout      = 15 * time.Second
	defaultHandshakeTimeout    = 15 * time.Second
	defaultLeaseTTL            = 30 * time.Second
	defaultRenewBefore         = 30 * time.Second
	defaultReadyTarget         = 2
	defaultRetryWait           = 3 * time.Second
	defaultHTTPShutdownTimeout = 5 * time.Second
)

var errRelayIncompatible = errors.New("relay is incompatible")

func closeIdleHTTPClient(controlHTTPClient *http.Client) {
	if controlHTTPClient == nil {
		return
	}
	if transport, ok := controlHTTPClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

// resetTransport tears down the cached HTTP client and TLS config so the next
// API call creates fresh TCP connections. Call this after detecting a system
// sleep/wake cycle where pooled connections are almost certainly dead.
func (l *listener) resetTransport() {
	if l == nil {
		return
	}
	l.mu.Lock()
	controlHTTPClient := l.controlHTTPClient
	l.controlHTTPClient = nil
	l.controlTLSConfig = nil
	l.mu.Unlock()
	closeIdleHTTPClient(controlHTTPClient)
}

func (l *listener) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, error) {
	if err := l.ensureControlHTTPClient(ctx); err != nil {
		return types.RegisterResponse{}, err
	}
	l.mu.Lock()
	controlHTTPClient := l.controlHTTPClient
	relayURL := l.relayURL
	identity := l.identity.Copy()
	metadata := l.metadata.Copy()
	l.mu.Unlock()
	if controlHTTPClient == nil {
		return types.RegisterResponse{}, errors.New("relay http client is unavailable")
	}

	var challenge types.RegisterChallengeResponse
	challengeReq := types.RegisterChallengeRequest{
		Identity:   identity,
		Metadata:   metadata,
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
	}
	if err := utils.HTTPDoAPIPath(ctx, controlHTTPClient, relayURL, http.MethodPost, types.PathSDKRegisterChallenge, challengeReq, nil, &challenge); err != nil {
		return types.RegisterResponse{}, err
	}

	signature, err := utils.SignEthereumPersonalMessage(challenge.SIWEMessage, identity.PrivateKey)
	if err != nil {
		return types.RegisterResponse{}, err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, controlHTTPClient, relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    l.reportedIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, err
	}
	return resp, nil
}

func (l *listener) ensureControlHTTPClient(ctx context.Context) error {
	if l == nil {
		return errors.New("listener is unavailable")
	}
	l.mu.Lock()
	if l.controlHTTPClient != nil && l.controlTLSConfig != nil {
		l.mu.Unlock()
		return nil
	}
	relayURL := l.relayURL
	requestTimeout := l.requestTimeout
	l.mu.Unlock()
	if relayURL == nil {
		return errors.New("relay url is unavailable")
	}

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
	defer cancel()

	controlTLSConfig, controlHTTPClient, err := utils.NewHTTPTLSClient(bootstrapCtx, relayURL, requestTimeout)
	if err != nil {
		return err
	}
	if err := l.ensureCompatible(ctx, controlHTTPClient); err != nil {
		closeIdleHTTPClient(controlHTTPClient)
		return err
	}

	l.mu.Lock()
	if l.controlHTTPClient != nil && l.controlTLSConfig != nil {
		l.mu.Unlock()
		closeIdleHTTPClient(controlHTTPClient)
		return nil
	}
	oldControlHTTPClient := l.controlHTTPClient
	l.controlHTTPClient = controlHTTPClient
	l.controlTLSConfig = controlTLSConfig
	l.mu.Unlock()
	closeIdleHTTPClient(oldControlHTTPClient)

	return nil
}

func (l *listener) reportedIP(ctx context.Context) string {
	l.mu.Lock()
	if l.resolvedPublicIP != "" {
		ip := l.resolvedPublicIP
		l.mu.Unlock()
		return ip
	}
	l.mu.Unlock()

	ip := utils.ResolvePublicIP(ctx)
	l.mu.Lock()
	if l.resolvedPublicIP == "" {
		l.resolvedPublicIP = ip
	}
	ip = l.resolvedPublicIP
	l.mu.Unlock()
	return ip
}

func (l *listener) ensureCompatible(ctx context.Context, controlHTTPClient *http.Client) error {
	l.mu.Lock()
	relayURL := l.relayURL
	l.mu.Unlock()
	if relayURL == nil {
		return errors.New("relay url is unavailable")
	}

	var resp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, controlHTTPClient, relayURL, http.MethodGet, types.PathSDKDomain, nil, nil, &resp); err != nil {
		err = fmt.Errorf("check relay compatibility: %w", err)
		var netErr net.Error
		var apiErr *types.APIRequestError
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) {
			return err
		}
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 500 {
			return err
		}
		return fmt.Errorf("%w: %w", errRelayIncompatible, err)
	}
	protocolVersion := strings.TrimSpace(resp.ProtocolVersion)
	if protocolVersion != types.SDKVersion {
		return fmt.Errorf("%w: relay sdk protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.SDKVersion)
	}
	return nil
}

func (l *listener) renewRegisteredLease(ctx context.Context, ttl time.Duration, accessToken string) (types.RenewResponse, error) {
	if err := l.ensureControlHTTPClient(ctx); err != nil {
		return types.RenewResponse{}, err
	}

	l.mu.Lock()
	controlHTTPClient := l.controlHTTPClient
	relayURL := l.relayURL
	l.mu.Unlock()
	if controlHTTPClient == nil {
		return types.RenewResponse{}, errors.New("relay http client is unavailable")
	}

	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, controlHTTPClient, relayURL, http.MethodPost, types.PathSDKRenew, types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(ttl / time.Second),
		ReportedIP:  l.reportedIP(ctx),
	}, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	return resp, nil
}

func (l *listener) unregisterLease(ctx context.Context, accessToken string) error {
	if err := l.ensureControlHTTPClient(ctx); err != nil {
		return err
	}
	l.mu.Lock()
	controlHTTPClient := l.controlHTTPClient
	relayURL := l.relayURL
	l.mu.Unlock()
	if controlHTTPClient == nil {
		return errors.New("relay http client is unavailable")
	}
	return utils.HTTPDoAPIPath(ctx, controlHTTPClient, relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
}

func (l *listener) openReverseSession(ctx context.Context, accessToken string) (net.Conn, error) {
	if err := l.ensureControlHTTPClient(ctx); err != nil {
		return nil, err
	}
	l.mu.Lock()
	controlTLSConfig := l.controlTLSConfig
	relayURL := l.relayURL
	dialTimeout := l.dialTimeout
	l.mu.Unlock()
	if controlTLSConfig == nil {
		return nil, errors.New("relay tls config is unavailable")
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    controlTLSConfig.Clone(),
	}

	conn, err := dialer.DialContext(ctx, "tcp", utils.EnsurePort(relayURL.Host))
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: http.MethodGet,
		URL:    utils.ResolveAPIURL(relayURL, types.PathSDKConnect),
		Host:   relayURL.Host,
		Header: make(http.Header),
	}
	req.Header.Set(types.HeaderAccessToken, accessToken)
	req.Header.Set("Connection", "keep-alive")

	if writeErr := req.Write(conn); writeErr != nil {
		_ = conn.Close()
		return nil, writeErr
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		apiErr := utils.DecodeAPIRequestError(resp)
		_ = conn.Close()
		return nil, apiErr
	}

	return wrapBufferedConn(conn, reader), nil
}

type bufferedConn struct {
	net.Conn
	reader *bytes.Reader
}

func wrapBufferedConn(conn net.Conn, reader *bufio.Reader) net.Conn {
	if reader == nil || reader.Buffered() == 0 {
		return conn
	}
	buf := make([]byte, reader.Buffered())
	if _, err := io.ReadFull(reader, buf); err != nil {
		return conn
	}
	return &bufferedConn{Conn: conn, reader: bytes.NewReader(buf)}
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	if c.reader != nil && c.reader.Len() > 0 {
		return c.reader.Read(p)
	}
	return c.Conn.Read(p)
}

// openQUICSession opens a QUIC connection to the relay for datagram transport.
func (l *listener) openQUICSession(ctx context.Context, accessToken string, sniPort int) (*quic.Conn, error) {
	if err := l.ensureControlHTTPClient(ctx); err != nil {
		return nil, err
	}

	l.mu.Lock()
	controlTLSConfig := l.controlTLSConfig
	relayURL := l.relayURL
	l.mu.Unlock()
	if controlTLSConfig == nil {
		return nil, errors.New("relay tls config is unavailable")
	}

	tlsConf := controlTLSConfig.Clone()
	tlsConf.NextProtos = []string{"portal-tunnel"}

	quicConf := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
	}

	host := strings.TrimSpace(relayURL.Hostname())
	if host == "" {
		host = strings.TrimSpace(relayURL.Host)
	}
	dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", sniPort))
	conn, err := quic.DialAddr(ctx, dialAddr, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("quic dial: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(1, "stream open failed")
		return nil, fmt.Errorf("open control stream: %w", err)
	}

	controlMsg := types.QUICControlMessage{
		AccessToken: accessToken,
	}
	if err := json.NewEncoder(stream).Encode(controlMsg); err != nil {
		_ = conn.CloseWithError(1, "control write failed")
		return nil, fmt.Errorf("write control: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp types.QUICControlResponse
	if err := json.NewDecoder(io.LimitReader(stream, 4096)).Decode(&resp); err != nil {
		_ = conn.CloseWithError(1, "control read failed")
		return nil, fmt.Errorf("read control response: %w", err)
	}
	if !resp.OK {
		_ = conn.CloseWithError(1, resp.Error)
		return nil, fmt.Errorf("quic connect rejected: %s", resp.Error)
	}

	return conn, nil
}
