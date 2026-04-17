package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
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

// resetTransport tears down the cached HTTP client and TLS config so the next
// API call creates fresh TCP connections. Call this after detecting a system
// sleep/wake cycle where pooled connections are almost certainly dead.
func (l *listener) resetTransport() {
	if l.httpClient != nil {
		if transport, ok := l.httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	l.httpClient = nil
	l.tlsConfig = nil
}

func (l *listener) initHTTPTransport(ctx context.Context) error {
	if l.httpClient != nil {
		return nil
	}

	bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
	defer cancel()

	tlsConfig, httpClient, err := utils.NewHTTPTLSClient(bootstrapCtx, l.relayURL, l.requestTimeout)
	if err != nil {
		return err
	}

	var domainResp types.DomainResponse
	if err := utils.HTTPDoAPIPath(ctx, httpClient, l.relayURL, http.MethodGet, types.PathSDKDomain, nil, nil, &domainResp); err != nil {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
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
	protocolVersion := strings.TrimSpace(domainResp.ProtocolVersion)
	if protocolVersion != types.SDKVersion {
		if transport, ok := httpClient.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		return fmt.Errorf("%w: relay sdk protocol version mismatch: relay=%q client=%q", errRelayIncompatible, protocolVersion, types.SDKVersion)
	}

	l.httpClient = httpClient
	l.tlsConfig = tlsConfig
	return nil
}

func (l *listener) registerLease(ctx context.Context, ttl time.Duration, udpEnabled, tcpEnabled bool) (types.RegisterResponse, []types.HopRoute, error) {
	var exitHopToken string
	var publicHostname string
	var keylessURL string
	var hopRoutes []types.HopRoute
	if len(l.multiHop) > 0 {
		if len(l.multiHop) < 2 {
			return types.RegisterResponse{}, nil, errors.New("multi-hop requires at least entry and exit relay urls")
		}
		if l.relaySet == nil {
			return types.RegisterResponse{}, nil, errors.New("multi-hop relay set is unavailable")
		}

		states := l.relaySet.AggregateRelays()
		descriptors := make(map[string]types.RelayDescriptor, len(states))
		for _, state := range states {
			desc := state.Descriptor
			if desc.APIHTTPSAddr != "" {
				descriptors[desc.APIHTTPSAddr] = desc
			}
		}

		hopPath := make([]types.RelayDescriptor, 0, len(l.multiHop))
		for i, relayURL := range l.multiHop {
			desc, ok := descriptors[relayURL]
			if !ok {
				return types.RegisterResponse{}, nil, fmt.Errorf("multi-hop relay %d descriptor was not discovered", i)
			}
			if !desc.SupportsOverlay {
				return types.RegisterResponse{}, nil, fmt.Errorf("multi-hop relay %d does not support overlay", i)
			}
			hopPath = append(hopPath, desc)
		}

		var err error
		publicHostname, err = utils.LeaseHostname(l.identity.Name, utils.PortalRootHost(hopPath[0].APIHTTPSAddr))
		if err != nil {
			return types.RegisterResponse{}, nil, err
		}
		keylessURL = hopPath[0].APIHTTPSAddr

		tokens := make([]string, len(hopPath)-1)
		for i := range tokens {
			token, err := l.identity.DeriveToken(
				"hop-token",
				publicHostname,
				strconv.Itoa(i),
				hopPath[i].APIHTTPSAddr,
				hopPath[i+1].APIHTTPSAddr,
			)
			if err != nil {
				return types.RegisterResponse{}, nil, err
			}
			tokens[i] = "hpt_" + token
		}

		hopRoutes = make([]types.HopRoute, 0, len(tokens))
		for i := range tokens {
			route := types.HopRoute{
				RelayURL:     hopPath[i].APIHTTPSAddr,
				ForwardRelay: hopPath[i+1],
				ForwardToken: tokens[i],
			}
			if i == 0 {
				route.MatchHostname = publicHostname
			} else {
				route.MatchToken = tokens[i-1]
			}
			hopRoutes = append(hopRoutes, route)
		}
		exitHopToken = tokens[len(tokens)-1]
	}

	var challenge types.RegisterChallengeResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegisterChallenge, types.RegisterChallengeRequest{
		Identity:   l.identity,
		Metadata:   l.metadata,
		TTL:        int(ttl / time.Second),
		UDPEnabled: udpEnabled,
		TCPEnabled: tcpEnabled,
		HopToken:   exitHopToken,
	}, nil, &challenge); err != nil {
		return types.RegisterResponse{}, nil, err
	}

	signature, err := utils.SignEthereumPersonalMessage(challenge.SIWEMessage, l.identity.PrivateKey)
	if err != nil {
		return types.RegisterResponse{}, nil, err
	}

	var resp types.RegisterResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRegister, types.RegisterRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
		ReportedIP:    utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RegisterResponse{}, nil, err
	}
	if len(hopRoutes) > 0 {
		if err := l.syncHopRoutes(ctx, http.MethodPost, resp.ExpiresAt, hopRoutes); err != nil {
			_ = l.unregisterLease(context.Background(), resp.AccessToken, hopRoutes)
			return types.RegisterResponse{}, nil, err
		}
		resp.Hostname = publicHostname
		resp.KeylessURL = keylessURL
	}
	return resp, hopRoutes, nil
}

func (l *listener) renewRegisteredLease(ctx context.Context, ttl time.Duration, accessToken string, hopRoutes []types.HopRoute) (types.RenewResponse, error) {
	var resp types.RenewResponse
	if err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKRenew, types.RenewRequest{
		AccessToken: accessToken,
		TTL:         int(ttl / time.Second),
		ReportedIP:  utils.ResolvePublicIP(ctx),
	}, nil, &resp); err != nil {
		return types.RenewResponse{}, err
	}
	if err := l.syncHopRoutes(ctx, http.MethodPost, resp.ExpiresAt, hopRoutes); err != nil {
		return types.RenewResponse{}, err
	}
	return resp, nil
}

func (l *listener) unregisterLease(ctx context.Context, accessToken string, hopRoutes []types.HopRoute) error {
	var unregisterErr error
	if err := l.syncHopRoutes(ctx, http.MethodDelete, time.Time{}, hopRoutes); err != nil {
		unregisterErr = errors.Join(unregisterErr, err)
	}
	err := utils.HTTPDoAPIPath(ctx, l.httpClient, l.relayURL, http.MethodPost, types.PathSDKUnregister, types.UnregisterRequest{
		AccessToken: accessToken,
	}, nil, nil)
	return errors.Join(unregisterErr, err)
}

func (l *listener) syncHopRoutes(ctx context.Context, method string, expiresAt time.Time, routes []types.HopRoute) error {
	if len(routes) == 0 {
		return nil
	}

	orderedRoutes := routes
	if method == http.MethodPost {
		orderedRoutes = append([]types.HopRoute(nil), routes...)
		slices.Reverse(orderedRoutes)
	}

	var syncErr error
	for _, unsignedRoute := range orderedRoutes {
		route, err := auth.SignHopRoute(method, unsignedRoute, l.identity, expiresAt)
		if err != nil {
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}
		relayURL, err := url.Parse(route.RelayURL)
		if err != nil {
			err = fmt.Errorf("parse hop route relay url: %w", err)
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}

		bootstrapCtx, cancel := context.WithTimeout(ctx, defaultDialTimeout+defaultHandshakeTimeout)
		_, client, err := utils.NewHTTPTLSClient(bootstrapCtx, relayURL, l.requestTimeout)
		cancel()
		if err != nil {
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}
		transport, _ := client.Transport.(*http.Transport)
		err = utils.HTTPDoAPIPath(ctx, client, relayURL, method, types.PathSDKHop, route, nil, nil)
		if transport != nil {
			transport.CloseIdleConnections()
		}
		if err != nil {
			if method == http.MethodDelete {
				syncErr = errors.Join(syncErr, err)
				continue
			}
			return err
		}
	}
	return syncErr
}
