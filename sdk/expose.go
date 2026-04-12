package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// Exposure owns the lifecycle of one or more relay listeners and accepts
// traffic from all of them through one net.Listener.
type Exposure struct {
	cancel context.CancelFunc
	done   <-chan struct{}

	identity        types.Identity
	TargetAddr      string
	UDPAddr         string
	udpEnabled      bool
	tcpEnabled      bool
	banMITM         bool
	maxActiveRelays int
	metadata        types.LeaseMetadata
	rootCAPEM       []byte

	accepted  chan net.Conn
	datagrams chan types.DatagramFrame

	relaySet       *discovery.RelaySet
	listenerMu     sync.RWMutex
	relayListeners map[string]*Listener

	closeOnce sync.Once
	connSeq   atomic.Uint64
}

type ExposeConfig struct {
	RelayURLs       []string
	IdentityPath    string
	IdentityJSON    string
	Name            string
	TargetAddr      string
	UDPAddr         string
	UDPEnabled      bool
	TCPEnabled      bool
	BanMITM         bool
	MaxActiveRelays int
	Discovery       bool
	Metadata        types.LeaseMetadata
	RootCAPEM       []byte
}

// Expose creates relay listeners for the selected relay pool and exposes a
// dynamic listener hub for accepting traffic from all of them.
func Expose(ctx context.Context, cfg ExposeConfig) (*Exposure, error) {
	relayURLs, err := utils.ResolvePortalRelayURLs(ctx, cfg.RelayURLs, cfg.Discovery)
	if err != nil {
		return nil, err
	}

	identity, createdIdentity, err := utils.ResolveListenerIdentity(
		types.Identity{Name: cfg.Name},
		cfg.TargetAddr,
		cfg.IdentityPath,
		cfg.IdentityJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve identity: %w", err)
	}
	if createdIdentity {
		log.Info().
			Str("identity_path", strings.TrimSpace(cfg.IdentityPath)).
			Str("address", identity.Address).
			Msg("generated tunnel identity and saved it to disk")
	}
	targetAddr, err := utils.NormalizeLoopbackTarget(cfg.TargetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target value %q: %w", cfg.TargetAddr, err)
	}
	udpAddr := cfg.UDPAddr
	if cfg.UDPEnabled {
		udpAddr, err = utils.NormalizeLoopbackTarget(utils.StringOrDefault(udpAddr, targetAddr))
		if err != nil {
			return nil, fmt.Errorf("invalid --udp-addr value %q: %w", cfg.UDPAddr, err)
		}
	}
	relaySet, err := discovery.NewRelaySet(types.Identity{}, "", relayURLs)
	if err != nil {
		return nil, err
	}

	exposureCtx, cancel := context.WithCancel(ctx)
	exposure := &Exposure{
		cancel:          cancel,
		done:            exposureCtx.Done(),
		identity:        identity,
		TargetAddr:      targetAddr,
		UDPAddr:         udpAddr,
		udpEnabled:      cfg.UDPEnabled,
		tcpEnabled:      cfg.TCPEnabled,
		banMITM:         cfg.BanMITM,
		maxActiveRelays: cfg.MaxActiveRelays,
		metadata:        cfg.Metadata.Copy(),
		rootCAPEM:       append([]byte(nil), cfg.RootCAPEM...),
		accepted:        make(chan net.Conn, max(len(relayURLs)*defaultReadyTarget*2, 1)),
		datagrams:       make(chan types.DatagramFrame, max(len(relayURLs)*32, 1)),
		relaySet:        relaySet,
		relayListeners:  make(map[string]*Listener, len(relayURLs)),
	}

	if len(relayURLs) > 0 {
		if err := exposure.reconcileRelayListeners(true); err != nil {
			_ = exposure.Close()
			return nil, err
		}
	}

	if cfg.Discovery {
		go exposure.runDiscoveryLoop(exposureCtx)
	}
	go func() {
		<-exposure.done
		_ = exposure.Close()
	}()

	return exposure, nil
}

func (e *Exposure) runDiscoveryLoop(ctx context.Context) {
	refresher, err := discovery.NewRefresher(e.relaySet, e.rootCAPEM, nil)
	if err != nil {
		return
	}
	ticker := time.NewTicker(discovery.DiscoveryPollInterval)
	defer ticker.Stop()

	for {
		if err := refresher.Refresh(ctx); err != nil {
			return
		}
		if err := e.reconcileRelayListeners(false); err != nil {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Exposure) ActiveRelayURLs() []string {
	return append([]string(nil), e.clientState().ActiveRelayURLs...)
}

func (e *Exposure) clientState() discovery.ClientState {
	state := discovery.ClientState{
		MaxActiveRelays: e.maxActiveRelays,
		RequireUDP:      e.udpEnabled,
		RequireTCP:      e.tcpEnabled,
	}

	e.listenerMu.RLock()
	state.ActiveRelayURLs = make([]string, 0, len(e.relayListeners))
	for relayURL := range e.relayListeners {
		state.ActiveRelayURLs = append(state.ActiveRelayURLs, relayURL)
	}
	e.listenerMu.RUnlock()
	sort.Strings(state.ActiveRelayURLs)
	return state
}

func (e *Exposure) Addr() net.Addr {
	if e.identity.Address == "" {
		return listenerAddr("portal:exposure")
	}
	return listenerAddr("portal:" + e.identity.Address)
}

func (e *Exposure) Identity() types.Identity {
	return e.identity.Copy()
}

func (e *Exposure) AcceptDatagram() (types.DatagramFrame, error) {
	if !e.udpEnabled {
		return types.DatagramFrame{}, net.ErrClosed
	}

	select {
	case <-e.done:
		return types.DatagramFrame{}, net.ErrClosed
	case frame := <-e.datagrams:
		return frame, nil
	}
}

func (e *Exposure) SendDatagram(frame types.DatagramFrame) error {
	if !e.udpEnabled {
		return net.ErrClosed
	}

	e.listenerMu.RLock()
	listener := e.relayListeners[frame.RelayURL]
	e.listenerMu.RUnlock()
	if listener == nil {
		return net.ErrClosed
	}
	return listener.SendDatagram(frame)
}

func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]string, error) {
	if !e.udpEnabled {
		return nil, errors.New("exposure does not have udp enabled")
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		e.listenerMu.RLock()
		addrs := make([]string, 0, len(e.relayListeners))
		seen := make(map[string]struct{})
		resolvedWithoutDatagram := true
		for _, listener := range e.relayListeners {
			if listener == nil {
				continue
			}

			udpAddr, ready, pending := listener.DatagramReady()
			if ready {
				if _, ok := seen[udpAddr]; !ok {
					seen[udpAddr] = struct{}{}
					addrs = append(addrs, udpAddr)
				}
			}
			if pending {
				resolvedWithoutDatagram = false
			}
		}
		e.listenerMu.RUnlock()
		if len(addrs) > 0 {
			return addrs, nil
		}
		if resolvedWithoutDatagram {
			return nil, errors.New("relay did not expose udp")
		}

		select {
		case <-e.done:
			return nil, net.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (e *Exposure) RunHTTP(ctx context.Context, handler http.Handler, localAddr string) error {
	e.listenerMu.RLock()
	hasRelayListeners := len(e.relayListeners) > 0
	e.listenerMu.RUnlock()

	if hasRelayListeners {
		return RunHTTP(ctx, e, handler, localAddr)
	}
	return RunHTTP(ctx, nil, handler, localAddr)
}

type exposureConn struct {
	net.Conn
	id         uint64
	localAddr  string
	remoteAddr string
	closeOnce  sync.Once
}

func (c *exposureConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		closeErr = c.Conn.Close()
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}

		event := log.Info().
			Uint64("conn_id", c.id).
			Str("local_addr", c.localAddr).
			Str("remote_addr", c.remoteAddr)
		if closeErr != nil {
			event = log.Warn().
				Err(closeErr).
				Uint64("conn_id", c.id).
				Str("local_addr", c.localAddr).
				Str("remote_addr", c.remoteAddr)
		}
		event.Msg("exposure connection closed")
	})
	return closeErr
}

func (e *Exposure) Accept() (net.Conn, error) {
	select {
	case <-e.done:
		return nil, net.ErrClosed
	case conn := <-e.accepted:
		if conn == nil {
			return nil, net.ErrClosed
		}

		connID := e.connSeq.Add(1)
		log.Info().
			Uint64("conn_id", connID).
			Str("local_addr", utils.AddrString(conn.LocalAddr())).
			Str("remote_addr", utils.AddrString(conn.RemoteAddr())).
			Msg("exposure connection accepted")

		return &exposureConn{
			Conn:       conn,
			id:         connID,
			localAddr:  utils.AddrString(conn.LocalAddr()),
			remoteAddr: utils.AddrString(conn.RemoteAddr()),
		}, nil
	}
}

func (e *Exposure) Close() error {
	var closeErr error
	e.closeOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}

		e.listenerMu.Lock()
		relayListeners := e.relayListeners
		e.relayListeners = make(map[string]*Listener)
		e.listenerMu.Unlock()

		relayURLs := make([]string, 0, len(relayListeners))
		for relayURL, listener := range relayListeners {
			relayURLs = append(relayURLs, relayURL)
			if listener != nil {
				closeErr = errors.Join(closeErr, listener.Close())
			}
		}

		event := log.Info().
			Int("relay_count", len(relayListeners)).
			Strs("relays", relayURLs)
		if closeErr != nil {
			event = log.Warn().
				Err(closeErr).
				Int("relay_count", len(relayListeners)).
				Strs("relays", relayURLs)
		}
		event.Msg("exposure closed")
	})
	return closeErr
}

func (e *Exposure) reconcileRelayListeners(failOnError bool) error {
	selectedRelays := e.relaySet.PriorityRelays(e.clientState())
	desiredRelayURLs := make(map[string]struct{}, len(selectedRelays))
	for _, state := range selectedRelays {
		desiredRelayURLs[state.Descriptor.APIHTTPSAddr] = struct{}{}
	}

	e.listenerMu.Lock()
	staleRelayListeners := make(map[string]*Listener)
	for relayURL, listener := range e.relayListeners {
		if _, ok := desiredRelayURLs[relayURL]; ok {
			continue
		}
		staleRelayListeners[relayURL] = listener
		delete(e.relayListeners, relayURL)
	}

	missingRelayURLs := make([]string, 0, len(selectedRelays))
	for _, state := range selectedRelays {
		relayURL := state.Descriptor.APIHTTPSAddr
		if _, ok := e.relayListeners[relayURL]; ok {
			continue
		}
		missingRelayURLs = append(missingRelayURLs, relayURL)
	}
	e.listenerMu.Unlock()

	for relayURL, listener := range staleRelayListeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("close stale relay listener")
		}
	}
	for _, relayURL := range missingRelayURLs {
		listener, err := NewListener(context.Background(), relayURL, ListenerConfig{
			Identity:   e.identity.Copy(),
			UDPEnabled: e.udpEnabled,
			TCPEnabled: e.tcpEnabled,
			BanMITM:    e.banMITM,
			Metadata:   e.metadata.Copy(),
			RootCAPEM:  append([]byte(nil), e.rootCAPEM...),
			relaySet:   e.relaySet,
		})
		if err != nil {
			if failOnError {
				return fmt.Errorf("listen %q: %w", relayURL, err)
			}
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("add relay listener")
			continue
		}

		select {
		case <-e.done:
			_ = listener.Close()
			continue
		default:
		}

		e.listenerMu.Lock()
		if _, exists := e.relayListeners[relayURL]; exists {
			e.listenerMu.Unlock()
			_ = listener.Close()
			continue
		}
		e.relayListeners[relayURL] = listener
		e.listenerMu.Unlock()

		go e.runListenerAcceptLoop(listener)
	}
	return nil
}

func (e *Exposure) runListenerAcceptLoop(listener *Listener) {
	if listener == nil {
		return
	}

	relayURL := listener.api.baseURL.String()
	if e.udpEnabled {
		go func() {
			for {
				frame, err := listener.AcceptDatagram()
				if err != nil {
					select {
					case <-e.done:
						return
					default:
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					log.Warn().
						Err(err).
						Str("relay_url", relayURL).
						Str("address", listener.Address()).
						Msg("datagram accept failed")
					return
				}

				select {
				case <-e.done:
					return
				case e.datagrams <- frame:
				}
			}
		}()
	}
	defer func() {
		e.listenerMu.Lock()
		if current, ok := e.relayListeners[relayURL]; ok && current == listener {
			delete(e.relayListeners, relayURL)
		}
		e.listenerMu.Unlock()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if listener.closed() || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn().Err(err).Str("relay_url", relayURL).Msg("exposure listener accept failed")
			return
		}

		select {
		case <-e.done:
			_ = conn.Close()
			return
		case e.accepted <- conn:
		}
	}
}
