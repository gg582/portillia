package portal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/policy"
	"github.com/gosuda/portal-tunnel/v2/portal/transport"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

const defaultRegisterChallengeTTL = 2 * time.Minute

type leaseRegistry struct {
	leasesByKey        map[string]*leaseRecord
	recordsByHostname  map[string]*leaseRecord
	recordsByHopToken  map[string]*leaseRecord
	registerChallenges map[string]*auth.RegisterChallenge
	policy             *policy.Runtime
	mu                 sync.RWMutex
}

func newLeaseRegistry(udpEnabled, tcpPortEnabled bool, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*leaseRegistry, error) {
	runtime, err := policy.NewRuntime(udpEnabled, tcpPortEnabled, trustProxyHeaders, rawTrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}

	return &leaseRegistry{
		leasesByKey:        make(map[string]*leaseRecord),
		recordsByHostname:  make(map[string]*leaseRecord),
		recordsByHopToken:  make(map[string]*leaseRecord),
		registerChallenges: make(map[string]*auth.RegisterChallenge),
		policy:             runtime,
	}, nil
}

func (r *leaseRegistry) CloseAll() []*leaseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*leaseRecord, 0, len(r.leasesByKey))
	for _, record := range r.leasesByKey {
		out = append(out, record)
		r.policy.ForgetIdentity(record.Key())
	}
	r.leasesByKey = make(map[string]*leaseRecord)
	r.recordsByHostname = make(map[string]*leaseRecord)
	r.recordsByHopToken = make(map[string]*leaseRecord)
	r.registerChallenges = make(map[string]*auth.RegisterChallenge)
	return out
}

func (r *leaseRegistry) Lookup(host string) (*leaseRecord, bool) {
	host = utils.NormalizeHostname(host)
	if host == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record := r.lookupLocked(host)
	return record, record != nil
}

func (r *leaseRegistry) lookupLocked(host string) *leaseRecord {
	record := r.recordsByHostname[host]
	if record == nil {
		parts := strings.Split(host, ".")
		if len(parts) < 3 {
			return nil
		}
		record = r.recordsByHostname["*."+strings.Join(parts[1:], ".")]
	}
	return record
}

func (r *leaseRegistry) Register(record *leaseRecord) error {
	if record == nil {
		return errors.New("lease record is required")
	}

	key := record.Key()
	if key == "" {
		return errors.New("lease identity is required")
	}
	hostname := utils.NormalizeHostname(record.Hostname)
	if hostname == "" {
		return errors.New("lease hostname is required")
	}
	record.hopToken = strings.TrimSpace(record.hopToken)

	r.mu.Lock()

	now := time.Now()
	if record.isDirect() {
		if existing := r.recordsByHostname[hostname]; existing != nil && existing.Key() != key && now.Before(existing.ExpiresAt) {
			r.mu.Unlock()
			return errHostnameConflict
		}
	}
	if record.hopToken != "" {
		if existing := r.recordsByHopToken[record.hopToken]; existing != nil && existing.Key() != key && now.Before(existing.ExpiresAt) {
			r.mu.Unlock()
			return errors.New("hop token conflict")
		}
	}

	var replaced *leaseRecord
	if existing, ok := r.leasesByKey[key]; ok && existing != nil {
		replaced = existing
		r.deleteIndexesLocked(existing)
		r.policy.ForgetIdentity(existing.Key())
	}
	record.Hostname = hostname
	r.leasesByKey[key] = record
	if record.isDirect() {
		r.recordsByHostname[hostname] = record
	}
	if record.hopToken != "" {
		r.recordsByHopToken[record.hopToken] = record
	}
	r.policy.IPFilter().RegisterIdentityIP(key, record.ClientIP)
	r.mu.Unlock()

	if replaced != nil && replaced != record {
		replaced.Close()
	}
	return nil
}

func (r *leaseRegistry) Renew(identity types.Identity, ttl time.Duration, clientIP, reportedIP string) (*leaseRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.leasesByKey[identity.Key()]
	if !ok {
		return nil, errLeaseNotFound
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	record.ExpiresAt = expiresAt
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	if strings.TrimSpace(reportedIP) != "" {
		record.ReportedIP = reportedIP
	}
	r.policy.IPFilter().RegisterIdentityIP(record.Key(), clientIP)
	return record, nil
}

func (r *leaseRegistry) Unregister(identity types.Identity) (*leaseRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := identity.Key()
	record, ok := r.leasesByKey[key]
	if !ok {
		return nil, errLeaseNotFound
	}

	delete(r.leasesByKey, key)
	r.deleteIndexesLocked(record)
	r.policy.ForgetIdentity(key)
	return record, nil
}

func (r *leaseRegistry) RecordByKey(key string, now time.Time) (*leaseRecord, bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record := r.leasesByKey[key]
	if record == nil || now.After(record.ExpiresAt) {
		return nil, false
	}
	return record, true
}

func (r *leaseRegistry) RecordByHopToken(token string, now time.Time) (*leaseRecord, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	record := r.recordsByHopToken[token]
	if record != nil && now.Before(record.ExpiresAt) {
		return record, true
	}
	return nil, false
}

func (r *leaseRegistry) RegisterHopRoute(route *types.HopRoute, now time.Time) error {
	if route == nil {
		return errors.New("hop route is required")
	}
	ownerKey, err := utils.AddressFromCompressedPublicKeyHex(route.OwnerPublicKey)
	if err != nil {
		return err
	}
	matchHostname := utils.NormalizeHostname(route.MatchHostname)
	matchToken := strings.TrimSpace(route.MatchToken)
	overlayIPv4 := strings.TrimSpace(route.ForwardRelay.OverlayIPv4)
	forwardToken := strings.TrimSpace(route.ForwardToken)
	expiresAt := route.ExpiresAt.UTC()

	switch {
	case r == nil:
		return errFeatureUnavailable
	case !expiresAt.After(now):
		return errors.New("route expiry must be in the future")
	case matchHostname == "" && matchToken == "":
		return errors.New("hostname or token matcher is required")
	case matchHostname != "" && matchToken != "":
		return errors.New("hostname and token matchers are mutually exclusive")
	case overlayIPv4 == "":
		return errors.New("forward overlay ipv4 is required")
	case forwardToken == "":
		return errors.New("forward token is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	record := &leaseRecord{
		Hostname:           matchHostname,
		ExpiresAt:          expiresAt,
		hopOwnerKey:        ownerKey,
		hopToken:           matchToken,
		hopNextOverlayIPv4: overlayIPv4,
		hopNextToken:       forwardToken,
	}
	if matchHostname != "" {
		if existing := r.lookupLocked(matchHostname); existing != nil && now.Before(existing.ExpiresAt) {
			if !existing.isHopForward() || existing.hopOwnerKey != ownerKey {
				return errHostnameConflict
			}
		}
		r.recordsByHostname[matchHostname] = record
		return nil
	}
	if existing := r.recordsByHopToken[matchToken]; existing != nil && now.Before(existing.ExpiresAt) {
		if !existing.isHopForward() || existing.hopOwnerKey != ownerKey {
			return errors.New("hop token conflict")
		}
	}
	r.recordsByHopToken[matchToken] = record
	return nil
}

func (r *leaseRegistry) DeleteHopRoute(route *types.HopRoute) {
	if r == nil || route == nil {
		return
	}
	ownerKey, err := utils.AddressFromCompressedPublicKeyHex(route.OwnerPublicKey)
	if err != nil {
		return
	}
	hostname := utils.NormalizeHostname(route.MatchHostname)
	token := strings.TrimSpace(route.MatchToken)

	r.mu.Lock()
	if hostname != "" {
		if record := r.recordsByHostname[hostname]; record != nil && record.isHopForward() && record.hopOwnerKey == ownerKey {
			delete(r.recordsByHostname, hostname)
		}
	}
	if token != "" {
		if record := r.recordsByHopToken[token]; record != nil && record.isHopForward() && record.hopOwnerKey == ownerKey {
			delete(r.recordsByHopToken, token)
		}
	}
	r.mu.Unlock()
}

func (r *leaseRegistry) issueRegisterChallenge(req types.RegisterChallengeRequest, domain, uri string) (types.RegisterChallengeResponse, error) {
	if strings.TrimSpace(req.HopToken) != "" && (req.UDPEnabled || req.TCPEnabled) {
		return types.RegisterChallengeResponse{}, errTransportMismatch
	}
	if req.UDPEnabled {
		if !r.policy.IsUDPEnabled() {
			return types.RegisterChallengeResponse{}, errUDPDisabled
		}
		if max := r.policy.UDPMaxLeases(); max > 0 && r.countDatagramLeases() >= max {
			return types.RegisterChallengeResponse{}, errUDPCapacityExceeded
		}
	}
	if req.TCPEnabled {
		if !r.policy.IsTCPPortEnabled() {
			return types.RegisterChallengeResponse{}, errTCPPortDisabled
		}
		if max := r.policy.TCPPortMaxLeases(); max > 0 && r.countTCPPortLeases() >= max {
			return types.RegisterChallengeResponse{}, errTCPPortCapacityExceeded
		}
	}

	now := time.Now().UTC()
	challenge, err := auth.NewRegisterChallenge(req, domain, uri, now, defaultRegisterChallengeTTL)
	if err != nil {
		return types.RegisterChallengeResponse{}, err
	}

	r.mu.Lock()
	r.registerChallenges[challenge.ChallengeID] = challenge
	r.mu.Unlock()

	return types.RegisterChallengeResponse{
		ChallengeID: challenge.ChallengeID,
		ExpiresAt:   challenge.ExpiresAt,
		SIWEMessage: challenge.SIWEMessage,
	}, nil
}

func (r *leaseRegistry) consumeVerifiedRegisterChallenge(req types.RegisterRequest) (*auth.RegisterChallenge, error) {
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		return nil, auth.ErrRegisterChallengeNotFound
	}

	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	challenge := r.registerChallenges[challengeID]
	if challenge == nil {
		return nil, auth.ErrRegisterChallengeNotFound
	}
	if challenge.Expired(now) {
		delete(r.registerChallenges, challengeID)
		return nil, auth.ErrRegisterChallengeExpired
	}
	if err := challenge.Verify(req, now); err != nil {
		return nil, err
	}

	delete(r.registerChallenges, challengeID)
	return challenge, nil
}

func (r *leaseRegistry) Touch(identity types.Identity, clientIP string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.leasesByKey[identity.Key()]
	if !ok {
		return
	}
	record.LastSeenAt = now
	if strings.TrimSpace(clientIP) != "" {
		record.ClientIP = clientIP
	}
	r.policy.IPFilter().RegisterIdentityIP(record.Key(), clientIP)
}

func (r *leaseRegistry) cleanupExpired(now time.Time) []*leaseRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	expired := make([]*leaseRecord, 0)
	for key, record := range r.leasesByKey {
		if now.After(record.ExpiresAt) {
			expired = append(expired, record)
			delete(r.leasesByKey, key)
			r.deleteIndexesLocked(record)
			r.policy.ForgetIdentity(key)
		}
	}
	for challengeID, challenge := range r.registerChallenges {
		if challenge.Expired(now) {
			delete(r.registerChallenges, challengeID)
		}
	}
	for hostname, record := range r.recordsByHostname {
		if record != nil && !now.Before(record.ExpiresAt) {
			delete(r.recordsByHostname, hostname)
		}
	}
	for token, record := range r.recordsByHopToken {
		if record != nil && !now.Before(record.ExpiresAt) {
			delete(r.recordsByHopToken, token)
		}
	}
	return expired
}

func (r *leaseRegistry) countDatagramLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range r.leasesByKey {
		if now.Before(record.ExpiresAt) && record.datagram != nil {
			count++
		}
	}
	return count
}

func (r *leaseRegistry) countTCPPortLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, record := range r.leasesByKey {
		if now.Before(record.ExpiresAt) && record.tcpPort != nil {
			count++
		}
	}
	return count
}

func (r *leaseRegistry) LeaseSnapshots(now time.Time) []types.Lease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]types.Lease, 0, len(r.leasesByKey))
	for _, record := range r.leasesByKey {
		if record == nil || now.After(record.ExpiresAt) {
			continue
		}
		adminSnapshot := r.AdminSnapshot(record)
		since := time.Duration(0)
		if !adminSnapshot.LastSeenAt.IsZero() {
			since = max(now.Sub(adminSnapshot.LastSeenAt), 0)
		}
		if adminSnapshot.IsBanned || adminSnapshot.IsDenied || !adminSnapshot.IsApproved || adminSnapshot.Metadata.Hide {
			continue
		}
		if adminSnapshot.Ready == 0 && since >= 3*time.Minute {
			continue
		}
		snapshots = append(snapshots, adminSnapshot.Lease)
	}
	return snapshots
}

func (r *leaseRegistry) AdminLeaseSnapshots(now time.Time) []types.AdminLease {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snapshots := make([]types.AdminLease, 0, len(r.leasesByKey))
	for _, record := range r.leasesByKey {
		if now.After(record.ExpiresAt) {
			continue
		}
		snapshots = append(snapshots, r.AdminSnapshot(record))
	}
	return snapshots
}

func (r *leaseRegistry) Snapshot(record *leaseRecord) types.Lease {
	snapshot := types.Lease{
		Name:        record.Name,
		ExpiresAt:   record.ExpiresAt,
		FirstSeenAt: record.FirstSeenAt,
		LastSeenAt:  record.LastSeenAt,
		Hostname:    record.Hostname,
		UDPEnabled:  record.UDPEnabled,
		TCPEnabled:  record.TCPEnabled,
		Metadata:    record.Metadata.Copy(),
	}
	if record.tcpPort != nil {
		snapshot.TCPAddr = fmt.Sprintf("%s:%d", record.Hostname, record.tcpPort.TCPPort())
	}
	if record.stream != nil {
		snapshot.Ready = record.stream.ReadyCount()
	}
	return snapshot
}

type leaseRecord struct {
	types.Identity
	ExpiresAt   time.Time
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	ClientIP    string
	ReportedIP  string
	Hostname    string
	UDPEnabled  bool
	TCPEnabled  bool
	Metadata    types.LeaseMetadata

	hopToken           string
	hopOwnerKey        string
	hopNextOverlayIPv4 string
	hopNextToken       string

	datagram  *transport.RelayDatagram
	udpPorts  *transport.PortAllocator
	tcpPort   *transport.RelayTCPPort
	tcpPorts  *transport.PortAllocator
	stream    *transport.RelayStream
	startErr  error
	startOnce sync.Once
}

func (r *leaseRecord) isDirect() bool {
	return r == nil || (strings.TrimSpace(r.hopToken) == "" && !r.isHopForward())
}

func (r *leaseRecord) isHopForward() bool {
	return r != nil && (strings.TrimSpace(r.hopNextOverlayIPv4) != "" || strings.TrimSpace(r.hopNextToken) != "")
}

func (r *leaseRegistry) deleteIndexesLocked(record *leaseRecord) {
	if record == nil {
		return
	}
	hostname := utils.NormalizeHostname(record.Hostname)
	if hostname != "" {
		if r.recordsByHostname[hostname] == record {
			delete(r.recordsByHostname, hostname)
		}
	}
	token := strings.TrimSpace(record.hopToken)
	if token != "" {
		if r.recordsByHopToken[token] == record {
			delete(r.recordsByHopToken, token)
		}
	}
}

func (r *leaseRegistry) AdminSnapshot(record *leaseRecord) types.AdminLease {
	clientIP := record.ClientIP
	identityKey := record.Key()
	return types.AdminLease{
		Lease:       r.Snapshot(record),
		IdentityKey: identityKey,
		Address:     record.Address,
		BPS:         r.policy.BPSManager().IdentityBPS(identityKey),
		ClientIP:    clientIP,
		ReportedIP:  record.ReportedIP,
		IsApproved:  r.policy.EffectiveApproval(identityKey),
		IsBanned:    r.policy.IsIdentityBanned(identityKey),
		IsDenied:    r.policy.IsIdentityDenied(identityKey),
		IsIPBanned:  r.policy.IPFilter().IsIPBanned(clientIP),
	}
}

func (r *leaseRecord) Start() error {
	r.startOnce.Do(func() {
		if r.datagram != nil {
			r.startErr = r.datagram.Start(context.Background())
			if r.startErr != nil {
				return
			}
		}
		if r.tcpPort != nil {
			r.startErr = r.tcpPort.Start(context.Background())
		}
	})
	return r.startErr
}

func (r *leaseRecord) Close() {
	if r == nil {
		return
	}
	if r.stream != nil {
		r.stream.Close()
	}
	if r.datagram != nil {
		port := r.datagram.UDPPort()
		r.datagram.Close()
		if port > 0 && r.udpPorts != nil {
			r.udpPorts.Release(port)
		}
	}
	if r.tcpPort != nil {
		port := r.tcpPort.TCPPort()
		r.tcpPort.Close()
		if port > 0 && r.tcpPorts != nil {
			r.tcpPorts.Release(port)
		}
	}
}
