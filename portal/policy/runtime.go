package policy

import (
	"fmt"
	"net"
	"sync"

	"github.com/gosuda/portal-tunnel/v2/utils"
)

type PortPolicy struct {
	enabled   bool
	maxLeases int
}

func (p PortPolicy) IsEnabled() bool { return p.enabled }
func (p PortPolicy) MaxLeases() int  { return p.maxLeases }

func (p *PortPolicy) Set(enabled bool, maxLeases int) {
	p.enabled = enabled
	p.maxLeases = maxLeases
}

type Runtime struct {
	approver           *Approver
	bpsManager         *BPSManager
	ipFilter           *IPFilter
	bannedIdentityKeys map[string]struct{}
	udp                PortPolicy
	tcpPort            PortPolicy
	trustProxyHeaders  bool
	trustedProxyCIDRs  []*net.IPNet
	mu                 sync.RWMutex
}

func NewRuntime(udpEnabled, tcpPortEnabled bool, trustProxyHeaders bool, rawTrustedProxyCIDRs string) (*Runtime, error) {
	runtime := &Runtime{
		approver:           NewApprover(),
		bpsManager:         NewBPSManager(),
		ipFilter:           NewIPFilter(),
		bannedIdentityKeys: make(map[string]struct{}),
	}
	runtime.udp.Set(udpEnabled, 0)
	runtime.tcpPort.Set(tcpPortEnabled, 0)
	if err := runtime.SetProxyTrust(trustProxyHeaders, rawTrustedProxyCIDRs); err != nil {
		return nil, err
	}
	return runtime, nil
}

func (r *Runtime) Approver() *Approver {
	return r.approver
}

func (r *Runtime) IPFilter() *IPFilter {
	return r.ipFilter
}

func (r *Runtime) BPSManager() *BPSManager {
	return r.bpsManager
}

func (r *Runtime) BanIdentity(key string) {
	if key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bannedIdentityKeys[key] = struct{}{}
}

func (r *Runtime) UnbanIdentity(key string) {
	if key == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.bannedIdentityKeys, key)
}

func (r *Runtime) IsIdentityBanned(key string) bool {
	if key == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.bannedIdentityKeys[key]
	return ok
}

func (r *Runtime) BannedIdentityKeys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.bannedIdentityKeys))
	for key := range r.bannedIdentityKeys {
		out = append(out, key)
	}
	return out
}

func (r *Runtime) SetBannedIdentityKeys(keys []string) {
	bannedIdentityKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		bannedIdentityKeys[key] = struct{}{}
	}

	r.mu.Lock()
	r.bannedIdentityKeys = bannedIdentityKeys
	r.mu.Unlock()
}

func (r *Runtime) EffectiveApproval(key string) bool {
	if r.approver == nil || key == "" {
		return true
	}
	if r.approver.Mode() == ModeAuto {
		return true
	}
	return r.approver.IsApproved(key)
}

func (r *Runtime) IsIdentityDenied(key string) bool {
	if r.approver == nil || key == "" {
		return false
	}
	return r.approver.IsDenied(key)
}

func (r *Runtime) IsIdentityRoutable(key string) bool {
	if r.IsIdentityBanned(key) || r.IsIdentityDenied(key) {
		return false
	}
	return r.EffectiveApproval(key)
}

func (r *Runtime) SetUDPPolicy(enabled bool, maxLeases int) {
	r.mu.Lock()
	r.udp.Set(enabled, maxLeases)
	r.mu.Unlock()
}

func (r *Runtime) IsUDPEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.udp.IsEnabled()
}

func (r *Runtime) UDPMaxLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.udp.MaxLeases()
}

func (r *Runtime) SetTCPPortPolicy(enabled bool, maxLeases int) {
	r.mu.Lock()
	r.tcpPort.Set(enabled, maxLeases)
	r.mu.Unlock()
}

func (r *Runtime) SetProxyTrust(trustProxyHeaders bool, rawTrustedProxyCIDRs string) error {
	if r == nil {
		return nil
	}
	trustedProxyCIDRs, err := utils.ParseCIDRs(rawTrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("parse trusted proxy cidrs: %w", err)
	}
	copied := append([]*net.IPNet(nil), trustedProxyCIDRs...)
	r.mu.Lock()
	r.trustProxyHeaders = trustProxyHeaders
	r.trustedProxyCIDRs = copied
	r.mu.Unlock()
	return nil
}

func (r *Runtime) IsTCPPortEnabled() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tcpPort.IsEnabled()
}

func (r *Runtime) TCPPortMaxLeases() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.tcpPort.MaxLeases()
}

func (r *Runtime) ForgetIdentity(key string) {
	if r.ipFilter != nil {
		r.ipFilter.RemoveIdentityIP(key)
	}
	if r.bpsManager != nil {
		r.bpsManager.DeleteIdentityBPS(key)
	}
}
