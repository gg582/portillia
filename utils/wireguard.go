package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func NormalizeWireGuardPrivateKey(raw string) (string, error) {
	key, err := decodeWireGuardKey(raw)
	if err != nil {
		return "", err
	}
	clampWireGuardPrivateKey(&key)
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

func GenerateWireGuardPrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	clampWireGuardPrivateKey(&key)
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

func WireGuardPublicKeyFromPrivate(raw string) (string, error) {
	privateKey, err := decodeWireGuardKey(raw)
	if err != nil {
		return "", err
	}
	clampWireGuardPrivateKey(&privateKey)
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

func WireGuardListenPort(rawEndpoint string) (int, error) {
	endpoint := strings.TrimSpace(rawEndpoint)
	if endpoint == "" {
		return 0, errors.New("wireguard endpoint is required")
	}
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return 0, errors.New("wireguard endpoint must be host:port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return 0, errors.New("wireguard endpoint port is invalid")
	}
	return port, nil
}

func DeriveWireGuardOverlayIPv4(publicKey string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil {
		return "", errors.New("wireguard public key must be base64 encoded")
	}
	if len(decoded) != 32 {
		return "", errors.New("wireguard public key must be 32 bytes")
	}

	sum := sha256.Sum256(decoded)
	return netip.AddrFrom4([4]byte{
		100,
		64 + (sum[0] & 0x3f),
		sum[1],
		1 + (sum[2] % 254),
	}).String(), nil
}

func WireGuardKeyHex(raw string) (string, error) {
	key, err := decodeWireGuardKey(raw)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key[:]), nil
}

func decodeWireGuardKey(raw string) ([32]byte, error) {
	var key [32]byte
	value := strings.TrimSpace(raw)
	if value == "" {
		return key, errors.New("wireguard key is required")
	}

	var decoded []byte
	var err error
	if len(value) == 64 && !strings.Contains(value, "=") {
		decoded, err = hex.DecodeString(value)
	} else {
		decoded, err = base64.StdEncoding.DecodeString(value)
	}
	if err != nil {
		return key, errors.New("wireguard key must be base64 or hex encoded")
	}
	if len(decoded) != len(key) {
		return key, errors.New("wireguard key must be 32 bytes")
	}
	copy(key[:], decoded)
	return key, nil
}

func clampWireGuardPrivateKey(key *[32]byte) {
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
}

func ValidateWireGuardPublicKey(raw string) error {
	key := strings.TrimSpace(raw)
	if key == "" {
		return errors.New("wireguard_public_key is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.New("wireguard_public_key must be base64 encoded")
	}
	if len(decoded) != 32 {
		return errors.New("wireguard_public_key must be 32 bytes")
	}
	return nil
}

func ValidateWireGuardEndpoint(raw string) error {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return errors.New("wireguard_endpoint is required")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return errors.New("wireguard_endpoint must be host:port")
	}
	if strings.TrimSpace(host) == "" {
		return errors.New("wireguard_endpoint host is required")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum <= 0 || portNum > 65535 {
		return errors.New("wireguard_endpoint port is invalid")
	}
	return nil
}

func ValidateOverlayIPv4(raw string) error {
	ipText := strings.TrimSpace(raw)
	if ipText == "" {
		return errors.New("overlay_ipv4 is required")
	}
	ip := net.ParseIP(ipText)
	if ip == nil || ip.To4() == nil {
		return errors.New("overlay_ipv4 must be a valid IPv4 address")
	}
	return nil
}

func NormalizeOverlayCIDRs(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(inputs))
	out := make([]string, 0, len(inputs))
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		_, network, err := net.ParseCIDR(input)
		if err != nil {
			return nil, fmt.Errorf("invalid overlay cidr %q", input)
		}
		normalized := network.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}
