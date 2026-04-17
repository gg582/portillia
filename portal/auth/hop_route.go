package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

var ErrHopRouteSignatureInvalid = errors.New("hop route signature is invalid")

func SignHopRoute(method string, route types.HopRoute, identity types.Identity, expiresAt time.Time) (types.HopRoute, error) {
	route.ExpiresAt = expiresAt.UTC()
	route.Signature = ""
	route.OwnerPublicKey = ""

	route, err := normalizeHopRoute(route, false)
	if err != nil {
		return types.HopRoute{}, err
	}
	ownerScope := struct {
		RelayURL      string `json:"relay_url"`
		MatchHostname string `json:"match_hostname"`
		MatchToken    string `json:"match_token"`
	}{
		RelayURL:      route.RelayURL,
		MatchHostname: route.MatchHostname,
		MatchToken:    route.MatchToken,
	}
	encodedOwnerScope, err := json.Marshal(ownerScope)
	if err != nil {
		return types.HopRoute{}, err
	}
	ownerToken, err := identity.DeriveToken("hop-owner:" + string(encodedOwnerScope) + ":0")
	if err != nil {
		return types.HopRoute{}, err
	}
	ownerSeed := sha256.Sum256([]byte(ownerToken))
	owner, err := utils.ResolveSecp256k1Identity(hex.EncodeToString(ownerSeed[:]))
	if err != nil {
		return types.HopRoute{}, err
	}
	route.OwnerPublicKey = owner.PublicKey
	payload, err := types.HopRouteBytes(method, route)
	if err != nil {
		return types.HopRoute{}, err
	}
	route.Signature, err = utils.SignSHA256Secp256k1DER(payload, owner.PrivateKey)
	if err != nil {
		return types.HopRoute{}, err
	}
	return route, nil
}

func VerifyHopRoute(method string, route types.HopRoute) (types.HopRoute, error) {
	signature := strings.TrimSpace(route.Signature)
	route.Signature = ""

	route, err := normalizeHopRoute(route, true)
	if err != nil {
		return types.HopRoute{}, err
	}
	payload, err := types.HopRouteBytes(method, route)
	if err != nil {
		return types.HopRoute{}, err
	}
	if err := utils.VerifySHA256Secp256k1DER(payload, route.OwnerPublicKey, signature); err != nil {
		return types.HopRoute{}, ErrHopRouteSignatureInvalid
	}
	route.Signature = signature
	return route, nil
}

func normalizeHopRoute(route types.HopRoute, requireOwner bool) (types.HopRoute, error) {
	ownerPublicKey := strings.ToLower(utils.TrimHexPrefix(strings.TrimSpace(route.OwnerPublicKey)))
	if ownerPublicKey != "" {
		if _, err := utils.ParseSecp256k1PublicKeyHex(ownerPublicKey); err != nil {
			return types.HopRoute{}, fmt.Errorf("hop route owner public key: %w", err)
		}
	} else if requireOwner {
		return types.HopRoute{}, errors.New("hop route owner public key is required")
	}

	relayURL, err := utils.NormalizeRelayURL(route.RelayURL)
	if err != nil {
		return types.HopRoute{}, fmt.Errorf("hop relay url: %w", err)
	}

	route.OwnerPublicKey = ownerPublicKey
	route.RelayURL = relayURL
	route.MatchHostname = utils.NormalizeHostname(route.MatchHostname)
	route.MatchToken = strings.TrimSpace(route.MatchToken)
	route.ForwardToken = strings.TrimSpace(route.ForwardToken)
	route.ExpiresAt = route.ExpiresAt.UTC()
	route.Signature = strings.TrimSpace(route.Signature)
	return route, nil
}
