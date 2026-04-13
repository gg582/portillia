package discovery

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/gosuda/portal-tunnel/v2/utils"
)

// descriptorSignatureSize is the byte length of a recoverable secp256k1
// compact ECDSA signature: 1 byte recovery code + 32 byte R + 32 byte S.
const descriptorSignatureSize = 65

// ErrDescriptorUnsigned is returned when a descriptor that should carry a
// signature is missing one. Distinct from ErrDescriptorInvalidSignature so
// callers can differentiate "this peer never signed" from "this peer signed
// incorrectly or the payload was tampered with".
var (
	ErrDescriptorUnsigned         = errors.New("relay descriptor is not signed")
	ErrDescriptorInvalidSignature = errors.New("relay descriptor signature is invalid")
	ErrDescriptorAddressMismatch  = errors.New("relay descriptor address does not match recovered signing key")
	ErrDescriptorMissingAddress   = errors.New("relay descriptor address is required for signature verification")
)

// SignDescriptor returns a copy of desc with its Signature field populated by
// signing the canonical bytes with the supplied secp256k1 private key (hex
// encoded). The signature is recoverable, so verifiers do not need to know
// the public key out of band — they recover it from the signature and check
// it derives the descriptor's Address field.
//
// Mutable telemetry fields (Load, LoadScore, LastUpdated) are NOT covered by
// the signature, so callers may freely update them after signing without
// invalidating the signature.
func SignDescriptor(desc types.RelayDescriptor, privateKeyHex string) (types.RelayDescriptor, error) {
	privateKey, _, err := utils.ParseSecp256k1PrivateKeyHex(privateKeyHex, true)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("relay descriptor signing key: %w", err)
	}

	// Strip any pre-existing signature so re-signing is idempotent and the
	// canonical bytes never depend on what the signature happens to be.
	desc.Signature = ""

	// Both signer and verifier hash the post-normalization form so that
	// JSON round-trips and minor input variation (case, whitespace, etc.)
	// do not break signature verification.
	normalized, err := utils.NormalizeDescriptor(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("normalize relay descriptor for signing: %w", err)
	}
	if strings.TrimSpace(normalized.Address) == "" {
		return types.RelayDescriptor{}, ErrDescriptorMissingAddress
	}
	desc = normalized

	canonical, err := types.CanonicalBytes(desc)
	if err != nil {
		return types.RelayDescriptor{}, fmt.Errorf("canonicalize relay descriptor: %w", err)
	}
	digest := sha256.Sum256(canonical)
	// isCompressedKey=true matches the descriptor's Identity.PublicKey, which
	// is the compressed form of the public key throughout the codebase.
	signature := ecdsa.SignCompact(privateKey, digest[:], true)
	if len(signature) != descriptorSignatureSize {
		return types.RelayDescriptor{}, fmt.Errorf("unexpected compact signature length %d", len(signature))
	}

	desc.Signature = base64.StdEncoding.EncodeToString(signature)
	return desc, nil
}

// VerifyDescriptor checks the descriptor's signature against its canonical
// bytes and confirms that the recovered signing key corresponds to the
// descriptor's Address field. Returns the verified compressed public key hex
// on success so callers can use it as a stable identity for indexing.
//
// The descriptor argument is treated as read-only.
func VerifyDescriptor(desc types.RelayDescriptor) (publicKeyHex string, err error) {
	rawSignature := strings.TrimSpace(desc.Signature)
	if rawSignature == "" {
		return "", ErrDescriptorUnsigned
	}

	signature, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		return "", fmt.Errorf("%w: base64 decode: %w", ErrDescriptorInvalidSignature, err)
	}
	if len(signature) != descriptorSignatureSize {
		return "", fmt.Errorf("%w: unexpected signature length %d", ErrDescriptorInvalidSignature, len(signature))
	}

	// Strip the signature and normalize before recomputing canonical bytes
	// so signer and verifier agree on the exact byte sequence that was
	// hashed regardless of incidental input variation (case, whitespace,
	// JSON ordering of slice elements normalized in NormalizeDescriptor).
	unsignedCopy := desc
	unsignedCopy.Signature = ""
	normalized, err := utils.NormalizeDescriptor(unsignedCopy)
	if err != nil {
		return "", fmt.Errorf("%w: normalize: %w", ErrDescriptorInvalidSignature, err)
	}
	if strings.TrimSpace(normalized.Address) == "" {
		return "", ErrDescriptorMissingAddress
	}
	canonical, err := types.CanonicalBytes(normalized)
	if err != nil {
		return "", fmt.Errorf("canonicalize relay descriptor: %w", err)
	}
	digest := sha256.Sum256(canonical)

	publicKey, _, err := ecdsa.RecoverCompact(signature, digest[:])
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDescriptorInvalidSignature, err)
	}
	if publicKey == nil {
		return "", ErrDescriptorInvalidSignature
	}

	publicKeyHex = hex.EncodeToString(publicKey.SerializeCompressed())
	derivedAddress, err := utils.AddressFromCompressedPublicKeyHex(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("derive address from recovered key: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(derivedAddress), strings.TrimSpace(normalized.Address)) {
		return "", ErrDescriptorAddressMismatch
	}
	return publicKeyHex, nil
}
