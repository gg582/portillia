/* Portal bridge FFI header.
 * This file is hand-maintained; it must match the exported symbols in
 * rust_bridge/src/lib.rs and rust_bridge/src/utils.rs.
 */

#ifndef PORTAL_BRIDGE_H
#define PORTAL_BRIDGE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Overlay / HopMux (Phase 2 Rust runtime) ---------- */
extern int OverlayInit(const char* cPrivateKey, const char* cPublicKey, int cListenPort);
extern int OverlaySyncJSON(const char* cRelaysJSON);
extern int HopMuxOpenStreamFD(const char* cOverlayIPv4, const char* cToken);
extern int HopMuxAcceptFD(char** cTokenOut);

/* ---------- Memory ---------- */
extern void FreeCString(char* s);
extern void FreeRustString(char* s);

/* ---------- Descriptor ---------- */
extern char* SignDescriptorJSON(const char* cDescJSON, const char* cPrivateKeyHex);
extern char* VerifyDescriptorJSON(const char* cDescJSON);

/* ---------- Hop Route ---------- */
extern char* SignHopRouteJSON(const char* cRouteJSON, const char* cMethod, const char* cIdentityJSON, long long int cExpiresAtUnix);
extern char* VerifyHopRouteJSON(const char* cRouteJSON, const char* cMethod);

/* ---------- Lease Token ---------- */
extern char* IssueLeaseTokenJSON(const char* cPrivateKeyHex, const char* cKeyID, const char* cIssuer, const char* cIdentityJSON, int cTTLSeconds);
extern char* VerifyLeaseTokenJSON(const char* cToken, const char* cPublicKeyHex, const char* cIssuer, long long int cNowUnix);

/* ---------- Discovery helpers ---------- */
extern char* DiscoveryPollJSON(const char* cURL);
extern char* DiscoveryAnnounceJSON(const char* cURL, const char* cDescriptorJSON);

/* ---------- ECH helpers ---------- */
extern char* ECHMaterialsJSON(const char* cSeed, const char* cPublicName);
extern char* NormalizeECHConfigListJSON(const char* cConfigListB64);

/* ---------- SIWE ---------- */
extern int VerifySIWESignature(const char* cMessage, const char* cSignature, const char* cExpectedAddress);
extern char* VerifySIWEMessageJSON(const char* cMessage, const char* cSignature, const char* cDomain, const char* cNonce, long long int cNowUnix);
extern char* CreateSIWEMessage(const char* cDomain, const char* cAddress, const char* cURI, const char* cNonce, const char* cStatement, const char* cRequestId, const char* cIssuedAt, const char* cExpirationTime, int cChainId);

/* ---------- Compatibility helpers ---------- */
extern char* HostnameHashJSON(const char* cHostname);
extern char* DeriveTokenJSON(const char* cIdentityJSON, const char* cPartsJSON);
extern char* PortalRootHostJSON(const char* cRelayURL);
extern char* LeaseHostnameJSON(const char* cName, const char* cRootHost);
extern char* NormalizeDNSLabelJSON(const char* cLabel);
extern char* StreamLeaseECHJSON(const char* cIdentityJSON, const char* cPublicHostname, const char* cRootHost);
extern char* StreamLeaseExtrasJSON(const char* cIdentityJSON, const char* cRelayURL);

#ifdef __cplusplus
}
#endif

#endif /* PORTAL_BRIDGE_H */
