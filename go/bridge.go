package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/types"
	"github.com/spruceid/siwe-go"
)

//export FreeCString
func FreeCString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

// ---------- SIWE ----------

//export VerifySIWESignature
func VerifySIWESignature(cMessage, cSignature, cExpectedAddress *C.char) C.int {
	message := C.GoString(cMessage)
	signature := C.GoString(cSignature)
	expectedAddress := C.GoString(cExpectedAddress)

	msg, err := siwe.ParseMessage(message)
	if err != nil {
		return 0
	}
	if !strings.EqualFold(msg.GetAddress().Hex(), expectedAddress) {
		return 0
	}
	_, err = msg.VerifyEIP191(signature)
	if err != nil {
		return 0
	}
	return 1
}

// ---------- Descriptor ----------

//export SignDescriptorJSON
func SignDescriptorJSON(cDescJSON, cPrivateKeyHex *C.char) *C.char {
	var desc types.RelayDescriptor
	if err := json.Unmarshal([]byte(C.GoString(cDescJSON)), &desc); err != nil {
		return nil
	}
	signed, err := auth.SignRelayDescriptor(desc, C.GoString(cPrivateKeyHex))
	if err != nil {
		return nil
	}
	b, err := json.Marshal(signed)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

//export VerifyDescriptorJSON
func VerifyDescriptorJSON(cDescJSON *C.char) *C.char {
	var desc types.RelayDescriptor
	if err := json.Unmarshal([]byte(C.GoString(cDescJSON)), &desc); err != nil {
		return nil
	}
	verified, err := auth.VerifyRelayDescriptor(desc)
	if err != nil {
		return nil
	}
	b, err := json.Marshal(verified)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

// ---------- Hop Route ----------

//export SignHopRouteJSON
func SignHopRouteJSON(cRouteJSON, cMethod, cIdentityJSON *C.char, cExpiresAtUnix C.longlong) *C.char {
	var route types.HopRoute
	if err := json.Unmarshal([]byte(C.GoString(cRouteJSON)), &route); err != nil {
		return nil
	}
	var identity types.Identity
	if err := json.Unmarshal([]byte(C.GoString(cIdentityJSON)), &identity); err != nil {
		return nil
	}
	expiresAt := time.Unix(int64(cExpiresAtUnix), 0).UTC()
	signed, err := auth.SignHopRoute(C.GoString(cMethod), route, identity, expiresAt)
	if err != nil {
		return nil
	}
	b, err := json.Marshal(signed)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

//export VerifyHopRouteJSON
func VerifyHopRouteJSON(cRouteJSON, cMethod *C.char) *C.char {
	var route types.HopRoute
	if err := json.Unmarshal([]byte(C.GoString(cRouteJSON)), &route); err != nil {
		return nil
	}
	verified, err := auth.VerifyHopRoute(C.GoString(cMethod), route)
	if err != nil {
		return nil
	}
	b, err := json.Marshal(verified)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

// ---------- Lease Token ----------

//export IssueLeaseTokenJSON
func IssueLeaseTokenJSON(cPrivateKeyHex, cKeyID, cIssuer, cIdentityJSON *C.char, cTTLSeconds C.int) *C.char {
	var identity types.Identity
	if err := json.Unmarshal([]byte(C.GoString(cIdentityJSON)), &identity); err != nil {
		return nil
	}
	token, claims, err := auth.IssueLeaseAccessToken(
		C.GoString(cPrivateKeyHex),
		C.GoString(cKeyID),
		C.GoString(cIssuer),
		identity,
		time.Duration(int(cTTLSeconds))*time.Second,
	)
	if err != nil {
		return nil
	}
	out := struct {
		Token  string                       `json:"token"`
		Claims auth.LeaseAccessTokenClaims `json:"claims"`
	}{
		Token:  token,
		Claims: claims,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

//export VerifyLeaseTokenJSON
func VerifyLeaseTokenJSON(cToken, cPublicKeyHex, cIssuer *C.char, cNowUnix C.longlong) *C.char {
	now := time.Unix(int64(cNowUnix), 0)
	claims, err := auth.VerifyLeaseAccessToken(
		C.GoString(cToken),
		C.GoString(cPublicKeyHex),
		C.GoString(cIssuer),
		now,
	)
	if err != nil {
		return nil
	}
	b, err := json.Marshal(claims)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

// ---------- Discovery helpers (minimal JSON bridge) ----------

//export DiscoveryPollJSON
func DiscoveryPollJSON(cURL *C.char) *C.char {
	url := C.GoString(cURL)
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return C.CString(string(body))
}

//export DiscoveryAnnounceJSON
func DiscoveryAnnounceJSON(cURL, cDescriptorJSON *C.char) *C.char {
	url := C.GoString(cURL)
	body := strings.NewReader(C.GoString(cDescriptorJSON))
	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return C.CString(string(respBody))
}

func main() {}
