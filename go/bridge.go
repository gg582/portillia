package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gosuda/portal-tunnel/v2/portal/auth"
	"github.com/gosuda/portal-tunnel/v2/portal/discovery"
	"github.com/gosuda/portal-tunnel/v2/portal/overlay"
	"github.com/gosuda/portal-tunnel/v2/types"
)

var (
	globalOverlay *overlay.Overlay
	globalHopMux  *overlay.HopMux
)

func bridgeConnToFD(conn net.Conn) (int, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, err
	}
	go func() {
		defer syscall.Close(fds[0])
		defer conn.Close()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					if _, werr := syscall.Write(fds[0], buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for {
				n, err := syscall.Read(fds[0], buf)
				if n > 0 {
					if _, werr := conn.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		wg.Wait()
	}()
	return fds[1], nil
}

//export OverlayInit
func OverlayInit(cPrivateKey, cPublicKey *C.char, cListenPort C.int) C.int {
	cfg := overlay.Config{
		PrivateKey: C.GoString(cPrivateKey),
		PublicKey:  C.GoString(cPublicKey),
		ListenPort: int(cListenPort),
	}
	var err error
	globalOverlay, err = overlay.NewOverlay(cfg, nil)
	if err != nil {
		return -1
	}
	globalHopMux, err = overlay.NewHopMux(globalOverlay)
	if err != nil {
		return -1
	}
	go func() {
		if err := globalOverlay.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			// Log expected errors silently
		}
	}()
	go func() {
		if err := globalHopMux.Serve(context.Background()); err != nil && !errors.Is(err, net.ErrClosed) {
			// Log expected errors silently
		}
	}()
	return 0
}

//export OverlaySyncJSON
func OverlaySyncJSON(cRelaysJSON *C.char) C.int {
	if globalOverlay == nil {
		return -1
	}
	var relays []discovery.RelayState
	if err := json.Unmarshal([]byte(C.GoString(cRelaysJSON)), &relays); err != nil {
		return -1
	}
	if err := globalOverlay.Sync(relays); err != nil {
		return -1
	}
	return 0
}

//export HopMuxOpenStreamFD
func HopMuxOpenStreamFD(cOverlayIPv4, cToken *C.char) C.int {
	if globalHopMux == nil {
		return -1
	}
	conn, err := globalHopMux.OpenStream(context.Background(), C.GoString(cOverlayIPv4), C.GoString(cToken))
	if err != nil {
		return -1
	}
	fd, err := bridgeConnToFD(conn)
	if err != nil {
		return -1
	}
	return C.int(fd)
}

//export HopMuxAcceptFD
func HopMuxAcceptFD(cTokenOut **C.char) C.int {
	if globalHopMux == nil {
		return -1
	}
	stream, err := globalHopMux.Accept(context.Background())
	if err != nil {
		return -1
	}
	fd, err := bridgeConnToFD(stream.Conn)
	if err != nil {
		return -1
	}
	*cTokenOut = C.CString(stream.Token)
	return C.int(fd)
}

//export FreeCString
func FreeCString(s *C.char) {
	C.free(unsafe.Pointer(s))
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
