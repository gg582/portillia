package main

import "C"
import (
	"strings"

	"github.com/spruceid/siwe-go"
)

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

//export CreateSIWEMessage
func CreateSIWEMessage(cDomain, cAddress, cURI, cNonce, cStatement, cRequestID, cIssuedAt, cExpirationTime *C.char, cChainId C.int) *C.char {
	domain := C.GoString(cDomain)
	address := C.GoString(cAddress)
	uri := C.GoString(cURI)
	nonce := C.GoString(cNonce)
	statement := C.GoString(cStatement)
	requestID := C.GoString(cRequestID)
	issuedAt := C.GoString(cIssuedAt)
	expirationTime := C.GoString(cExpirationTime)
	chainId := int(cChainId)

	message, err := siwe.InitMessage(domain, address, uri, nonce, map[string]interface{}{
		"statement":      statement,
		"chainId":        chainId,
		"issuedAt":       issuedAt,
		"expirationTime": expirationTime,
		"requestId":      requestID,
	})
	if err != nil {
		return nil
	}
	return C.CString(message.String())
}
