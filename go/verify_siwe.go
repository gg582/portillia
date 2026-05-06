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
