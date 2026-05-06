package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"strings"

	siwe "github.com/spruceid/siwe-go"
)

//export PortilliaGoSiweVerify
func PortilliaGoSiweVerify(message *C.char, signature *C.char, expectedAddress *C.char) (result C.int) {
	defer func() {
		if recover() != nil {
			result = 0
		}
	}()

	if message == nil || signature == nil || expectedAddress == nil {
		return 0
	}

	parsed, err := siwe.ParseMessage(C.GoString(message))
	if err != nil {
		return 0
	}

	expected := C.GoString(expectedAddress)
	if strings.HasPrefix(strings.ToLower(expected), "0x") {
		expected = expected[2:]
	}
	actual := parsed.GetAddress().Hex()
	if strings.HasPrefix(strings.ToLower(actual), "0x") {
		actual = actual[2:]
	}
	if !strings.EqualFold(actual, expected) {
		return 0
	}

	if _, err := parsed.VerifyEIP191(C.GoString(signature)); err != nil {
		return 0
	}
	return 1
}

func main() {}
