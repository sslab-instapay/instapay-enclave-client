package main;

/*
#cgo CPPFLAGS: -I/home/xiaofo/sgxsdk/include -I./untrusted -I./include
#cgo LDFLAGS: -L. -ltee

#include "untrusted/app.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
	"reflect"
)

func main() {
	C.initialize_enclave()

	/* calling ecall_preset_account_w */
	owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	key := []C.uchar("e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd")
	C.ecall_preset_account_w(&owner[0], &key[0])


	/* calling ecall_create_channel_w */
	nonce := C.uint(0)
	owner = []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	receiver := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	amount := C.uint(1000000000000000000)
	SigLen := C.uint(0)

	var sig *C.uchar = C.ecall_onchain_payment(nonce, &owner[0], &receiver[0], amount, &SigLen)
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(sig)),
		Len:  int(SigLen),
		Cap:  int(SigLen),
	}

	s := *(*[]C.uchar)(unsafe.Pointer(&hdr))
	for i := C.uint(0); i < SigLen; i++ {
        fmt.Printf("%02x", s[i])
	}
	fmt.Println()

}