package main

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

	/* calling ecall_register_account */
	owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	key := []C.uchar("e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd")
	C.ecall_register_account(&owner[0], &key[0])


	/* calling ecall_new_channel */
	nonce := C.uint(0)
	owner = []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	receiver := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	deposit := C.uint(8)
	SigLen := C.uint(0)

	var sig *C.uchar = C.ecall_new_channel(nonce, &owner[0], &receiver[0], deposit, &SigLen)
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


	/* calling ecall_event_create_channel */
    /*
                     id: 2                   id: 3
        A(0x7890...) -----> owner(0xd03a...) -----> B(0x0b41...)
    */	
	channel_id := C.uint(2)
	A := []C.uchar("78902c58006916201F65f52f7834e467877f0500")
	B := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	deposit = C.uint(5)
	C.ecall_event_create_channel(channel_id, &A[0], &owner[0], deposit)

	channel_id = C.uint(3)
	deposit = C.uint(9)
	C.ecall_event_create_channel(channel_id, &owner[0], &B[0], deposit)


	/* check balance */
	fmt.Printf("[BEFORE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(2)))
	fmt.Printf("[BEFORE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(3)))
	fmt.Println()


	/* calling ecall_receive_agreement_request */
	payment_num := C.uint(30)
	channel_ids := []C.uint{2, 3}
	amount := []C.int{4, -4}
	size := C.uint(2)
    C.ecall_receive_agreement_request(payment_num, &channel_ids[0], &amount[0], size);

	fmt.Printf("[PRE-UPDATE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(2)))
	fmt.Printf("[PRE-UPDATE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(3)))
	fmt.Println()


	/* calling ecall_receive_update_request */
	C.ecall_receive_update_request(payment_num, &channel_ids[0], &amount[0], size);

	fmt.Printf("[POST-UPDATE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(2)))
	fmt.Printf("[POST-UPDATE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(3)))
	fmt.Println()


	/* calling ecall_receive_payment_confirmation */
	C.ecall_receive_payment_confirmation(10);

	/* check balance */
	fmt.Printf("[AFTER] CHANNEL 2 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(2)))
	fmt.Printf("[AFTER] CHANNEL 3 BALANCE: %d\n", C.ecall_get_my_balance(C.uint(3)))
}