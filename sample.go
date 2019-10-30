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

	/* calling ecall_preset_account_w */
	owner := []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	key := []C.uchar("e113ff405699b7779fbe278ee237f2988b1e6769d586d8803860d49f28359fbd")
	C.ecall_preset_account_w(&owner[0], &key[0])


	/* calling ecall_create_channel_w */
	nonce := C.uint(0)
	owner = []C.uchar("D03A2CC08755eC7D75887f0997195654b928893e")
	receiver := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	deposit := C.uint(8)
	SigLen := C.uint(0)

	var sig *C.uchar = C.ecall_create_channel_w(nonce, &owner[0], &receiver[0], deposit, &SigLen)
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


	/* calling ecall_receive_create_channel_w */
    /*
                     id: 2                   id: 3
        A(0x7890...) -----> owner(0xd03a...) -----> B(0x0b41...)
    */	
	channel_id := C.uint(2)
	A := []C.uchar("78902c58006916201F65f52f7834e467877f0500")
	B := []C.uchar("0b4161ad4f49781a821c308d672e6c669139843c")
	deposit = C.uint(5)
	C.ecall_receive_create_channel_w(channel_id, &A[0], &owner[0], deposit)

	channel_id = C.uint(3)
	deposit = C.uint(9)
	C.ecall_receive_create_channel_w(channel_id, &owner[0], &B[0], deposit)


	fmt.Printf("[BEFORE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	fmt.Printf("[BEFORE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
	fmt.Println()


	/*
		calling ecall_go_pre_update_w
		received agreement request
	*/
	payment_num := C.uint(30)
	channel_ids := []C.uint{2, 3}
	amount := []C.int{4, -4}
	size := C.uint(2)
	C.ecall_go_pre_update_w(payment_num, &channel_ids[0], &amount[0], size);

	fmt.Printf("[PRE-UPDATE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	fmt.Printf("[PRE-UPDATE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
	fmt.Println()


	/* 
		calling ecall_go_post_update_w
		received update request
	*/
	C.ecall_go_post_update_w(payment_num, &channel_ids[0], &amount[0], size);

	fmt.Printf("[POST-UPDATE] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	fmt.Printf("[POST-UPDATE] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
	fmt.Println()


	/* 
		calling ecall_go_idle_w
		received payment confirmation
	*/
	C.ecall_go_idle_w(10);

	fmt.Printf("[AFTER] CHANNEL 2 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(2)))
	fmt.Printf("[AFTER] CHANNEL 3 BALANCE: %d\n", C.ecall_get_balance_w(C.uint(3)))
}