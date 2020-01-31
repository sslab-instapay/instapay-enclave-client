package main

/*
#cgo CPPFLAGS: -I/home/xiaofo/sgxsdk/include -I./untrusted -I./include
#cgo LDFLAGS: -L. -ltee

#include "untrusted/app.h"
*/
import "C"

import(
	"fmt"
)

func main(){

	channelIds := make([]int, 10)
	amounts := make([]int, 10)
	var channelSlice []C.uint

	for i := range channelIds{
		channelSlice = append(channelSlice, C.uint(i))
	}

	var amountSlice []C.int

	for i := range amounts{
		amountSlice = append(amountSlice, C.int(i))
	}
	fmt.Println(len(amounts))
	fmt.Println(len(channelSlice))
}