package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

func Test_getNsIp(t *testing.T) {
	nsIp := &sync.Map{}
	ip, err := getNsIp(context.Background(), "xmdhs.com", nsIp)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(ip)

	nsIp.Range(func(key, value any) bool {
		fmt.Println(key, value)
		return true
	})

	getNsIp(context.Background(), "xmdhs.com", nsIp)
}
