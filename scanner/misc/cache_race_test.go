//go:build !race
// +build !race

package misc

import (
	"crypto/x509"
	"math/rand"
	"strconv"
	"sync"
	"testing"
	"time"
)

func Test_concurrentUse(t *testing.T) {
	cache := NewCertCache(GetSHA1)
	wg := sync.WaitGroup{}
	numberOfGoRoutines := 400
	wg.Add(numberOfGoRoutines)

	timeout := time.After(time.Minute)
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	for i := 0; i < numberOfGoRoutines; i++ {
		go runConcurrentTest(&wg, cache)
	}

	select {
	case <-timeout:
		t.Fatal("Test didn't finish in time")
	case <-done:
	}
}

func runConcurrentTest(wg *sync.WaitGroup, cache *CertCache) {
	for i := 1; i < 10000; i++ {
		randomInt := rand.Int() % i
		key := x509.Certificate{Raw: []byte(strconv.Itoa(randomInt))}

		_, _ = cache.GetID(&key)
		if randomInt%3 == 0 {
			cache.MarkOld(&key)
		}
		time.Sleep(time.Nanosecond)
	}
	wg.Done()
}
