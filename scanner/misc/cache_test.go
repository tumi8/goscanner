package misc

import (
	"bytes"
	"crypto/x509"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"strings"
	"testing"
)

func Test_getId(t *testing.T) {

	cache := NewCertCache(GetSHA256)

	key := x509.Certificate{Raw: []byte("TEST")}

	id, isNew := cache.GetID(&key)

	if !isNew {
		t.Error("id was not new")
	}

	id2, isNew2 := cache.GetID(&key)

	if !isNew2 {
		t.Error("id2 was not new")
	}

	if id != id2 {
		t.Error("id1, and id2 arent the same ", id, id2)
	}

	cache.MarkOld(&key)

	id3, isNew3 := cache.GetID(&key)
	if isNew3 {
		t.Error("id3 was new")
	}

	if id != id3 {
		t.Error("id1, and id3 arent the same ", id, id2)
	}
}

func Test_callOrderErrorMsg(t *testing.T) {
	cache := NewCertCache(GetSHA256)

	key := x509.Certificate{Raw: []byte("TEST")}

	logger := log.Logger

	testWriter := bytes.NewBufferString("")
	log.Logger = zerolog.New(testWriter).With().Timestamp().Logger()

	cache.MarkOld(&key)

	if !strings.Contains(testWriter.String(), "MarkOld was called before GetID") {
		t.Error("No Error Msg produced")
	}
	log.Logger = logger
}
