package misc

import (
	"crypto/x509"
	"github.com/rs/zerolog/log"
	"sync"
)

const highestBitU32 = uint32(1) << 31 // highest bit 1 rest zero. in binary: 1000...000

// Contains two relations
//    Certificate -> ID
//    Certificate -> Certificate is new
// Later is used to write Certificates to a file only once.
// This class is a bit more complicated to save RAM and to enable concurrent use of the methods,
// e.g. CertRelationResult uses the ID of a certificate before CertResult actually writes it into a file
type CertCache struct {
	cacheFunc func([]byte) []byte
	cache     map[string]map[string]uint32
	cacheLock sync.Mutex
}

func NewCertCache(cacheFunc func([]byte) []byte) *CertCache {
	tmpCacheFunc := cacheFunc
	if tmpCacheFunc == nil {
		tmpCacheFunc = func(bytes []byte) []byte {
			return bytes
		}
	}
	return &CertCache{
		cacheFunc: tmpCacheFunc,
		cache:     make(map[string]map[string]uint32),
	}
}

// Method is unsafe for concurrent use
func (c *CertCache) getIDUnsafe(key string) (certId SessionUID, certIsNew bool, createdNewId bool) {
	_, ok := c.cache[key[:1]]

	if !ok {
		c.cache[key[:1]] = make(map[string]uint32)
	}

	id, ok := c.cache[key[:1]][key[1:]]

	if !ok {
		id = uint32(GetSessionUID())
		c.cache[key[:1]][key[1:]] = id
	}
	// If the highest bit is 0, we have a new cert
	// Because of a uint the highest bit will be zero for IDs < 2^31, should be enough for out use case
	flag := id & highestBitU32
	isNew := flag == 0

	return SessionUID(id &^ highestBitU32), isNew, !ok
}

// returns the ID for a cert and whether this cert was not marked as old by MarkOld yet
func (c *CertCache) GetID(cert *x509.Certificate) (certId SessionUID, certIsNew bool) {
	cacheBytes := string(c.cacheFunc(cert.Raw))

	// We need a lock if we touch a go map
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()

	id, isNew, _ := c.getIDUnsafe(cacheBytes)
	return id, isNew
}

func (c *CertCache) MarkOld(cert *x509.Certificate) {
	cacheBytes := string(c.cacheFunc(cert.Raw))

	// We need a lock if we touch a go map
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()

	id, _, isNewId := c.getIDUnsafe(cacheBytes)
	if isNewId {
		log.Error().Str("Certificate Id", id.ToString()).Str("Certificate Subject", cert.Subject.String()).Msg("MarkOld was called before GetID. This means a certificate would be never written. Wrong call order?")
	}

	idRaw := uint32(id)

	newId := idRaw | highestBitU32 // Set the highest bit to 1 d

	c.cache[cacheBytes[:1]][cacheBytes[1:]] = newId
}
