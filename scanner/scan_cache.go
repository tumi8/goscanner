package scanner

import (
	"github.com/syndtr/goleveldb/leveldb"
	"os"
)

type scanCache interface {
	contains(key []byte) bool
	put(key []byte) error
	finish()
}

type levelDbCache struct {
	db *leveldb.DB
	dbPath string
}

type simpleMapCache struct {
	mapCache map[string]map[string]struct{}
}

func (sm simpleMapCache) contains(key []byte) bool {
	cacheBytes := string(key)

	_, ok := sm.mapCache[cacheBytes[:1]]

	if !ok {
		sm.mapCache[cacheBytes[:1]] = make(map[string]struct{})
	}
	_, ok = sm.mapCache[cacheBytes[:1]][cacheBytes[1:]]
	return ok
}

func (sm simpleMapCache) finish() {}

func (sm simpleMapCache) put(key []byte) error {
	cacheBytes := string(key)

	_, ok := sm.mapCache[cacheBytes[:1]]

	if !ok {
		sm.mapCache[cacheBytes[:1]] = make(map[string]struct{})
	}

	sm.mapCache[cacheBytes[:1]][cacheBytes[1:]] = struct{}{}
	return nil
}

func (l levelDbCache) contains(key []byte) bool {
	val,_ := l.db.Get(key, nil)
	return val != nil
}

func (l levelDbCache) put(key []byte) error {
	return l.db.Put(key, nil, nil)
}

func (l levelDbCache) finish() {
	l.db.Close()
	os.RemoveAll(l.dbPath)
}