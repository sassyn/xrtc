package webrtc

import (
	"sync"

	log "github.com/PeterXu/xrtc/logging"
	"github.com/PeterXu/xrtc/util"
)

type Cache struct {
	sync.RWMutex
	items map[string]*CacheItem
}

func NewCache() *Cache {
	return &Cache{items: make(map[string]*CacheItem)}
}

type CacheItem struct {
	data    interface{} // data
	misc    interface{} // others
	timeout uint32      // timeout, if 0 use default timeout
	utime   uint32      // update time (last access time)
	ctime   uint32      // create time
}

func NewCacheItem(data interface{}, timeout uint32) *CacheItem {
	return &CacheItem{data: data, timeout: timeout, utime: util.NowMs(), ctime: util.NowMs()}
}

func NewCacheItemEx(data interface{}, misc interface{}, timeout uint32) *CacheItem {
	return &CacheItem{data: data, misc: misc, timeout: timeout, utime: util.NowMs(), ctime: util.NowMs()}
}

func (h *Cache) Get(key string) *CacheItem {
	h.RLock()
	defer h.RUnlock()
	if i, ok := h.items[key]; ok {
		i.utime = util.NowMs()
		return i
	}
	return nil
}

func (h *Cache) Set(key string, item *CacheItem) {
	h.Lock()
	defer h.Unlock()
	item.utime = util.NowMs()
	h.items[key] = item
}

func (h *Cache) Update(key string) bool {
	h.Lock()
	defer h.Unlock()
	if i, ok := h.items[key]; ok {
		i.utime = util.NowMs()
		return true
	}
	return false
}

func (h *Cache) ClearTimeout() {
	// default 30s
	const kDefaultTimeout = 30 * 1000 // ms

	nowTime := util.NowMs()
	var desperated []string
	h.RLock()
	for k, v := range h.items {
		timeout := v.timeout
		if timeout == 0 {
			timeout = kDefaultTimeout
		}
		if nowTime >= v.utime+timeout {
			desperated = append(desperated, k)
		}
	}
	h.RUnlock()

	if len(desperated) > 0 {
		log.Println("[cache] clear timeout, size=", len(desperated))
		h.Lock()
		for index := range desperated {
			delete(h.items, desperated[index])
		}
		h.Unlock()
	}
}
