package webrtc

import (
	"sync"
	"time"

	"github.com/PeterXu/xrtc/log"
	"github.com/PeterXu/xrtc/util"
)

type Cache struct {
	sync.RWMutex
	items    map[string]*CacheItem
	exitTick chan bool
}

func NewCache() *Cache {
	c := &Cache{
		items:    make(map[string]*CacheItem),
		exitTick: make(chan bool),
	}
	go c.Run()
	return c
}

// default 30s
const kDefaultTimeout = 30 * 1000 // ms

type CacheItem struct {
	data    interface{} // data
	timeout uint32      // timeout, default(30s) if 0
	utime   uint32      // update time (last access time)
	ctime   uint32      // create time
}

func NewCacheItem(data interface{}) *CacheItem {
	return &CacheItem{data: data, timeout: 0, utime: util.NowMs(), ctime: util.NowMs()}
}

func NewCacheItemEx(data interface{}, timeout uint32) *CacheItem {
	return &CacheItem{data: data, timeout: timeout, utime: util.NowMs(), ctime: util.NowMs()}
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

func (h *Cache) Close() {
	h.exitTick <- true
}

func (h *Cache) Run() {
	tickChan := time.NewTicker(time.Second * 30).C
	for {
		select {
		case <-h.exitTick:
			close(h.exitTick)
			log.Println("[cache] cache exit...")
			return
		case <-tickChan:
			h.ClearTimeout()
		}
	}
}
