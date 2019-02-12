// Based-on https://github.com/xhs/gosctp
package nnet

/*
#cgo CFLAGS: -DINET -DINET6 -Wno-deprecated
#cgo LDFLAGS: -lusrsctp -lpthread

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <usrsctp.h>


// The highest stream ID (Sid) that SCTP allows, and the number of streams we
// tell SCTP we're going to use.
#define kMaxSctpSid     1023

// This is the default SCTP port to use. It is passed along the wire and the
// connectee and connector must be using the same port. It is not related to the
// ports at the IP level. (Corresponds to: sockaddr_conn.sconn_port in usrsctp.h)
#define kSctpDefaultPort 5000

// http://tools.ietf.org/html/rfc4960#section-14.4
// The value is not used by SCTP itself. It indicates the protocol running
// on top of SCTP.
enum {
    PPID_NONE = 0,  // No protocol is specified.
    PPID_CONTROL = 50,
    PPID_BINARY_PARTIAL = 52,
    PPID_BINARY_LAST = 53,
    PPID_TEXT_PARTIAL = 54,
    PPID_TEXT_LAST = 51
};

static int g_sctp_ref = 0;

typedef struct {
  struct socket *sock;
  void *udata;
} sctp_transport;

extern void go_sctp_data_ready_cb(sctp_transport *sctp, void *data, size_t len);

static int sctp_data_ready_cb(void *addr, void *data, size_t len, uint8_t tos, uint8_t set_df) {
  go_sctp_data_ready_cb((sctp_transport *)addr, data, len);
  return 0;
}

extern void go_sctp_data_received_cb(sctp_transport *sctp, void *data, size_t len, int sid, int ppid);
extern void go_sctp_notification_received_cb(sctp_transport *sctp, void *data, size_t len);

static int sctp_data_received_cb(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t len, struct sctp_rcvinfo recv_info, int flags, void *udata) {
  sctp_transport *sctp = (sctp_transport *)udata;
  if (flags & MSG_NOTIFICATION)
    go_sctp_notification_received_cb(sctp, data, len);
  else
    go_sctp_data_received_cb(sctp, data, len, recv_info.rcv_sid, ntohl(recv_info.rcv_ppid));
  free(data);
  return 0;
}

static void debug_sctp_printf(const char *format, ...) {
  char s[255];
  va_list ap;
  va_start(ap, format);
  vsnprintf(s, sizeof(s), format, ap);
  printf("SCTP: %s\n", s);
  va_end(ap);
}

static sctp_transport *new_sctp_transport(int port, void *udata) {
  sctp_transport *sctp = (sctp_transport *)calloc(1, sizeof *sctp);
  if (sctp == NULL)
    return NULL;
  sctp->sock = NULL;
  sctp->udata = udata;

  if (g_sctp_ref == 0) {
    usrsctp_init(0, sctp_data_ready_cb, debug_sctp_printf);

    // To turn on/off detailed SCTP debugging.
    //usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);

    usrsctp_sysctl_set_sctp_ecn_enable(0);

    // Add a blackhole sysctl. Setting it to 1 results in no ABORTs
    // being sent in response to INITs, setting it to 2 results
    // in no ABORTs being sent for received OOTB packets.
    // This is similar to the TCP sysctl.
    // usrsctp_sysctl_set_sctp_blackhole(2);

    // Set the number of default outgoing streams.
    usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(kMaxSctpSid);
  }
  g_sctp_ref++;

  usrsctp_register_address(sctp);
  return sctp;
}

static bool open_sctp_socket(sctp_transport *sctp, int port) {
  if (!sctp || sctp->sock)
    return false;

  struct socket *s = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                                    sctp_data_received_cb, NULL, 0, sctp);
  if (s == NULL)
    return false;

  // Make the socket non-blocking
  //if (usrsctp_set_non_blocking(s, 1) < 0)
  //  return false;

  // This ensures that the usrsctp close call deletes the association. This
  // prevents usrsctp from calling OnSctpOutboundPacket with references to
  // this class as the address.
  struct linger lopt;
  lopt.l_onoff = 1;
  lopt.l_linger = 0;
  if (usrsctp_setsockopt(s, SOL_SOCKET, SO_LINGER, &lopt, sizeof lopt))
    return false;

  //struct sctp_paddrparams addr_param;
  //memset(&addr_param, 0, sizeof addr_param);
  //addr_param.spp_flags = SPP_PMTUD_DISABLE;
  //addr_param.spp_pathmtu = 1200;
  //if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &addr_param, sizeof addr_param))
  //  return false;

  // Enable stream ID resets.
  struct sctp_assoc_value av;
  av.assoc_id = SCTP_ALL_ASSOC;
  av.assoc_value = 1;
  if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, sizeof av))
    return false;

  // Nagle.
  uint32_t nodelay = 1;
  if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof nodelay))
    return false;

  // TODO:Subscribe to SCTP event notifications.

  //struct sctp_initmsg init_msg;
  //memset(&init_msg, 0, sizeof init_msg);
  //init_msg.sinit_num_ostreams = 1024;
  //init_msg.sinit_max_instreams = 1023;
  //if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof init_msg))
  //  return false;

  sctp->sock = s;
  return true;
}

static void release_usrsctp() {
  if (--g_sctp_ref <= 0) {
    g_sctp_ref = 0;

    // usrsctp_finish() may fail if it's called too soon after the channels are
    // closed. Wait and try again until it succeeds for up to 3 seconds.
    for (size_t i = 0; i < 300; ++i) {
      if(usrsctp_finish() == 0) break;
      usleep(10);
    }
  }
}

static ssize_t send_sctp2(sctp_transport *sctp,
                         void *data, size_t len, uint16_t sid, uint32_t ppid, bool ordered)
{
  struct sctp_sendv_spa spa = {0};
  spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
  spa.sendv_sndinfo.snd_sid = sid;
  spa.sendv_sndinfo.snd_ppid = htonl(ppid);

  // Ordered implies reliable.
  if (!ordered) {
    spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
    spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
    spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
    spa.sendv_prinfo.pr_value = 0;
  }

  // We don't fragment.
  return usrsctp_sendv(sctp->sock, data, len, NULL, 0,
                       &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
}

static ssize_t send_sctp(sctp_transport *sctp,
                         void *data, size_t len, uint16_t sid, uint32_t ppid)
{
  struct sctp_sndinfo info;
  memset(&info, 0, sizeof info);
  info.snd_sid = sid;
  info.snd_flags = SCTP_EOR;
  info.snd_ppid = htonl(ppid);
  return usrsctp_sendv(sctp->sock, data, len, NULL, 0,
                       &info, sizeof info, SCTP_SENDV_SNDINFO, 0);
}

static struct sockaddr_conn sctp_sockaddr(int port, void *udata) {
  struct sockaddr_conn sconn = {0};
  sconn.sconn_family = AF_CONN;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  sconn.sconn_len = sizeof(sconn);
#endif
  // Note: conversion from int to uint16_t happens here.
  sconn.sconn_port = htons(port);
  sconn.sconn_addr = udata;
  return sconn;
}

static int connect_sctp(sctp_transport *sctp, int port) {
  struct sockaddr_conn local_sconn = sctp_sockaddr(port, (void *)sctp);
  if (usrsctp_bind(sctp->sock, (struct sockaddr *)&local_sconn, sizeof local_sconn) < 0)
    return -1;

  struct sockaddr_conn remote_sconn = sctp_sockaddr(port, (void *)sctp);
  if (usrsctp_connect(sctp->sock, (struct sockaddr *)&remote_sconn, sizeof remote_sconn) < 0)
    return -1;

  return 0;
}

static int accept_sctp(sctp_transport *sctp, int port) {
  struct sockaddr_conn sconn = sctp_sockaddr(port, (void *)sctp);
  usrsctp_listen(sctp->sock, 1);
  socklen_t len = sizeof sconn;
  struct socket *s = usrsctp_accept(sctp->sock, (struct sockaddr *)&sconn, &len);
  if (s) {
    struct socket *t = sctp->sock;
    sctp->sock = s;
    usrsctp_close(t);
    return 0;
  }

  return -1;
}
*/
import "C"

import (
	"errors"
	"sync"
	"unsafe"
)

type SctpData struct {
	Sid, Ppid int
	Data      []byte
}

type SctpTransport struct {
	sctp          *C.sctp_transport
	ready         bool
	Port          int
	BufferChannel chan []byte
	DataChannel   chan *SctpData
	mtx           sync.Mutex
}

func NewTransport(port int) (*SctpTransport, error) {
	sctp := C.new_sctp_transport(C.int(port), nil)
	if sctp == nil {
		return nil, errors.New("fail to create SCTP transport")
	}
	s := &SctpTransport{sctp: sctp, ready: true, Port: port}
	s.BufferChannel = make(chan []byte, 16)
	s.DataChannel = make(chan *SctpData, 16)
	sctp.udata = unsafe.Pointer(s)
	return s, nil
}

func (s *SctpTransport) Open() bool {
	bret := C.open_sctp_socket(s.sctp, C.int(s.Port))
	return bool(bret)
}

func (s *SctpTransport) Destroy() {
	C.usrsctp_close(s.sctp.sock)
	C.usrsctp_deregister_address(unsafe.Pointer(s.sctp))
	C.free(unsafe.Pointer(s.sctp))
	C.release_usrsctp()
}

//export go_sctp_data_ready_cb
func go_sctp_data_ready_cb(sctp *C.sctp_transport, data unsafe.Pointer, length C.size_t) {
	s := (*SctpTransport)(sctp.udata)
	b := C.GoBytes(data, C.int(length))
	s.BufferChannel <- b
}

//export go_sctp_data_received_cb
func go_sctp_data_received_cb(sctp *C.sctp_transport, data unsafe.Pointer, length C.size_t, sid, ppid C.int) {
	s := (*SctpTransport)(sctp.udata)
	b := C.GoBytes(data, C.int(length))
	d := &SctpData{int(sid), int(ppid), b}
	s.DataChannel <- d
}

//export go_sctp_notification_received_cb
func go_sctp_notification_received_cb(sctp *C.sctp_transport, data unsafe.Pointer, length C.size_t) {
	// TODO: add interested events
}

func (s *SctpTransport) Feed(data []byte) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	C.usrsctp_conninput(unsafe.Pointer(s.sctp), unsafe.Pointer(&data[0]), C.size_t(len(data)), 0)
}

func (s *SctpTransport) Send2(data []byte, sid, ppid int) (int, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	rv := C.send_sctp2(s.sctp, unsafe.Pointer(&data[0]), C.size_t(len(data)), C.uint16_t(sid), C.uint32_t(ppid), true)
	if rv < 0 {
		return 0, errors.New("fail to send SCTP data")
	}
	return int(rv), nil
}

func (s *SctpTransport) Send(data []byte, sid, ppid int) (int, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	rv := C.send_sctp(s.sctp, unsafe.Pointer(&data[0]), C.size_t(len(data)), C.uint16_t(sid), C.uint32_t(ppid))
	if rv < 0 {
		return 0, errors.New("fail to send SCTP data")
	}
	return int(rv), nil
}

func (s *SctpTransport) Connect(port int) error {
	if !s.ready {
		rv := C.connect_sctp(s.sctp, C.int(port))
		if rv < 0 {
			return errors.New("fail to connect SCTP transport")
		}
	}
	return nil
}

func (s *SctpTransport) Accept() error {
	if !s.ready {
		rv := C.accept_sctp(s.sctp, C.int(s.Port))
		if rv < 0 {
			return errors.New("fail to accept SCTP transport")
		}
	}
	return nil
}
