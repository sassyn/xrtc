# xRTC

***xRTC*** is an eXtendable WebRTC proxy, for REST-based WebRTC server.

- [x] Serve many WebRTC clients on one ICE port at the same time.
- [x] Serve as HTTP/WebSocket Reverse Proxy(`HTTP-RP`) .
- [x] Serve HTTP/HTTPS/WS/WSS/ICE-TCP on one TCP port at the same time.
- [x] Serve as HTTP static server.
- [x] Serve as an extendable node of WebRTC server.
- [x] Support most features of [Janus WebRTC server](https://github.com/meetecho/janus-gateway).



<br>

## 1. Cases

### 1). Direct cases

```
WebRTC client A   <---HTTP/WS--->  WebRTC server(Janus/..)
WebRTC client B   <---HTTP/WS--->  WebRTC server(Janus/..)
WebRTC client C   <---HTTP/WS--->  WebRTC server(Janus/..)

WebRTC client A   <---ICE port0--->  WebRTC server(Janus/..)
WebRTC client B   <---ICE port1--->  WebRTC server(Janus/..)
WebRTC client C   <---ICE port2--->  WebRTC server(Janus/..)
```

The clients must connect to the same WebRTC server for interacting with each other.

And also the WebRTC server(Janus) need to use different ports for different clients.

However, most servers only provide limited ports for security.


### 2). xRTC cases

```
WebRTC client A   <--HTTP-RP-->   xRTC0(reverse porxy)   <--HTTP-RP-->  WebRTC server
WebRTC client B   <--HTTP-RP-->   xRTC0(reverse porxy)   <--HTTP-RP-->  WebRTC server
WebRTC client C   <--HTTP-RP-->   xRTC1(reverse porxy)   <--HTTP-RP-->  WebRTC server

WebRTC client A   <--ICE port0-->   xRTC0  <--ICE port1-->  WebRTC server
WebRTC client B   <--ICE port0-->   xRTC0  <--ICE port2-->  WebRTC server
WebRTC client C   <--ICE port1-->   xRTC1  <--ICE port3-->  WebRTC server
```

The xRTC can use the same port (ICE-UDP/TCP) for different clients.

<br>

## 2. Flow

```
WebRTC client <---------------------->     xRTC    <--------------------> WebRTC server
                                        (1)
              ---- (Parse offer from REST request and forward)   ------->
              
                                        (2)
              <--- (Parse answer from REST response and forward) --------
              
                       (3)                                     (4)
              <--- ice data0--->       xRTC             <---ice data1--->
              
                                        (5)
              <------         dtls/sctp/srtp/srtcp forward       ------->
```


> Step1: Parse offer of REST request from WebRTC client.
> 
> Step2: Parse answer of REST response from WebRTC client.
> 
> Step3: Build and maintain ice connection0 between WebRTC client and xRTC.
> 
> Step4: Build and maintain ice connection1 between xRTC and WebRTC server.
> 
> Step5: Forward dtls/sctp/srtp/srtcp data between WebRTC client and WebRTC server.


<br>

## 3. Routing

The default routes config is [routes.yml](testing/routes.yml) (YAML format).

The root node is `services` and its structure:

```yaml
services:
  servername:
    proto: http/tcp/udp
    net:
      enable: true
      addr: :6443
      tls_crt_file: /tmp/etc/cert.pem
      tls_key_file: /tmp/etc/cert.key
      ips:
        - host_ip
    enable_http: true
    http:
      root: /tmp/html
      hijacks:
        - host@janus.zenvv.com: janus
        - ws@janus-protocol:    janus
        - /janus:               janus
      routes:
        - host@janus.zenvv.com: http://janus_api:8088
        - ws@janus-protocol:    ws://janus_api:8188
        - /janus:               http://janus_api:8088
```

Each service is a server (servername), e.g. udp ice server, tcp ice server, http/ws reverse-proxy server.

The server's fields contains:

1. ***proto***: *http/tcp/udp*  
	*http* is a HTTP static or HTTP-RP(http/ws reverse proxy) server,  
	*tcp* is a WebRTC-ICE-TCP or HTTP-RP server,  
	*udp* is a WebRTC-ICE-UDP server,
	
2. ***net***: network config
	* ***enable***: *true/false*
	* ***addr***: server listen address, format: "*ip:port*"
	* ***tls\_crt\_file***: local crt file(openssl)
	* ***tls\_key\_file***: local key file(openssl)
	* ***ips***: server ICE candidate ip address.
	
	The `enable` is only valid for `proto:udp/tcp`, ICE candidates.
	
	The `tls_crt_file/tls_key_file` is only valid for `proto:udp/tcp`.
	
	The `ips` is only valid for `proto: udp/tcp`, ICE candidates.

	if `enable` is true, xRTC's candidates are constructed by `ips` and port of `addr`.
	
	if no valid tls key/crt, http(ws) enabled, otherwise both http(ws) and https(wss) are enabled.
	
3. ***http***: HTTP server config
	* ***root***: HTTP static directory for no-routing http request.
	* ***hijacks***: HTTP-RP tags for which server(Janus/Jitsi), like *routes*.
	* ***routes***: HTTP-RP routing rules with priority desc....
		* hostname matching: "*host@...*"
		* websocket protocol matching: "*ws@...*", e.g. `var ws = WebSocket("wss://..", "protocol_name");`
		* path matching, now only support prefix-matching.

4. ***enable_http***: *true/false*, only valid for `proto: tcp`.  
	when *enable_http* is true and current service is a tcp server, then it can also act as a full HTTP-RP server. 


<br>

## TODO

- [ ] HTTP config parameters (`max_conns/dial_timeout/..`)
- [ ] Jitsi WebRTC server support
