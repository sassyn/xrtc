# xRTC

***xRTC*** is an eXtendable WebRTC proxy, for REST-based WebRTC server.

xRTC can serve many WebRTC clients on one ICE port at the same time.

xRTC is a HTTP/Websocket Reverse Proxy(***HTTP-RP***).

xRTC supports customed HTTP-RP routes.

xRTC can serve HTTP/HTTPS/WS/WSS on one TCP port at the same time.

xRTC can act as a HTTP static server.

xRTC supports most features of [Janus WebRTC server](https://github.com/meetecho/janus-gateway).


<br>

## 0. Arch

### 0). Direct cases

```
WebRTC client A   <---HTTP/WS--->  WebRTC server(Janus/Jitsi/Moxtra)
WebRTC client B   <---HTTP/WS--->  WebRTC server(Janus/Jitsi/Moxtra)

WebRTC client A   <---ICE port0--->  WebRTC server(Janus/Jitsi/Moxtra)
WebRTC client B   <---ICE port1--->  WebRTC server(Janus/Jitsi/Moxtra)
```

The WebRTC servers(Janus/Jitsi) need to use different ports for different clients.

However, most servers only provide limited ports for security.


### 1). xRTC cases

```
WebRTC client A   <--HTTP-RP-->   xRTC(reverse porxy)   <--HTTP-RP-->  WebRTC server
WebRTC client B   <--HTTP-RP-->   xRTC(reverse porxy)   <--HTTP-RP-->  WebRTC server

WebRTC client A   <--ICE port0-->   xRTC  <--ICE port1-->  WebRTC server
WebRTC client B   <--ICE port0-->   xRTC  <--ICE port2-->  WebRTC server
```


<br>

## 1. Principle

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

## 2. Routes

The default routes config is [routes.yml](testing/routes.yml) (YAML format).

The root node is `services` and its structure is:

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

Each service is a server, e.g. udp ice server, tcp ice server, http/ws reverse-proxy server.

The meaning of server's fields:

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

	xRTC's candidates are constructed by `ips` and port of `addr`.
	
	if no valid tls key/crt, http(ws) enabled, or both http(ws) and https()wss enabled.
	
3. ***http***: HTTP server config
	* ***root***: HTTP static directory for no-routing http request.
	* ***hijacks***: HTTP-RP tags for which server(Janus/Jitsi), like *routes*.
	* ***routes***: HTTP-RP routing rules with priority desc....
		* hostname matching: "*host@...*"
		* websocket protocol matching: "*ws@...*", e.g. `var ws = WebSocket("wss://..", "protocol_name");`
		* path matching, now only support prefix-matching.

4. ***enable_http***: *true/false*, only valid for **proto: tcp**.  
	when *enable_http* is true and current service is a tcp server, then it can also act as a full HTTP-RP server. 


<br>

## TODO

- [ ] HTTP config parameters (`max_conns/dial_timeout/..`)
- [ ] Jitsi WebRTC server support
