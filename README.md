# xRTC

***xRTC*** is an eXtendable WebRTC proxy, for REST-based WebRTC server.

- [x] Serve many WebRTC clients on one ICE port at the same time.
- [x] Serve as HTTP/WebSocket Reverse Proxy(`HTTP-RP`) .
- [x] Serve HTTP/HTTPS/WS/WSS/ICE-TCP on one TCP port at the same time.
- [x] Serve as HTTP static server.
- [x] Serve as an extendable node of WebRTC server.
- [x] Support most features of [Janus WebRTC server](https://github.com/meetecho/janus-gateway).
- [x] Support `upstream` config like nginx (partial).
- [x] Support `icedirect`(transparent) between client and WebRTC server.(partial)


<br>

# TODO

- [ ] HTTP config parameters (`max_conns/dial_timeout/..`)
- [ ] Jitsi WebRTC server support


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


### 1) Stun-Hijacked Flow

```
WebRTC client <---------------------->     xRTC    <--------------------> WebRTC server
                                        (1)
              ---- (Parse offer from REST request and forward)   ------->
              
                                        (2)
              <--- (Parse answer from REST response and forward) --------
              
                                        (3)
                                connect with server              ------->
              
                       (4)                                     (5)
              <--- ice data0--->       xRTC             <---ice data1--->
              
                                        (6)
              <------         dtls/sctp/srtp/srtcp forward       ------->
```


> ***Step1***: Parse offer of REST request from WebRTC client.  
> 		xRTC parses send-ice-ufrag/pwd from offer.
> 
> ***Step2***: Parse answer of REST response from WebRTC server.  
>		xRTC parses recv-ice-ufrag/pwd from answer.   
> 		Answer candidates are updated with `host_ip` & `udp/tcp server port`(passive-only-mode) in config. 
> 
> ***Step3***: Build ice connection between xRTC and WebRTC server.  
> 		xRTC builds ice conenction(send-ice-ufrag/pwd) by libnice.   
> 		The candidates are passive or active-mode.
> 
> ***Step4***: Maintain ice connection0 between WebRTC client and xRTC.  
> 		xRTC makes use of recv-ice-ufrag/pwd to interact with client. 
> 
> ***Step5***: Maintain ice connection1 between xRTC and WebRTC server.  
> 		xRTC-libnice takes the owner to interact with server. 
> 
> ***Step6***: Forward dtls/sctp/srtp/srtcp data between WebRTC client and WebRTC server.  
> 		xRTC only forwards these packets between client and server.


<br>

### 2) Stun-Transparent Flow

```
WebRTC client <---------------------->     xRTC    <--------------------> WebRTC server
                                        (1)
              ---- (Parse offer from REST request and forward)   ------->
              
                                        (2)
              <--- (Parse answer from REST response and forward) --------
              
                                        (3)
                                connect with server              ------->
              
                                        (4)
              <--------------    ice data forward    ------------------->
              
                                        (5)
              <------         dtls/sctp/srtp/srtcp forward       ------->
```

> ***Step1***: Parse offer of REST request from WebRTC client.  
> 		xRTC parses send-ice-ufrag/pwd from offer.
> 
> ***Step2***: Parse answer of REST response from WebRTC server.  
> 		xRTC parses recv-ice-ufrag/pwd from answer.  
> 		Answer candidates are updated with `host_ip` & `udp/tcp server port`(passive-only-mode) in config.  
> 		xRTC parses WebRTC-server ip/port from canddiate. 
> 
> ***Step3***: Build connection between xRTC and WebRTC server.  
> 		xRTC builds general network conenction(udp/tcp) with address from Step2. 
> 
> ***Step4***: Foward ice data between WebRTC client and xRTC.  
> 		xRTC only forwards these packets between client and server. 
> 
> ***Step5***: Forward dtls/sctp/srtp/srtcp data between WebRTC client and WebRTC server.  
> 		xRTC only forwards these packets between client and server.


<br>

## 3. Routing

The default routes config is [routes.yml](testing/routes.yml) (YAML format).

The root node is `services` and its structure:

```yaml
services:
  servicename:
    proto: http/tcp/udp/upstream
    servers:
      - http://janus_api:8088
      - ws://janus_api:8188
    net:
      enable: true
      addr: :6443
      tls_crt_file: /tmp/etc/cert.pem
      tls_key_file: /tmp/etc/cert.key
      ips:
        - host_ip
    enable_http: true
    http:
      servername: _
      root: /tmp/html
      routes:
        janus:
          upstream: http://upstream_janus1
          hosts: 
            - janus.zenvv.com
          protos:
            - ws@janus-protocol
          paths:
            - /janus
        default:
          upstream: http://html_api:8080
          paths:
            - /index
```

Each service is a function(servicename), e.g. udp ice server, tcp ice server, http/ws reverse-proxy server or upstream group.

The server's fields contains:

1. ***proto***: *http/tcp/udp/upstream*  
	*http* is a HTTP static or HTTP-RP(http/ws reverse proxy) server,  
	*tcp* is a WebRTC-ICE-TCP or HTTP-RP server,  
	*udp* is a WebRTC-ICE-UDP server,  
	*upstream* is a upstream group,

2. ***servers***: only valid for `proto: upstream`   
	Each server should be: "http/https/ws/wss://host[:port]",   
	like nginx upstream. 
	
3. ***net***: network config, only valid for `proto:udp/tcp/http`
	* ***enable***: *true/false*
	* ***addr***: server listen address, format: "*ip:port*"
	* ***tls\_crt\_file***: local crt file(openssl)
	* ***tls\_key\_file***: local key file(openssl)
	* ***ips***: server ICE candidate ip address.
	
	The `enable` is only valid for `proto:udp/tcp`, for ICE candidates.
	
	The `tls_crt_file/tls_key_file` is only valid for `proto:udp/tcp`.
	
	The `ips` is only valid for `proto: udp/tcp`, IP of xrtc ICE candidates.

	if `enable` is true, xRTC's candidates are constructed by `ips` and port of `addr`.
	
	if no valid tls key/crt, http(ws) enabled, otherwise both http(ws) and https(wss) are enabled.
	
4. ***enable_http***: *true/false*, only valid for `proto: tcp`.  
	when *enable_http* is true and current service is a tcp server, then it also act as a full HTTP-RP server. 
	
5. ***http***: HTTP server config
	* ***servername***: HTTP server name, default "_" for any.  
		if not "_", only matched request will be processsed, like nginx. 
	* ***root***: HTTP static directory for no-routing http request.
	* ***routes***: HTTP-RP routing rules with priority desc....  
		Each group is a hijack tag for which kind of route, e.g. `janus/default`.  
		* ***upstream***: a seperate uri or previous upstream group.
		* ***icetcp***: xRTC connects WebRTC server with TCP in high-priority.
		* ***icedirect***: xRTC forwards all ice-data between client and server.
		* ***hosts***: hostname matching if `servername: _`
		* ***protos***: websocket matching, e.g. `var ws = WebSocket("wss://..", "protocol_name");`
		* ***paths***: path matching, now only support prefix-matching


<br>

## 4. Build & Run

Simply building for all platforms which support docker:
    
```
$> make docker-pull
$> make docker-mac
$> make deploy-mac
```

<br>

If you want to build completely, following steps as:


1. Library dependency
	
	libffi, libuuid, glib2, libnice, gnutls, openssl
	
2. Routing config

	```
	$> vim testing/routes.yml
	```
	
3. Common Build for Linux/Mac

	```
	$> make
	$> cp testing/routes.yml /tmp/etc/routes.yml
	$> make run
	```
	
	
4. Docker Build for CentOS-7
	
	This only works when Step-3 are successful in CentOS-7.
	
	1). Build and Deploy
	
	``` 
	$> make docker
	$> make deploy
	```
	
	2). Generate docker-build image for CentOS-7
	
	```
	$> make docker-build
	```
	
5. Docker Build for Others(Linux/Mac)
	
	This is a cross-platform building and deploying.

	However, it requires the docker image generated in Step-4-(2).
	
	``` 
	$> make docker-mac
	$> make deploy-mac
	```
