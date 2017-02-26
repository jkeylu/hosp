package main

import (
	"crypto/md5"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const VERSION = "1.2.0"

type WhiteList struct {
	filepath string
	list     []string
}

func NewWhiteList(filepath string, rpcPort string) *WhiteList {
	var wl = &WhiteList{filepath: filepath}

	wl.load()

	return wl
}

func (wl *WhiteList) load() {
	wl.list = make([]string, 0)

	if wl.filepath == "" {
		return
	}

	data, err := ioutil.ReadFile(wl.filepath)
	if err != nil {
		log.Printf("read file \"%s\" error\n%v", wl.filepath, err)
		return
	}

	list := strings.Split(string(data), "\n")

	for _, host := range list {
		if host != "" && !wl.has(host) {
			wl.list = append(wl.list, host)
		}
	}

	log.Printf("white list count: %d\n", len(wl.list))
}

func (wl *WhiteList) has(host string) bool {
	return wl.indexOf(host) >= 0
}

func (wl *WhiteList) indexOf(host string) int {
	for i, h := range wl.list {
		if strings.Contains(host, h) {
			return i
		}
	}

	return -1
}

type Server struct {
	localAddr    string
	remoteAddr   string
	socks5Dialer proxy.Dialer
	verbose      bool
	whitelist    *WhiteList
}

func (server *Server) ListenAndServe() {
	if server.socks5Dialer == nil {
		socks5URL, err := url.Parse("socks5://" + server.remoteAddr)
		if err != nil {
			log.Fatal(err)
		}

		server.socks5Dialer, err = proxy.FromURL(socks5URL, proxy.Direct)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("http proxy listening on", server.localAddr)
	if err := http.ListenAndServe(server.localAddr, server); err != nil {
		log.Fatal(err)
	}
}

func hash(req *http.Request) [16]byte {
	str := time.Now().String() + req.Method + req.URL.String()
	return md5.Sum([]byte(str))
}

type Client struct {
	id  [16]byte
	w   http.ResponseWriter
	req *http.Request
}

func (server *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	id := hash(req)
	client := &Client{id, w, req}

	if server.verbose {
		log.Printf("%x %s %s\n", id, req.Method, req.URL.String())
	} else {
		log.Printf("%x %s %s\n", id, req.Method, req.Host)
	}

	var err error
	if req.Method == http.MethodConnect {
		err = server.tunnel(client)

	} else {
		err = server.transfer(client)
	}

	if err != nil {
		log.Printf("%x \n%v", id, err)
	}

	if server.verbose {
		log.Printf("%x transferring finished", id)
	}
}

func establishConnection(conn net.Conn) error {
	if _, err := fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(conn, "Connection: close\r\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
		return err
	}

	return nil
}

func (server *Server) tunnel(client *Client) error {
	var err error
	var remoteConn net.Conn
	var clientConn net.Conn

	host := client.req.Host
	if server.whitelist.has(host) {
		remoteConn, err = net.Dial("tcp", host)
		log.Printf("%x direct connect \"%s\"\n", client.id, host)

	} else {
		remoteConn, err = server.socks5Dialer.Dial("tcp", host)
	}
	defer remoteConn.Close()
	if err != nil {
		return err
	}

	hi, ok := client.w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("not support hijacking")
	}

	clientConn, _, err = hi.Hijack()
	defer clientConn.Close()
	if err != nil {
		return err
	}

	recvDoneCh := make(chan error, 1)
	defer close(recvDoneCh)

	sendDoneCh := make(chan error, 1)
	defer close(sendDoneCh)

	go func() {
		written, err := io.Copy(clientConn, remoteConn)
		if err == nil && server.verbose {
			log.Printf("%x client <- remote %d", client.id, written)
		}
		recvDoneCh <- err
	}()
	go func() {
		written, err := io.Copy(remoteConn, clientConn)
		if err == nil && server.verbose {
			log.Printf("%x client -> remote %d", client.id, written)
		}
		sendDoneCh <- err
	}()

	if err := establishConnection(clientConn); err != nil {
		return err
	}

	if e := <-sendDoneCh; e != nil {
		err = e
	}

	if e := <-recvDoneCh; e != nil {
		if err == nil {
			err = e
		}
	}

	return err
}

func (server *Server) transfer(client *Client) error {
	client.req.Header.Del("Proxy-Connection")
	client.req.Header.Del("Connection")
	client.req.Header.Del("Keep-Alive")

	host := client.req.Host
	var dial func(network, addr string) (net.Conn, error)
	if server.whitelist.has(host) {
		dial = nil
		log.Printf("%x direct %s \"%s\"\n", client.id, client.req.Method, host)

	} else {
		dial = server.socks5Dialer.Dial
	}

	transport := &http.Transport{Dial: dial}

	res, err := transport.RoundTrip(client.req)
	if err != nil {
		return err
	}

	for key, values := range res.Header {
		for _, value := range values {
			client.w.Header().Add(key, value)
		}
	}
	client.w.WriteHeader(res.StatusCode)

	written, err := io.Copy(client.w, res.Body)
	if err != nil {
		return err
	}
	if server.verbose {
		log.Printf("%x transfer %d", client.id, written)
	}
	return nil
}

var localAddr, remoteAddr, wlFile string
var verbose, version bool
var toAddHost, toRemoveHost string
var rpcPort string

func init() {
	flag.StringVar(&localAddr, "l", "127.0.0.1:8080", "set http proxy 'host:port'")
	flag.StringVar(&remoteAddr, "s", "127.0.0.1:1080", "set remote socks5 server 'host:port'")
	flag.StringVar(&wlFile, "w", "", "set host white list file path")
	flag.BoolVar(&verbose, "verbose", false, "print extra debuging information")
	flag.BoolVar(&version, "v", false, "display version")
}

func main() {
	flag.Parse()

	if flag.NFlag() == 0 && flag.NArg() > 0 {
		flag.Usage()
		return
	}

	if version {
		fmt.Printf("v%s\n", VERSION)
		return
	}

	whitelist := NewWhiteList(wlFile, rpcPort)

	server := &Server{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		verbose:    verbose,
		whitelist:  whitelist,
	}

	server.ListenAndServe()
}
