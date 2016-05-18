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
	"net/rpc"
	"net/url"
	"strings"
	"sync"
	"time"
)

const VERSION = "1.1.0"

type WhiteList struct {
	filepath string
	rpcPort  string
	list     []string
}

func NewWhiteList(filepath string, rpcPort string) *WhiteList {
	var wl = &WhiteList{filepath: filepath, rpcPort: rpcPort}
	wl.list = make([]string, 0)

	if filepath == "" {
		return wl
	}

	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		log.Printf("read file \"%s\" error\n%v", filepath, err)
		return wl
	}

	list := strings.Split(string(data), "\n")

	for _, host := range list {
		if host != "" && !wl.has(host) {
			wl.list = append(wl.list, host)
		}
	}

	log.Printf("white list count: %d\n", len(wl.list))
	return wl
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

func (wl *WhiteList) Add(host string, reply *bool) error {
	if wl.has(host) {
		*reply = false
		return nil
	}
	*reply = true

	log.Printf("add new host \"%s\"\n", host)

	wl.list = append(wl.list, host)
	wl.saveToFile()

	return nil
}

func (wl *WhiteList) Remove(host string, reply *bool) error {
	i := wl.indexOf(host)
	if i < 0 {
		*reply = false
		return nil
	}
	*reply = true

	log.Printf("remove host \"%s\"\n", host)

	wl.list = append(wl.list[:i], wl.list[i+1:]...)
	wl.saveToFile()
	return nil
}

func (wl *WhiteList) saveToFile() {
	data := []byte(strings.Join(wl.list, "\n"))
	ioutil.WriteFile(wl.filepath, data, 0644)
}

func (wl *WhiteList) listenAndServeRpc() {
	if wl.rpcPort != "0" {
		addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:"+wl.rpcPort)
		if err != nil {
			log.Fatal(err)
		}

		inbound, err := net.ListenTCP("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("rpc listening on 127.0.0.1:" + rpcPort)

		rpc.Register(wl)
		rpc.Accept(inbound)
	}
}

func (wl *WhiteList) rpcAdd(host string) {
	client, err := rpc.Dial("tcp", "127.0.0.1:"+wl.rpcPort)
	if err != nil {
		log.Fatal(err)
	}

	var reply bool
	err = client.Call("WhiteList.Add", host, &reply)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("add \"%s\" status: %t\n", host, reply)
}

func (wl *WhiteList) rpcRemove(host string) {
	client, err := rpc.Dial("tcp", "127.0.0.1:"+wl.rpcPort)
	if err != nil {
		log.Fatal(err)
	}

	var reply bool
	err = client.Call("WhiteList.Remove", host, &reply)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("add \"%s\" status: %t\n", host, reply)
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

	errCh := make(chan error, 2)
	defer close(errCh)

	go func() {
		written, err := io.Copy(clientConn, remoteConn)
		if err == nil && server.verbose {
			log.Printf("%x %s %d", client.id, "client <- remote", written)
		}
		errCh <- err
	}()
	go func() {
		written, err := io.Copy(remoteConn, clientConn)
		if err == nil && server.verbose {
			log.Printf("%x %s %d", client.id, "client -> remote", written)
		}
		errCh <- err
	}()

	if err := establishConnection(clientConn); err != nil {
		return err
	}

	for i := 0; i < 2; i++ {
		select {
		case err = <-errCh:
			if err != nil {
				return err
			}
		}
	}

	return nil
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
		log.Printf("%x %s %d", client.id, "transfer", written)
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
	flag.StringVar(&toAddHost, "a", "", "add white host")
	flag.StringVar(&toRemoveHost, "r", "", "remove white host")
	flag.StringVar(&rpcPort, "p", "40401", "set rpc port")
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

	serve := true
	if toAddHost != "" {
		serve = false
		whitelist.rpcAdd(toAddHost)
	}

	if toRemoveHost != "" {
		serve = false
		whitelist.rpcRemove(toRemoveHost)
	}

	if !serve {
		return
	}

	server := &Server{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		verbose:    verbose,
		whitelist:  whitelist,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go server.ListenAndServe()
	go whitelist.listenAndServeRpc()

	wg.Wait()
}
