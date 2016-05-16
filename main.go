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

const VERSION = "1.0.0"

type WhiteList struct {
	filepath string
	list     []string
}

func NewWhiteList(filepath string) *WhiteList {
	var wl = &WhiteList{filepath: filepath}
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

func (wl *WhiteList) add(host string) {
	if wl.has(host) {
		return
	}

	log.Printf("add new host \"%s\"\n", host)

	wl.list = append(wl.list, host)
	wl.saveToFile()
}

func (wl *WhiteList) remove(host string) {
	i := wl.indexOf(host)
	if i < 0 {
		return
	}

	log.Printf("remove host \"%s\"\n", host)

	wl.list = append(wl.list[:i], wl.list[i+1:]...)
	wl.saveToFile()
}

func (wl *WhiteList) saveToFile() {
	data := []byte(strings.Join(wl.list, "\n"))
	ioutil.WriteFile(wl.filepath, data, 0644)
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

	log.Println("listening on", server.localAddr)
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

func handleCommandLine() (localAddr, remoteAddr, wlFile string, verbose, version bool) {
	flag.StringVar(&localAddr, "l", "127.0.0.1:8080", "set http proxy 'host:port'")
	flag.StringVar(&remoteAddr, "s", "127.0.0.1:1080", "set remote socks5 server 'host:port'")
	flag.StringVar(&wlFile, "w", "", "set host white list file path")
	flag.BoolVar(&verbose, "verbose", false, "print extra debuging information")
	flag.BoolVar(&version, "v", false, "display version")
	flag.Parse()
	return
}

func main() {
	localAddr, remoteAddr, wlFile, verbose, version := handleCommandLine()

	if flag.NFlag() == 0 && flag.NArg() > 0 {
		flag.Usage()
		return
	}

	if version {
		log.Printf("v%s\n", VERSION)
		return
	}

	server := &Server{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		verbose:    verbose,
		whitelist:  NewWhiteList(wlFile),
	}

	server.ListenAndServe()
}
