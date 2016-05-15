package main

import (
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

const VERSION = "v1.0.0"

func handleCommandLine() (localAddr string, remoteAddr string, verbose bool, version bool) {
	flag.StringVar(&localAddr, "l", "127.0.0.1:8080", "set http proxy 'host:port'")
	flag.StringVar(&remoteAddr, "s", "127.0.0.1:1080", "set remote socks5 server 'host:port'")
	flag.BoolVar(&verbose, "verbose", false, "print extra debuging information")
	flag.BoolVar(&version, "v", false, "display version")
	flag.Parse()
	return
}

type Server struct {
	localAddr    string
	remoteAddr   string
	socks5Dialer proxy.Dialer
	verbose      bool
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

func hash(req *http.Request) string {
	str := time.Now().String() + req.Method + req.URL.String()
	hash := md5.Sum([]byte(str))
	return hex.EncodeToString(hash[:])
}

type Client struct {
	id  string
	w   http.ResponseWriter
	req *http.Request
}

func (server *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	id := hash(req)
	client := &Client{id, w, req}

	if server.verbose {
		log.Printf("%s: %s %s\n", id, req.Method, req.URL.String())
	} else {
		log.Printf("%s: %s %s\n", id, req.Method, req.Host)
	}

	var err error
	if req.Method == http.MethodConnect {
		err = server.tunnel(client)

	} else {
		err = server.transfer(client)
	}

	if err != nil {
		log.Printf("%s: \n%v", id, err)
	}

	if server.verbose {
		log.Println(id, "transferring finished")
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

	if remoteConn, err = server.socks5Dialer.Dial("tcp", client.req.Host); err != nil {
		return err
	}
	defer remoteConn.Close()

	hi, ok := client.w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("not support hijacking")
	}

	if clientConn, _, err = hi.Hijack(); err != nil {
		return err
	}
	defer clientConn.Close()

	errCh := make(chan error, 2)
	defer close(errCh)

	go func() {
		written, err := io.Copy(clientConn, remoteConn)
		if err == nil && server.verbose {
			log.Printf("%s: %s %d", client.id, "client <- remote", written)
		}
		errCh <- err
	}()
	go func() {
		written, err := io.Copy(remoteConn, clientConn)
		if err == nil && server.verbose {
			log.Printf("%s: %s %d", client.id, "client -> remote", written)
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

	transport := &http.Transport{
		Dial: server.socks5Dialer.Dial,
	}

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
		log.Printf("%s %s %d", client.id, "transfer", written)
	}
	return nil
}

func main() {
	localAddr, remoteAddr, verbose, version := handleCommandLine()

	if flag.NFlag() == 0 && flag.NArg() > 0 {
		flag.Usage()
		return
	}

	if version {
		fmt.Println(VERSION)
		return
	}

	server := &Server{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		verbose:    verbose,
	}

	server.ListenAndServe()
}
