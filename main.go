package main

import (
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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

func (server *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("%s %s\n", req.Method, req.Host)

	var err error
	if req.Method == http.MethodConnect {
		err = server.tunnel(w, req)

	} else {
		err = server.transfer(w, req)
	}

	if err != nil {
		if server.verbose {
			log.Println(err)
		}
	}
}

func (server *Server) tunnel(w http.ResponseWriter, req *http.Request) error {
	var err error

	remoteConn, err := server.socks5Dialer.Dial("tcp", req.Host)
	if err != nil {
		return err
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return err
	}

	done := make(chan error)

	go server.pipe(clientConn, remoteConn, done)
	go server.pipe(remoteConn, clientConn, done)

	if _, err := fmt.Fprint(clientConn, "HTTP/1.1 200 Connection established\r\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(clientConn, "Connection: close\r\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(clientConn, "\r\n"); err != nil {
		return err
	}

	for waiting := 2; waiting > 0; {
		select {
		case err = <-done:
			waiting--
		}
		if err != nil {
			break
		}
	}

	close(done)
	if err != nil {
		return err
	}

	return nil
}

func (server *Server) pipe(src, dst net.Conn, done chan<- error) {
	_, err := io.Copy(dst, src)
	if err != nil {
		log.Println(err)
	}
	done <- nil
}

func (server *Server) transfer(w http.ResponseWriter, req *http.Request) error {
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")

	transport := &http.Transport{
		Dial: server.socks5Dialer.Dial,
	}

	res, err := transport.RoundTrip(req)
	if err != nil {
		return err
	}

	for key, values := range res.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(res.StatusCode)

	_, err = io.Copy(w, res.Body)
	if err != nil {
		return err
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
