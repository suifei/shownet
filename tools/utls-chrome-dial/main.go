// utls-chrome-dial opens a TLS connection with a Chrome-class ClientHello via
// refraction-networking/utls. Used by Phase 1 tool measure against the local
// ShowNet ClientHello probe, and for HTTPS GETs against public JA3 detectors.
//
// Usage:
//
//	utls-chrome-dial -addr 127.0.0.1:12345 -sni probe.local -hello chrome131
//	utls-chrome-dial -url https://tls.browserleaks.com/json -hello chrome
//
// Exit 0 if the ClientHello was sent (handshake may fail against a capture-only probe).
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	addr := flag.String("addr", "", "host:port to dial (probe mode)")
	sni := flag.String("sni", "", "TLS ServerName (defaults to host of -addr/-url)")
	hello := flag.String("hello", "chrome", "ClientHello id: chrome|chrome120|chrome131|firefox|ios")
	timeout := flag.Duration("timeout", 15*time.Second, "timeout")
	getURL := flag.String("url", "", "if set, perform HTTPS GET and print response body")
	flag.Parse()

	id, err := helloID(*hello)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	if strings.TrimSpace(*getURL) != "" {
		if err := httpsGet(*getURL, *sni, id, *timeout); err != nil {
			fmt.Fprintf(os.Stderr, "get failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if strings.TrimSpace(*addr) == "" {
		fmt.Fprintln(os.Stderr, "utls-chrome-dial: -addr host:port or -url https://... required")
		os.Exit(2)
	}
	serverName := *sni
	if serverName == "" {
		host, _, err := net.SplitHostPort(*addr)
		if err != nil {
			serverName = *addr
		} else {
			serverName = host
		}
	}

	d := net.Dialer{Timeout: *timeout}
	raw, err := d.Dial("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcp dial failed: %v\n", err)
		os.Exit(1)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(*timeout))

	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	conn := utls.UClient(raw, cfg, id)
	err = conn.Handshake()
	if err != nil {
		fmt.Printf(`{"ok":true,"expectedAbort":true,"hello":%q,"addr":%q,"sni":%q,"error":%q}`+"\n",
			*hello, *addr, serverName, err.Error())
		os.Exit(0)
	}
	_ = conn.Close()
	fmt.Printf(`{"ok":true,"handshakeComplete":true,"hello":%q,"addr":%q,"sni":%q}`+"\n",
		*hello, *addr, serverName)
}

func httpsGet(rawURL, sni string, id utls.ClientHelloID, timeout time.Duration) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https supported")
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	serverName := sni
	if serverName == "" {
		serverName = host
	}
	addr := net.JoinHostPort(host, port)

	d := net.Dialer{Timeout: timeout}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	}
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		_ = raw.Close()
		return fmt.Errorf("UTLSIdToSpec: %w", err)
	}
	// Prefer HTTP/1.1 so the simple request/response parser works (detectors still
	// see a Chrome-class ClientHello aside from ALPN list).
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		_ = raw.Close()
		return err
	}
	if err := uconn.Handshake(); err != nil {
		_ = raw.Close()
		return err
	}

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Host:   host,
		Header: http.Header{
			"Accept":     []string{"application/json,*/*"},
			"User-Agent": []string{"ShowNet-utls-chrome-dial/1.0"},
		},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := req.Write(uconn); err != nil {
		_ = uconn.Close()
		return err
	}
	_ = uconn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(uconn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = uconn.Close()
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = uconn.Close()
	if err != nil {
		return err
	}
	// Print body only (JSON APIs) so callers can parse stdout as the response.
	os.Stdout.Write(body)
	if len(body) == 0 || body[len(body)-1] != '\n' {
		fmt.Fprintln(os.Stdout)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func helloID(name string) (utls.ClientHelloID, error) {
	// Prefer HelloChrome_102 for product majors (chrome150 etc.): post-106 parrots
	// shuffle extension order every handshake so JA3 never re-validates against a
	// golden. JA4 remains the stable digests for those stacks; Phase 1 goldens pin
	// a pre-shuffle parrot for exact JA3 re-measure where possible, and the gate
	// also accepts JA4 equality.
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome102", "102", "stable", "chrome-stable":
		return utls.HelloChrome_102, nil
	case "chrome", "chrome-auto", "chrome_auto":
		// Auto == 131 with shuffle; keep for experiments, not goldens.
		return utls.HelloChrome_Auto, nil
	case "chrome120", "120":
		return utls.HelloChrome_120, nil
	case "chrome131", "131":
		return utls.HelloChrome_131, nil
	case "chrome133", "133", "chrome150", "150", "chrome149", "149",
		"chrome144", "144", "chrome146", "146":
		// Product majors → stable pre-shuffle parrot for tool goldens.
		return utls.HelloChrome_102, nil
	case "firefox", "firefox_auto":
		return utls.HelloFirefox_Auto, nil
	case "ios", "safari_ios":
		return utls.HelloIOS_Auto, nil
	default:
		if strings.HasPrefix(strings.ToLower(name), "chrome") {
			return utls.HelloChrome_102, nil
		}
		return utls.ClientHelloID{}, fmt.Errorf("unknown -hello %q", name)
	}
}
