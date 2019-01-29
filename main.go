package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"time"
	"gopkg.in/ldap.v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <host[:port]>\n", os.Args[0])
		os.Exit(1)
	}

	u, err := url.Parse(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "389"
	}
	addr := fmt.Sprintf("%s:%s", host, port)

	l, err := ldap.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	defer l.Close()

	tlsConf := tls.Config{}
	tlsConf.InsecureSkipVerify = false
	tlsConf.ServerName = host

	err = l.StartTLS(&tlsConf)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}

	cs := l.ConnectionState()

	for cert := range cs.PeerCertificates() {
		fmt.Printf("Subject: %s | Issuer: %s | Expires(days): %i\n", cert.Subject, cert.Issuer, expiresIn(cert))
	}
}

// Check how many days the certificate is still valid
func expiresIn(cert x509.Certificate) int {
	expiresIn := cert.NotAfter.Sub(time.Now())

	// Convert days to int
	return int(expiresIn.Hours() / 24)
}
