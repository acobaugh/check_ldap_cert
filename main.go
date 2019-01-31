package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"gopkg.in/ldap.v3"
	//"net"
	"net/url"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s ldap://<host[:port]>\n", os.Args[0])
		os.Exit(1)
	}

	// parse url
	u, err := url.Parse(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// create addr
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "389"
	}
	addr := fmt.Sprintf("%s:%s", host, port)

	// create ldap connection
	l, err := ldap.Dial("tcp", addr)
	if err != nil {
		fmt.Printf("net.Dial(): %s\n", err)
		os.Exit(1)
	}
	defer l.Close()

	// set up tls.Config{}
	tlsConf := tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	// initiate starttls
	err = l.StartTLS(&tlsConf)
	if err != nil {
		fmt.Printf("ldap.StartTLS(): %s\n", err)
		os.Exit(1)
	}

	cs, ok := l.TLSConnectionState()
	if !ok {
		fmt.Print("ConnectionState not ok\n")
		os.Exit(1)
	}

	for i, cert := range cs.PeerCertificates {
		fmt.Printf(" %d s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n",
			i, cert.Subject.Country,
			cert.Subject.Province,
			cert.Subject.Locality,
			cert.Subject.Organization,
			cert.Subject.OrganizationalUnit,
			cert.Subject.CommonName)
		fmt.Printf("   i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n",
			cert.Issuer.Country,
			cert.Issuer.Province,
			cert.Issuer.Locality,
			cert.Issuer.Organization,
			cert.Issuer.OrganizationalUnit,
			cert.Issuer.CommonName)
		fmt.Printf("   validity: NotBefore: %s, NotAfter: %s\n", cert.NotBefore, cert.NotAfter)
		fmt.Printf("   serial: %x\n", cert.SerialNumber)
		fmt.Print("   subjectAltName: ")
		for _, san := range cert.DNSNames {
			fmt.Printf("DNS: %s, ", san)
		}
		for san := range cert.EmailAddresses {
			fmt.Printf("Email: %s, ", san)
		}
		for san := range cert.IPAddresses {
			fmt.Printf("IP: %s, ", san)
		}
		for san := range cert.URIs {
			fmt.Printf("URI: %s, ", san)
		}
		fmt.Println()
	}
}

// Check how many days the certificate is still valid
func expiresIn(cert x509.Certificate) int {
	expiresIn := cert.NotAfter.Sub(time.Now())

	// Convert days to int
	return int(expiresIn.Hours() / 24)
}
