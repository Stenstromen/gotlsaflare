package resource

import (
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

func addVerifyFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("url", "u", "", "Domain")
	cmd.Flags().StringP("subdomain", "s", "", "TLSA subdomain")
	cmd.Flags().StringP("cert", "f", "", "Certificate PEM")
	cmd.Flags().BoolP("tcp25", "t", false, "Port 25/TCP")
	cmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	cmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	cmd.Flags().IntP("tcp-port", "c", 0, "Custom TCP Port")
	cmd.Flags().Bool("dane-ee", true, "Verify DANE-EE")
	cmd.Flags().Bool("no-dane-ee", false, "Do not verify DANE-EE")
	cmd.Flags().Bool("dane-ta", false, "Verify DANE-TA")
	cmd.Flags().IntP("selector", "l", -1, "TLSA selector")
	cmd.Flags().IntP("matching-type", "m", 1, "TLSA matching type")
	cmd.Flags().String("starttls", "auto", "Connect handshake")
}

func verifyCmdWith(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{RunE: ResourceVerify}
	addVerifyFlags(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return cmd
}

func useLookup(t *testing.T, fn func(string) ([]tlsaRecord, error)) {
	t.Helper()
	original := lookupTLSA
	t.Cleanup(func() { lookupTLSA = original })
	lookupTLSA = fn
}

func TestResourceVerify_RequiresPort(t *testing.T) {
	cmd := verifyCmdWith(t, "--url", "example.com", "--subdomain", "mail", "--cert", "unused.pem")
	err := ResourceVerify(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no ports specified") {
		t.Fatalf("expected missing port error, got %v", err)
	}
}

func TestResourceVerify_RequiresAUsage(t *testing.T) {
	cmd := verifyCmdWith(t,
		"--url", "example.com",
		"--subdomain", "mail",
		"--tcp25",
		"--no-dane-ee",
		"--cert", "unused.pem",
	)
	err := ResourceVerify(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "DANE-EE or DANE-TA") {
		t.Fatalf("expected usage error, got %v", err)
	}
}

func TestResourceVerify_FileDANEMatchesDNS(t *testing.T) {
	ee, _ := generateTestCertificate(t, false)
	ca, _ := generateTestCertificate(t, true)
	certPath := writeCertsToPEMFile(t, "fullchain.pem", ee, ca)

	eeHash, err := certificateHash(ee, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	caHash, err := certificateHash(ca, 0, 1)
	if err != nil {
		t.Fatal(err)
	}

	// The file hash used when publishing must be the hash verify compares.
	publishedEE, publishedCA := getHash(certPath, 1, 1)
	if publishedEE != eeHash {
		t.Fatalf("DANE-EE hash drifted: file %s certificate %s", publishedEE, eeHash)
	}
	publishedEE, publishedCA = getHash(certPath, 0, 1)
	if publishedCA != caHash {
		t.Fatalf("DANE-TA hash drifted: file %s certificate %s", publishedCA, caHash)
	}

	var queried []string
	useLookup(t, func(name string) ([]tlsaRecord, error) {
		queried = append(queried, name)
		return []tlsaRecord{
			{Usage: 3, Selector: 1, MatchingType: 1, Certificate: strings.ToUpper(eeHash)},
			{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "0123"},
			{Usage: 2, Selector: 0, MatchingType: 1, Certificate: caHash},
			{Usage: 3, Selector: 0, MatchingType: 1, Certificate: "ignored"},
		}, nil
	})

	cmd := verifyCmdWith(t,
		"--url", "example.com",
		"--subdomain", "mail",
		"--tcp25",
		"--dane-ta",
		"--cert", certPath,
	)
	if err := ResourceVerify(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if len(queried) != 1 || queried[0] != "_25._tcp.mail.example.com" {
		t.Fatalf("queried %v", queried)
	}
}

func TestResourceVerify_FileMismatch(t *testing.T) {
	ee, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "leaf.pem", ee)
	useLookup(t, func(name string) ([]tlsaRecord, error) {
		return []tlsaRecord{
			{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		}, nil
	})

	cmd := verifyCmdWith(t,
		"--url", "example.com",
		"--subdomain", "mail",
		"--tcp25",
		"--cert", certPath,
	)
	err := ResourceVerify(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "does not match DNS") {
		t.Fatalf("expected mismatch, got %v", err)
	}
}

func TestResourceVerify_MissingTLSA(t *testing.T) {
	ee, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "leaf.pem", ee)
	useLookup(t, func(name string) ([]tlsaRecord, error) {
		return nil, nil
	})

	cmd := verifyCmdWith(t,
		"--url", "example.com",
		"--subdomain", "mail",
		"--tcp-port", "443",
		"--cert", certPath,
	)
	err := ResourceVerify(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "no matching TLSA record") {
		t.Fatalf("expected missing record, got %v", err)
	}
}

func TestResourceVerify_DANEWithoutTrustAnchor(t *testing.T) {
	ee, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "leaf.pem", ee)
	useLookup(t, func(name string) ([]tlsaRecord, error) {
		t.Fatal("DNS should not be queried without a trust anchor")
		return nil, nil
	})

	cmd := verifyCmdWith(t,
		"--url", "example.com",
		"--subdomain", "mail",
		"--tcp25",
		"--dane-ta",
		"--no-dane-ee",
		"--cert", certPath,
	)
	err := ResourceVerify(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("expected trust anchor error, got %v", err)
	}
}

func TestVerifyAgainstRecords_Report(t *testing.T) {
	report, err := verifyAgainstRecords("_25._tcp.mail.example.com", "certificate file chain.pem", []tlsaRecord{
		{Usage: 3, Selector: 1, MatchingType: 1, Certificate: "abc"},
	}, []verifyCheck{{
		Usage: 3, Selector: 1, MatchingType: 1, Hash: "abc",
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"TLSA _25._tcp.mail.example.com",
		"source: certificate file chain.pem",
		"DANE-EE (3 1 1): ok",
		"  computed: abc",
		"  dns: abc",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("report missing %q:\n%s", want, report)
		}
	}
}

func TestPeerCertificates_TLSAndSTARTTLS(t *testing.T) {
	ee, eeKey := generateTestCertificate(t, false)
	ca, _ := generateTestCertificate(t, true)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{ee.Raw, ca.Raw},
		PrivateKey:  eeKey,
		Leaf:        ee,
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	eeHash, err := certificateHash(ee, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	caHash, err := certificateHash(ca, 0, 1)
	if err != nil {
		t.Fatal(err)
	}

	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tlsLn.Close() })
	go acceptTLS(tlsLn)

	smtpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { smtpLn.Close() })
	go acceptSMTP(smtpLn, config)

	for _, tc := range []struct {
		addr string
		mode string
	}{
		{tlsLn.Addr().String(), "tls"},
		{smtpLn.Addr().String(), "smtp"},
	} {
		host, port, err := net.SplitHostPort(tc.addr)
		if err != nil {
			t.Fatal(err)
		}
		certs, source, err := peerCertificates(host, port, tc.mode)
		if err != nil {
			t.Fatalf("%s: %v", tc.mode, err)
		}
		if len(certs) != 2 {
			t.Fatalf("%s presented %d certificates", tc.mode, len(certs))
		}
		gotEE, err := certificateHash(certs[0], 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		gotCA, err := certificateHash(certs[len(certs)-1], 0, 1)
		if err != nil {
			t.Fatal(err)
		}
		if gotEE != eeHash || gotCA != caHash {
			t.Fatalf("%s hashes ee %s/%s ca %s/%s", tc.mode, gotEE, eeHash, gotCA, caHash)
		}
		if !strings.Contains(source, port) {
			t.Fatalf("source %q", source)
		}
	}
}

func acceptTLS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			tlsConn, ok := c.(*tls.Conn)
			if !ok {
				return
			}
			_ = tlsConn.Handshake()
		}(conn)
	}
}

func acceptSMTP(ln net.Listener, config *tls.Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = c.Write([]byte("220 localhost ESMTP\r\n"))
			if _, err := readSMTPLine(c); err != nil {
				return
			}
			_, _ = c.Write([]byte("250-localhost\r\n250 STARTTLS\r\n"))
			if _, err := readSMTPLine(c); err != nil {
				return
			}
			_, _ = c.Write([]byte("220 Ready to start TLS\r\n"))
			tlsConn := tls.Server(c, config)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			_ = tlsConn.Close()
		}(conn)
	}
}

func TestQueryTLSAFrom(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		_ = dns.ActivateAndServe(nil, pc, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Answer = append(m.Answer, &dns.TLSA{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeTLSA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  "abcd",
			})
			_ = w.WriteMsg(m)
		}))
	}()

	records, err := queryTLSAFrom("_25._tcp.mail.example.com", []string{pc.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Usage != 3 || records[0].Certificate != "abcd" {
		t.Fatalf("records %+v", records)
	}
}

func TestUseSMTPSTARTTLS(t *testing.T) {
	smtp25, err := useSMTPSTARTTLS("25", "auto")
	if err != nil || !smtp25 {
		t.Fatalf("port 25 auto = %v, %v", smtp25, err)
	}
	tls465, err := useSMTPSTARTTLS("465", "auto")
	if err != nil || tls465 {
		t.Fatalf("port 465 auto = %v, %v", tls465, err)
	}
	forced, err := useSMTPSTARTTLS("443", "smtp")
	if err != nil || !forced {
		t.Fatalf("forced smtp = %v, %v", forced, err)
	}
	_, err = useSMTPSTARTTLS("25", "starttls")
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestNormalizeHex(t *testing.T) {
	if got := normalizeHex("AB:CD ef"); got != "abcdef" {
		t.Fatalf("got %s", got)
	}
}

func TestCertificateHashMatchesOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}

	ee, _ := generateTestCertificate(t, false)
	ca, _ := generateTestCertificate(t, true)
	eePath := writeCertsToPEMFile(t, "ee.pem", ee)
	caPath := writeCertsToPEMFile(t, "ca.pem", ca)

	eeHash, err := certificateHash(ee, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	caHash, err := certificateHash(ca, 0, 1)
	if err != nil {
		t.Fatal(err)
	}

	eeOpenSSL := opensslDigest(t, fmt.Sprintf(
		"openssl x509 -in %q -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256",
		eePath,
	))
	caOpenSSL := opensslDigest(t, fmt.Sprintf(
		"openssl x509 -in %q -outform DER | openssl dgst -sha256",
		caPath,
	))
	if eeHash != eeOpenSSL {
		t.Fatalf("DANE-EE hash %s != openssl %s", eeHash, eeOpenSSL)
	}
	if caHash != caOpenSSL {
		t.Fatalf("DANE-TA hash %s != openssl %s", caHash, caOpenSSL)
	}
}

func opensslDigest(t *testing.T, command string) string {
	t.Helper()

	out, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl: %v\n%s", err, out)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		t.Fatalf("empty openssl output: %q", out)
	}
	return strings.ToLower(fields[len(fields)-1])
}
