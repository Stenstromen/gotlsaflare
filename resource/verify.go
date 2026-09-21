package resource

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

type tlsaRecord struct {
	Usage        int
	Selector     int
	MatchingType int
	Certificate  string
}

type verifyCheck struct {
	Usage        int
	Selector     int
	MatchingType int
	Hash         string
}

// lookupTLSA is replaced in tests.
var lookupTLSA = queryTLSA

func ResourceVerify(cmd *cobra.Command, args []string) error {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return err
	}
	subdomain, err := cmd.Flags().GetString("subdomain")
	if err != nil {
		return err
	}
	certPath, err := cmd.Flags().GetString("cert")
	if err != nil {
		return err
	}
	tcp25, err := cmd.Flags().GetBool("tcp25")
	if err != nil {
		return err
	}
	tcp465, err := cmd.Flags().GetBool("tcp465")
	if err != nil {
		return err
	}
	tcp587, err := cmd.Flags().GetBool("tcp587")
	if err != nil {
		return err
	}
	tcpPort, err := cmd.Flags().GetInt("tcp-port")
	if err != nil {
		return err
	}
	daneEE, err := cmd.Flags().GetBool("dane-ee")
	if err != nil {
		return err
	}
	noDaneEE, err := cmd.Flags().GetBool("no-dane-ee")
	if err != nil {
		return err
	}
	daneTa, err := cmd.Flags().GetBool("dane-ta")
	if err != nil {
		return err
	}
	selector, err := cmd.Flags().GetInt("selector")
	if err != nil {
		return err
	}
	matchingType, err := cmd.Flags().GetInt("matching-type")
	if err != nil {
		return err
	}
	starttls, err := cmd.Flags().GetString("starttls")
	if err != nil {
		return err
	}

	url = strings.TrimSpace(url)
	subdomain = strings.TrimSpace(subdomain)
	if url == "" || subdomain == "" {
		return fmt.Errorf("url and subdomain are required")
	}

	if noDaneEE {
		daneEE = false
	}
	if !daneEE && !daneTa {
		return fmt.Errorf("at least one of DANE-EE or DANE-TA must be enabled")
	}
	if matchingType != 1 && matchingType != 2 {
		return fmt.Errorf("matching type must be either 1 (SHA2-256) or 2 (SHA2-512)")
	}
	if selector != -1 && selector != 0 && selector != 1 {
		return fmt.Errorf("selector must be 0 (full certificate) or 1 (SubjectPublicKeyInfo)")
	}
	switch starttls {
	case "auto", "smtp", "tls":
	default:
		return fmt.Errorf("starttls must be auto, smtp, or tls")
	}

	ports, err := selectedPorts(tcpPort, tcp25, tcp465, tcp587)
	if err != nil {
		return err
	}

	eeSel, taSel := selector, selector
	if selector == -1 {
		eeSel = 1
		taSel = 0
	}

	host := subdomain + "." + url
	var fileCerts []*x509.Certificate
	var fileChecks []verifyCheck
	if certPath != "" {
		fileCerts, err = certsFromPEM(certPath)
		if err != nil {
			return err
		}
		fileChecks, err = associationChecks(fileCerts, daneEE, daneTa, eeSel, taSel, matchingType)
		if err != nil {
			return err
		}
	}

	var failed []error
	for _, port := range ports {
		certs := fileCerts
		checks := fileChecks
		source := "certificate file " + certPath
		if certPath == "" {
			certs, source, err = peerCertificates(host, port, starttls)
			if err != nil {
				failed = append(failed, fmt.Errorf("%s:%s: %w", host, port, err))
				continue
			}
			checks, err = associationChecks(certs, daneEE, daneTa, eeSel, taSel, matchingType)
			if err != nil {
				failed = append(failed, fmt.Errorf("%s:%s: %w", host, port, err))
				continue
			}
		}

		name := tlsaOwnerName(port, host)
		records, err := lookupTLSA(name)
		if err != nil {
			failed = append(failed, fmt.Errorf("TLSA lookup %s: %w", name, err))
			continue
		}

		report, err := verifyAgainstRecords(name, source, records, checks)
		fmt.Print(report)
		if err != nil {
			failed = append(failed, err)
		}
	}

	return errors.Join(failed...)
}

func selectedPorts(tcpPort int, tcp25, tcp465, tcp587 bool) ([]string, error) {
	var ports []string
	seen := map[string]bool{}
	add := func(port string) {
		if seen[port] {
			return
		}
		seen[port] = true
		ports = append(ports, port)
	}

	if tcpPort != 0 {
		if tcpPort < 1 || tcpPort > 65535 {
			return nil, fmt.Errorf("tcp-port must be between 1 and 65535")
		}
		add(strconv.Itoa(tcpPort))
	}
	if tcp25 {
		add("25")
	}
	if tcp465 {
		add("465")
	}
	if tcp587 {
		add("587")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports specified. Please specify at least one port using --tcp-port, --tcp25, --tcp465, or --tcp587")
	}
	return ports, nil
}

func tlsaOwnerName(port, host string) string {
	return "_" + port + "._tcp." + host
}

func associationChecks(certs []*x509.Certificate, daneEE, daneTa bool, eeSel, taSel, matchingType int) ([]verifyCheck, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates to verify")
	}

	var checks []verifyCheck
	if daneEE {
		hash, err := certificateHash(certs[0], eeSel, matchingType)
		if err != nil {
			return nil, err
		}
		checks = append(checks, verifyCheck{
			Usage:        3,
			Selector:     eeSel,
			MatchingType: matchingType,
			Hash:         hash,
		})
	}
	if daneTa {
		if len(certs) < 2 {
			return nil, fmt.Errorf("DANE-TA needs the trust anchor certificate (the last certificate in the chain)")
		}
		hash, err := certificateHash(certs[len(certs)-1], taSel, matchingType)
		if err != nil {
			return nil, err
		}
		checks = append(checks, verifyCheck{
			Usage:        2,
			Selector:     taSel,
			MatchingType: matchingType,
			Hash:         hash,
		})
	}
	return checks, nil
}

func verifyAgainstRecords(name, source string, records []tlsaRecord, checks []verifyCheck) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "TLSA %s\n", name)
	fmt.Fprintf(&b, "source: %s\n", source)

	var failed []error
	for _, check := range checks {
		label := daneLabel(check.Usage, check.Selector, check.MatchingType)
		ok, relevant := matchTLSA(records, check)
		fmt.Fprintf(&b, "%s: %s\n", label, resultWord(ok))
		fmt.Fprintf(&b, "  computed: %s\n", check.Hash)
		if len(relevant) == 0 {
			fmt.Fprintf(&b, "  dns: (none)\n")
		}
		for _, record := range relevant {
			fmt.Fprintf(&b, "  dns: %s\n", normalizeHex(record.Certificate))
		}
		if !ok {
			if len(relevant) == 0 {
				failed = append(failed, fmt.Errorf("%s at %s: no matching TLSA record", label, name))
			} else {
				failed = append(failed, fmt.Errorf("%s at %s: computed hash does not match DNS", label, name))
			}
		}
	}

	return b.String(), errors.Join(failed...)
}

func resultWord(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func daneLabel(usage, selector, matchingType int) string {
	params := fmt.Sprintf("%d %d %d", usage, selector, matchingType)
	switch usage {
	case 2:
		return "DANE-TA (" + params + ")"
	case 3:
		return "DANE-EE (" + params + ")"
	default:
		return "TLSA (" + params + ")"
	}
}

func matchTLSA(records []tlsaRecord, check verifyCheck) (bool, []tlsaRecord) {
	want := normalizeHex(check.Hash)
	var relevant []tlsaRecord
	matched := false
	for _, record := range records {
		if record.Usage != check.Usage || record.Selector != check.Selector || record.MatchingType != check.MatchingType {
			continue
		}
		relevant = append(relevant, record)
		if normalizeHex(record.Certificate) == want {
			matched = true
		}
	}
	return matched, relevant
}

func normalizeHex(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, ":", "")
	return value
}

func certsFromPEM(path string) ([]*x509.Certificate, error) {
	pemContent, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	rest := pemContent
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}
	return certs, nil
}

func peerCertificates(host, port, mode string) ([]*x509.Certificate, string, error) {
	useSMTP, err := useSMTPSTARTTLS(port, mode)
	if err != nil {
		return nil, "", err
	}

	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, "", err
	}

	tlsConfig := &tls.Config{
		ServerName: host,
		// DANE-EE does not require a public PKIX trust anchor. The TLSA
		// association data checked below is the authentication.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	source := addr + " (TLS)"
	var tlsConn *tls.Conn
	if useSMTP {
		source = addr + " (SMTP STARTTLS)"
		tlsConn, err = smtpStartTLS(conn, tlsConfig)
	} else {
		tlsConn = tls.Client(conn, tlsConfig)
		err = tlsConn.Handshake()
	}
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	defer tlsConn.Close()

	peer := tlsConn.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		return nil, "", fmt.Errorf("server %s presented no certificates", addr)
	}
	certs := make([]*x509.Certificate, len(peer))
	copy(certs, peer)
	return certs, source, nil
}

func useSMTPSTARTTLS(port, mode string) (bool, error) {
	switch mode {
	case "smtp":
		return true, nil
	case "tls":
		return false, nil
	case "auto", "":
		return port == "25" || port == "587", nil
	default:
		return false, fmt.Errorf("starttls must be auto, smtp, or tls")
	}
}

func smtpStartTLS(conn net.Conn, tlsConfig *tls.Config) (*tls.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}

	code, err := readSMTP(conn)
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, fmt.Errorf("SMTP greeting: expected 220, got %d", code)
	}
	if _, err := fmt.Fprintf(conn, "EHLO gotlsaflare\r\n"); err != nil {
		return nil, err
	}
	code, err = readSMTP(conn)
	if err != nil {
		return nil, err
	}
	if code != 250 {
		return nil, fmt.Errorf("SMTP EHLO: expected 250, got %d", code)
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return nil, err
	}
	code, err = readSMTP(conn)
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return nil, fmt.Errorf("SMTP STARTTLS: expected 220, got %d", code)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

// readSMTP reads one SMTP reply without buffering past it, so the following
// TLS handshake still sees every byte.
func readSMTP(conn net.Conn) (int, error) {
	for {
		line, err := readSMTPLine(conn)
		if err != nil {
			return 0, err
		}
		if len(line) < 4 {
			return 0, fmt.Errorf("short SMTP response %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, fmt.Errorf("invalid SMTP response %q", line)
		}
		switch line[3] {
		case ' ':
			return code, nil
		case '-':
			continue
		default:
			return 0, fmt.Errorf("invalid SMTP response %q", line)
		}
	}
}

func readSMTPLine(conn net.Conn) (string, error) {
	buf := make([]byte, 0, 128)
	tmp := make([]byte, 1)
	for len(buf) < 4096 {
		n, err := conn.Read(tmp)
		if n == 1 {
			buf = append(buf, tmp[0])
			if tmp[0] == '\n' {
				return string(buf), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("SMTP response line too long")
}

func queryTLSA(name string) ([]tlsaRecord, error) {
	return queryTLSAFrom(name, resolverServers())
}

func resolverServers() []string {
	var servers []string
	seen := map[string]bool{}
	add := func(server string) {
		if server == "" || seen[server] {
			return
		}
		seen[server] = true
		servers = append(servers, server)
	}

	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		for _, server := range cfg.Servers {
			add(net.JoinHostPort(server, cfg.Port))
		}
	}
	add("1.1.1.1:53")
	add("8.8.8.8:53")
	return servers
}

func queryTLSAFrom(name string, servers []string) ([]tlsaRecord, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("no DNS resolvers available")
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
	m.RecursionDesired = true

	var lastErr error
	for _, server := range servers {
		client := &dns.Client{Timeout: 5 * time.Second}
		response, _, err := client.Exchange(m, server)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", server, err)
			continue
		}
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("%s: %s", server, dns.RcodeToString[response.Rcode])
			continue
		}
		return tlsaFromMessage(response), nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("TLSA lookup %s failed", name)
}

func tlsaFromMessage(response *dns.Msg) []tlsaRecord {
	if response == nil {
		return nil
	}
	var records []tlsaRecord
	for _, answer := range response.Answer {
		tlsa, ok := answer.(*dns.TLSA)
		if !ok {
			continue
		}
		records = append(records, tlsaRecord{
			Usage:        int(tlsa.Usage),
			Selector:     int(tlsa.Selector),
			MatchingType: int(tlsa.MatchingType),
			Certificate:  tlsa.Certificate,
		})
	}
	return records
}
