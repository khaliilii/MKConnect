package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/khaliilii/MKConnect/internal/profile"
)

// certProbeTimeout limits the extra TLS handshake of pinPresentedCert.
const certProbeTimeout = 8 * time.Second

// skipsCertCheck reports whether an account asks for its server's certificate
// not to be checked at all (allowInsecure), with no pinned hash to check it
// by instead. Xray has no such mode any more: see PreferredCore.
func skipsCertCheck(p *profile.Profile) bool {
	return p.TLS.Mode == "tls" && p.TLS.Insecure && p.TLS.PinnedCertSHA256 == ""
}

// pinPresentedCert lets Xray run an account that skips the certificate check
// and that only Xray can carry (xhttp): it pins the certificate the server
// presents now. That accepts what skipping the check would accept, and is
// done anew for every connection, so a renewed certificate is no problem.
// It changes p, which must be the caller's own copy, not the stored account.
func pinPresentedCert(ctx context.Context, p *profile.Profile) error {
	if !skipsCertCheck(p) || p.Transport.Network != "xhttp" {
		return nil // anything else that skips the check belongs on sing-box
	}
	ctx, cancel := context.WithTimeout(ctx, certProbeTimeout)
	defer cancel()
	d := tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{
			ServerName:         orDefault(p.TLS.SNI, p.Server),
			NextProtos:         p.TLS.ALPN,
			InsecureSkipVerify: true, // what the account asks for; the hash is all this is for
		},
	}
	conn, err := d.DialContext(ctx, "tcp", p.Address())
	if err != nil {
		return fmt.Errorf("read the certificate of %s: %w", p.Name, err)
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("read the certificate of %s: the server sent none", p.Name)
	}
	sum := sha256.Sum256(certs[0].Raw)
	p.TLS.PinnedCertSHA256, p.TLS.Insecure = hex.EncodeToString(sum[:]), false
	log.Printf("ℹ️  %s skips the certificate check, which Xray can't: using the certificate its server presents now", p.Name)
	return nil
}
