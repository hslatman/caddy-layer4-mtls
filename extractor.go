// Copyright 2021 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mtls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Extractor{})
}

type Meta struct {
	Certificates []*x509.Certificate
}

// Extractor is able to extract mTLS connection information and
// stores it in the Context of the Connection, so that it can be
// used by the next handler(s) in the chain.
type Extractor struct {
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Extractor) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.mtls_extractor",
		New: func() caddy.Module { return new(Extractor) },
	}
}

// Provision sets up the handler.
func (m *Extractor) Provision(ctx caddy.Context) error {

	m.logger = ctx.Logger(m)
	defer m.logger.Sync()

	return nil
}

// Handle handles the downstream connection.
func (m *Extractor) Handle(cx *layer4.Connection, next layer4.Handler) error {
	repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
	addTLSVarsToReplacer(repl, cx)
	return next.Handle(cx)
}

const reqTLSReplPrefix = "l4.tls."

// addTLSVarsToReplacer extracts (m)TLS information from a Connection and
// adds these variables to the replacer, similar to what is done for the
// {http.request.tls.*} variables in the http app. The layer4 variables
// are prefixed with "l4.tls." instead, but use the same suffixes.
// Adapted from: github.com/caddyserver/caddy/v2/modules/caddyhttp/replacer.go
func addTLSVarsToReplacer(repl *caddy.Replacer, cx *layer4.Connection) {
	tlsVars := func(key string) (interface{}, bool) {
		if cx != nil {
			// l4.tls.*
			if strings.HasPrefix(key, reqTLSReplPrefix) {
				return getReqTLSReplacement(cx, key)
			}
		}
		return nil, false
	}
	repl.Map(tlsVars)
}

// getReqTLSReplacement determines the value for the variable with key based
// on information in the Connection
// Adapted from: github.com/caddyserver/caddy/v2/modules/caddyhttp/replacer.go
func getReqTLSReplacement(cx *layer4.Connection, key string) (interface{}, bool) {

	if cx == nil {
		return nil, false
	}

	if len(key) < len(reqTLSReplPrefix) {
		return nil, false
	}

	field := strings.ToLower(key[len(reqTLSReplPrefix):])

	var (
		conn *tls.Conn
		ok   bool
	)
	if conn, ok = cx.Conn.(*tls.Conn); !ok {
		return nil, false
	}
	cs := conn.ConnectionState()

	if strings.HasPrefix(field, "client.") {
		cert := getTLSPeerCert(&cs)
		if cert == nil {
			return nil, false
		}

		// subject alternate names (SANs)
		if strings.HasPrefix(field, "client.san.") {
			field = field[len("client.san."):]
			var fieldName string
			var fieldValue interface{}
			switch {
			case strings.HasPrefix(field, "dns_names"):
				fieldName = "dns_names"
				fieldValue = cert.DNSNames
			case strings.HasPrefix(field, "emails"):
				fieldName = "emails"
				fieldValue = cert.EmailAddresses
			case strings.HasPrefix(field, "ips"):
				fieldName = "ips"
				fieldValue = cert.IPAddresses
			case strings.HasPrefix(field, "uris"):
				fieldName = "uris"
				fieldValue = cert.URIs
			default:
				return nil, false
			}
			field = field[len(fieldName):]

			// if no index was specified, return the whole list
			if field == "" {
				return fieldValue, true
			}
			if len(field) < 2 || field[0] != '.' {
				return nil, false
			}
			field = field[1:] // trim '.' between field name and index

			// get the numeric index
			idx, err := strconv.Atoi(field)
			if err != nil || idx < 0 {
				return nil, false
			}

			// access the indexed element and return it
			switch v := fieldValue.(type) {
			case []string:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			case []net.IP:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			case []*url.URL:
				if idx >= len(v) {
					return nil, true
				}
				return v[idx], true
			}
		}

		switch field {
		case "client.fingerprint":
			return fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), true
		case "client.public_key", "client.public_key_sha256":
			if cert.PublicKey == nil {
				return nil, true
			}
			pubKeyBytes, err := marshalPublicKey(cert.PublicKey)
			if err != nil {
				return nil, true
			}
			if strings.HasSuffix(field, "_sha256") {
				return fmt.Sprintf("%x", sha256.Sum256(pubKeyBytes)), true
			}
			return fmt.Sprintf("%x", pubKeyBytes), true
		case "client.issuer":
			return cert.Issuer, true
		case "client.serial":
			return cert.SerialNumber, true
		case "client.subject":
			return cert.Subject, true
		case "client.certificate_pem":
			block := pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
			return pem.EncodeToMemory(&block), true
		default:
			return nil, false
		}
	}

	switch field {
	case "version":
		return caddytls.ProtocolName(cs.Version), true
	case "cipher_suite":
		return tls.CipherSuiteName(cs.CipherSuite), true
	case "resumed":
		return cs.DidResume, true
	case "proto":
		return cs.NegotiatedProtocol, true
	case "proto_mutual":
		// req.TLS.NegotiatedProtocolIsMutual is deprecated - it's always true.
		return true, true
	case "server_name":
		return cs.ServerName, true
	}
	return nil, false
}

// marshalPublicKey returns the byte encoding of pubKey.
// Source: github.com/caddyserver/caddy/v2/modules/caddyhttp/replacer.go
func marshalPublicKey(pubKey interface{}) ([]byte, error) {
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		return asn1.Marshal(key)
	case *ecdsa.PublicKey:
		return elliptic.Marshal(key.Curve, key.X, key.Y), nil
	case ed25519.PublicKey:
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized public key type: %T", pubKey)
}

// getTLSPeerCert retrieves the first peer certificate from a TLS session.
// Returns nil if no peer cert is in use.
// Source: github.com/caddyserver/caddy/v2/modules/caddyhttp/replacer.go
func getTLSPeerCert(cs *tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}

// Interface guards
var (
	_ caddy.Module       = (*Extractor)(nil)
	_ caddy.Provisioner  = (*Extractor)(nil)
	_ layer4.NextHandler = (*Extractor)(nil)
)
