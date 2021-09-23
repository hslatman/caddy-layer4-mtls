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
	"crypto/tls"
	"crypto/x509"

	"github.com/caddyserver/caddy/v2"
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
	m.extractMTLSMeta(cx)
	return next.Handle(cx)
}

func (m *Extractor) extractMTLSMeta(cx *layer4.Connection) error {
	var (
		conn *tls.Conn
		ok   bool
	)
	if conn, ok = cx.Conn.(*tls.Conn); !ok {
		m.logger.Debug("cx is not a *tls.Conn")
		return nil // fail soft
	}

	state := conn.ConnectionState()
	peerCertificates := state.PeerCertificates
	if len(peerCertificates) == 0 {
		m.logger.Debug("no mTLS peer certificates found")
		return nil // fail soft
	}

	meta := Meta{
		Certificates: peerCertificates,
	}
	cx.SetVar("mtls_meta", meta) // TODO: decide if this is the way to go for this

	// TODO: fill placeholder values, similar to the tls.client placeholders?

	return nil
}

// Interface guards
var (
	_ caddy.Module       = (*Extractor)(nil)
	_ caddy.Provisioner  = (*Extractor)(nil)
	_ layer4.NextHandler = (*Extractor)(nil)
)
