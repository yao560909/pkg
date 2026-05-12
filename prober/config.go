package prober

import (
	"crypto/tls"
	"crypto/x509"
)

type Probe struct {
	// Target is the address of the EMQX node to probe. Required.
	Target string
	// Scheme is the protocol scheme of the EMQX node to probe.
	// Enum: [mqtt | tcp | mqtts | ssl | tls | ws | wss]
	// Default: tcp
	Scheme string
	// ClientID is the MQTT client ID to use when probing.
	// Default: emqx_exporter_probe_<index>
	ClientID string
	// Username is the MQTT username to use when probing.
	Username string
	// Password is the MQTT password to use when probing.
	Password string
	// Topic is the MQTT topic to use when probing.
	// Default: emqx-exporter-probe-<index>
	Topic string
	// QoS is the MQTT QoS to use when probing.
	// Default: 0
	QoS byte
	// KeepAlive is the keep alive period in seconds. Defaults to 30 seconds.
	KeepAlive int64
	// TLSClientConfig is the TLS configuration to use when probing.
	TLSClientConfig *TLSClientConfig
}

type TLSClientConfig struct {
	// Server should be accessed without verifying the TLS certificate. For testing only.
	InsecureSkipVerify bool

	// Server requires TLS client certificate authentication
	CertFile string
	// Server requires TLS client certificate authentication
	KeyFile string
	// Trusted root certificates for server
	CAFile string

	// CertData holds PEM-encoded bytes (typically read from a client certificate file).
	// CertData takes precedence over CertFile
	CertData []byte
	// KeyData holds PEM-encoded bytes (typically read from a client certificate key file).
	// KeyData takes precedence over KeyFile
	KeyData []byte
	// CAData holds PEM-encoded bytes (typically read from a root certificates bundle).
	// CAData takes precedence over CAFile
	CAData []byte
}

func (conf *TLSClientConfig) ToTLSConfig() *tls.Config {
	if conf == nil {
		return nil
	}
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(conf.CAData)
	clientKeyPair, _ := tls.X509KeyPair(conf.CertData, conf.KeyData)
	return &tls.Config{
		InsecureSkipVerify: conf.InsecureSkipVerify,
		RootCAs:            certpool,
		Certificates:       []tls.Certificate{clientKeyPair},
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
	}
}
