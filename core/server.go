package core

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultPort           = "3478"
	AppName               = "Gateway Troubleshooting Guide"
	Version               = "1.3.0"
	maxLogValueLength     = 200
	maxRedirectQueryBytes = 2048
	maxRedirectHostLength = 253
	hstsHeaderValue       = "max-age=31536000; includeSubDomains"
)

func isProduction() bool {
	return os.Getenv("GO_ENV") == "production"
}

func ServeDevelopmentHTTP(srv *http.Server) error {
	if isProduction() {
		return fmt.Errorf("HTTP protocol prohibited in production environment")
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// startHTTPRedirectServer only runs in non-production deployments for legacy
// clients that still reach the service over HTTP.
func StartHTTPRedirectServer() {
	if isProduction() {
		log.Println("event=http_redirect_server_disabled reason=production")
		return
	}
	redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target, err := buildHTTPSRedirectTarget(r)
		if err != nil {
			log.Printf("event=http_redirect_rejected path=%q host=%q reason=%q",
				sanitizeForLog(r.URL.EscapedPath()),
				sanitizeForLog(r.Host),
				sanitizeForLog(err.Error()))
			http.Error(w, "Invalid redirect target", http.StatusBadRequest)
			return
		}
		log.Printf("event=http_to_https_redirect path=%q host=%q",
			sanitizeForLog(r.URL.EscapedPath()),
			sanitizeForLog(r.Host))
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})

	srv := &http.Server{
		Addr:              ":80",
		Handler:           redirectHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Printf("event=http_redirect_server_start_failed error=%q", sanitizeForLog(err.Error()))
		return
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("event=http_redirect_server_exited error=%q", sanitizeForLog(err.Error()))
	}
}

func buildHTTPSRedirectTarget(r *http.Request) (string, error) {
	if r == nil || r.URL == nil {
		return "", fmt.Errorf("request URL is required")
	}
	host, err := normalizeRedirectHost(r.Host)
	if err != nil {
		return "", err
	}
	redirectPath, err := cleanRedirectPath(r.URL.Path)
	if err != nil {
		return "", err
	}
	if containsControlCharacter(r.URL.RawQuery) {
		return "", fmt.Errorf("query contains control characters")
	}
	if len(r.URL.RawQuery) > maxRedirectQueryBytes {
		return "", fmt.Errorf("query is too long")
	}
	u := url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     redirectPath,
		RawQuery: r.URL.RawQuery,
	}
	return u.String(), nil
}

// sanitizeForLog removes control characters and bounds user-controlled values
// before they are written to application logs.
func sanitizeForLog(s string) string {
	var b strings.Builder
	truncated := false
	for _, r := range s {
		if b.Len() >= maxLogValueLength {
			truncated = true
			break
		}
		if unicode.IsControl(r) {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if out == "" {
		return ""
	}
	if len(out) > maxLogValueLength {
		out = out[:maxLogValueLength]
		truncated = true
	}
	if truncated {
		return out + "...[truncated]"
	}
	return out
}



func normalizeRedirectHost(rawHost string) (string, error) {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return "", fmt.Errorf("host is required")
	}
	if len(rawHost) > maxRedirectHostLength+6 {
		return "", fmt.Errorf("host is too long")
	}
	if strings.ContainsAny(rawHost, "\r\n\t /\\@") || strings.Contains(rawHost, "%") {
		return "", fmt.Errorf("host contains unsafe characters")
	}
	hostname, port, err := splitHostPortOptional(rawHost)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalRedirectHostname(hostname)
	if err != nil {
		return "", err
	}
	if !isInAllowedHosts(canonical) {
		return "", fmt.Errorf("host is not allowed")
	}
	if port != "" {
		if err := validateTCPPort(port); err != nil {
			return "", err
		}
		return net.JoinHostPort(canonical, port), nil
	}
	if strings.Contains(canonical, ":") {
		return "[" + canonical + "]", nil
	}
	return canonical, nil
}

func splitHostPortOptional(rawHost string) (string, string, error) {
	if strings.HasPrefix(rawHost, "[") {
		end := strings.LastIndex(rawHost, "]")
		if end <= 0 {
			return "", "", fmt.Errorf("invalid bracketed host")
		}
		host := rawHost[1:end]
		rest := rawHost[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("invalid host suffix")
		}
		port := strings.TrimPrefix(rest, ":")
		if port == "" {
			return "", "", fmt.Errorf("port is required after colon")
		}
		return host, port, nil
	}
	if strings.Count(rawHost, ":") > 1 {
		if net.ParseIP(rawHost) == nil {
			return "", "", fmt.Errorf("invalid host")
		}
		return rawHost, "", nil
	}
	if strings.Contains(rawHost, ":") {
		host, port, err := net.SplitHostPort(rawHost)
		if err == nil {
			if port == "" {
				return "", "", fmt.Errorf("port is required after colon")
			}
			return host, port, nil
		}
		host, port, ok := strings.Cut(rawHost, ":")
		if !ok || host == "" || port == "" {
			return "", "", fmt.Errorf("invalid host")
		}
		return host, port, nil
	}
	return rawHost, "", nil
}

func canonicalRedirectHostname(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", fmt.Errorf("hostname is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if len(host) > maxRedirectHostLength {
		return "", fmt.Errorf("hostname is too long")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("hostname has an invalid label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("hostname label cannot start or end with hyphen")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", fmt.Errorf("hostname contains invalid characters")
		}
	}
	return host, nil
}


func isInAllowedHosts(host string) bool {
	canonical, err := canonicalRedirectHostname(host)
	if err != nil {
		return false
	}
	allowedHostsStr := os.Getenv("GW_REDIRECT_ALLOWED_HOSTS")
	if allowedHostsStr == "" {
		return canonical == "localhost" ||
			canonical == "127.0.0.1" ||
			canonical == "::1" ||
			isPrivateIP(canonical)
	}

	allowedHosts := strings.Split(allowedHostsStr, ",")
	for _, allowedHost := range allowedHosts {
		hostname, _, err := splitHostPortOptional(strings.TrimSpace(allowedHost))
		if err != nil {
			continue
		}
		allowedCanonical, err := canonicalRedirectHostname(hostname)
		if err != nil {
			continue
		}
		if allowedCanonical == canonical {
			return true
		}
	}
	return false
}

// isPrivateIP 检查IP地址是否为内网地址
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// IPv4私有地址段
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 || // 10.0.0.0/8
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
			(ip4[0] == 192 && ip4[1] == 168) || // 192.168.0.0/16
			ip4[0] == 127 // 127.0.0.0/8
	}

	// IPv6私有地址段
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		(len(ip) == 16 && ip[0] == 0xfe && ip[1]&0xc0 == 0x80) // fe80::/10
}


func validateTCPPort(port string) error {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be in range 1-65535")
	}
	return nil
}

func cleanRedirectPath(rawPath string) (string, error) {
	if containsControlCharacter(rawPath) {
		return "", fmt.Errorf("path contains control characters")
	}
	if rawPath == "" {
		return "/", nil
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(rawPath, "/"))
	if cleaned == "." {
		return "/", nil
	}
	return cleaned, nil
}

func containsControlCharacter(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}






