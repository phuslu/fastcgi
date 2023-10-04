// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fastcgi

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Handler facilitates FastCGI communication.
type Handler struct {
	// Use this directory as the fastcgi root directory. Defaults to the root
	// directory of the parent virtual host.
	Root string `json:"root,omitempty"`

	// The path in the URL will be split into two, with the first piece ending
	// with the value of SplitPath. The first piece will be assumed as the
	// actual resource (CGI script) name, and the second piece will be set to
	// PATH_INFO for the CGI script to use.
	//
	// Future enhancements should be careful to avoid CVE-2019-11043,
	// which can be mitigated with use of a try_files-like behavior
	// that 404s if the fastcgi path info is not found.
	SplitPath []string `json:"split_path,omitempty"`

	// Path declared as root directory will be resolved to its absolute value
	// after the evaluation of any symbolic links.
	// Due to the nature of PHP opcache, root directory path is cached: when
	// using a symlinked directory as root this could generate errors when
	// symlink is changed without php-fpm being restarted; enabling this
	// directive will set $_SERVER['DOCUMENT_ROOT'] to the real directory path.
	ResolveRootSymlink bool `json:"resolve_root_symlink,omitempty"`

	// Extra environment variables.
	EnvVars map[string]string `json:"env,omitempty"`

	// The duration used to set a deadline when connecting to an upstream. Default: `3s`.
	DialTimeout time.Duration `json:"dial_timeout,omitempty"`

	// The duration used to set a deadline when reading from the FastCGI server.
	ReadTimeout time.Duration `json:"read_timeout,omitempty"`

	// The duration used to set a deadline when sending to the FastCGI server.
	WriteTimeout time.Duration `json:"write_timeout,omitempty"`

	// Capture and log any messages sent by the upstream on stderr. Logs at WARN
	// level by default. If the response has a 4xx or 5xx status ERROR level will
	// be used instead.
	CaptureStderr bool `json:"capture_stderr,omitempty"`

	ServerSoftware string

	Logger *slog.Logger
}

// Provision sets up h.
func (h *Handler) Provision(ctx context.Context) error {
	if h.Root == "" {
		h.Root = "{http.vars.root}"
	}

	if h.ServerSoftware == "" {
		h.ServerSoftware = "GoFastCGI/1.0.0"
	}

	if h.Logger == nil {
		h.Logger = slog.Default()
	}

	// Set a relatively short default dial timeout.
	// This is helpful to make load-balancer retries more speedy.
	if h.DialTimeout == 0 {
		h.DialTimeout = time.Duration(3 * time.Second)
	}

	return nil
}

// RoundTrip implements http.RoundTripper.
func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Disallow null bytes in the request path, because
	// PHP upstreams may do bad things, like execute a
	// non-PHP file as PHP code. See #4574
	if strings.Contains(req.URL.Path, "\x00") {
		http.Error(rw, "invalid request path", http.StatusBadRequest)
		return
	}

	env, err := h.buildEnv(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("building environment: %v", err), http.StatusInternalServerError)
		return
	}

	ctx := req.Context()

	// extract dial information from request (should have been embedded by the reverse proxy)
	network, address := "tcp", req.URL.Host

	loggableEnv := loggableEnv{EnvVars: env, LogCredentials: true}

	logger := h.Logger.With(
		"request", req,
		"env", loggableEnv,
	)
	logger.Debug("roundtrip",
		"dial", address,
		"env", loggableEnv,
		"request", req,
	)

	// connect to the backend
	dialer := net.Dialer{Timeout: time.Duration(h.DialTimeout)}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		http.Error(rw, fmt.Sprintf("dialing backend: %v", err), http.StatusBadGateway)
		return
	}
	defer func() {
		// conn will be closed with the response body unless there's an error
		if err != nil {
			conn.Close()
		}
	}()

	// create the client that will facilitate the protocol
	client := client{
		rwc:    conn,
		reqID:  1,
		logger: logger,
		stderr: h.CaptureStderr,
	}

	// read/write timeouts
	if err = client.SetReadTimeout(time.Duration(h.ReadTimeout)); err != nil {
		http.Error(rw, fmt.Sprintf("setting read timeout: %v", err), http.StatusBadGateway)
		return
	}
	if err = client.SetWriteTimeout(time.Duration(h.WriteTimeout)); err != nil {
		http.Error(rw, fmt.Sprintf("setting write timeout: %v", err), http.StatusBadGateway)
		return
	}

	contentLength := req.ContentLength
	if contentLength == 0 {
		contentLength, _ = strconv.ParseInt(req.Header.Get("Content-Length"), 10, 64)
	}

	var resp *http.Response
	switch req.Method {
	case http.MethodHead:
		resp, err = client.Head(env)
	case http.MethodGet:
		resp, err = client.Get(env, req.Body, contentLength)
	case http.MethodOptions:
		resp, err = client.Options(env)
	default:
		resp, err = client.Post(env, req.Method, req.Header.Get("Content-Type"), req.Body, contentLength)
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	io.Copy(rw, resp.Body)

	return
}

// buildEnv returns a set of CGI environment variables for the request.
func (h *Handler) buildEnv(req *http.Request) (envVars, error) {

	var env envVars

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.LastIndex(req.RemoteAddr, ":"); idx > -1 {
		ip = req.RemoteAddr[:idx]
		port = req.RemoteAddr[idx+1:]
	} else {
		ip = req.RemoteAddr
	}

	// Remove [] from IPv6 addresses
	ip = strings.Replace(ip, "[", "", 1)
	ip = strings.Replace(ip, "]", "", 1)

	// make sure file root is absolute
	root, err := filepath.Abs(filepath.FromSlash(h.Root))
	if err != nil {
		return nil, err
	}

	if h.ResolveRootSymlink {
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			return nil, err
		}
	}

	fpath := req.URL.Path
	scriptName := fpath

	docURI := fpath
	// split "actual path" from "path info" if configured
	var pathInfo string
	if splitPos := h.splitPos(fpath); splitPos > -1 {
		docURI = fpath[:splitPos]
		pathInfo = fpath[splitPos:]

		// Strip PATH_INFO from SCRIPT_NAME
		scriptName = strings.TrimSuffix(scriptName, pathInfo)
	}

	// SCRIPT_FILENAME is the absolute path of SCRIPT_NAME
	scriptFilename := filepath.Join(h.Root, scriptName)

	// Ensure the SCRIPT_NAME has a leading slash for compliance with RFC3875
	// Info: https://tools.ietf.org/html/rfc3875#section-4.1.13
	if scriptName != "" && !strings.HasPrefix(scriptName, "/") {
		scriptName = "/" + scriptName
	}

	// Get the request URL from context. The context stores the original URL in case
	// it was changed by a middleware such as rewrite. By default, we pass the
	// original URI in as the value of REQUEST_URI (the user can overwrite this
	// if desired). Most PHP apps seem to want the original URI. Besides, this is
	// how nginx defaults: http://stackoverflow.com/a/12485156/1048862
	// origReq := req.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)

	requestScheme := "http"
	if req.TLS != nil {
		requestScheme = "https"
	}

	reqHost, reqPort, err := net.SplitHostPort(req.Host)
	if err != nil {
		// whatever, just assume there was no port
		reqHost = req.Host
	}

	// authUser, _ := repl.GetString("http.auth.user.id")
	authUser := ""

	// Some variables are unused but cleared explicitly to prevent
	// the parent environment from interfering.
	env = envVars{
		// Variables defined in CGI 1.1 spec
		"AUTH_TYPE":         "", // Not used
		"CONTENT_LENGTH":    req.Header.Get("Content-Length"),
		"CONTENT_TYPE":      req.Header.Get("Content-Type"),
		"GATEWAY_INTERFACE": "CGI/1.1",
		"PATH_INFO":         pathInfo,
		"QUERY_STRING":      req.URL.RawQuery,
		"REMOTE_ADDR":       ip,
		"REMOTE_HOST":       ip, // For speed, remote host lookups disabled
		"REMOTE_PORT":       port,
		"REMOTE_IDENT":      "", // Not used
		"REMOTE_USER":       authUser,
		"REQUEST_METHOD":    req.Method,
		"REQUEST_SCHEME":    requestScheme,
		"SERVER_NAME":       reqHost,
		"SERVER_PROTOCOL":   req.Proto,
		"SERVER_SOFTWARE":   h.ServerSoftware,

		// Other variables
		"DOCUMENT_ROOT":   root,
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       req.Host, // added here, since not always part of headers
		"REQUEST_URI":     req.RequestURI,
		"SCRIPT_FILENAME": scriptFilename,
		"SCRIPT_NAME":     scriptName,
	}

	// compliance with the CGI specification requires that
	// PATH_TRANSLATED should only exist if PATH_INFO is defined.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 14
	// if env["PATH_INFO"] != "" {
	// 	env["PATH_TRANSLATED"] = caddyhttp.SanitizedPathJoin(root, pathInfo) // Info: http://www.oreilly.com/openbook/cgi/ch02_04.html
	// }

	// compliance with the CGI specification requires that
	// the SERVER_PORT variable MUST be set to the TCP/IP port number on which this request is received from the client
	// even if the port is the default port for the scheme and could otherwise be omitted from a URI.
	// https://tools.ietf.org/html/rfc3875#section-4.1.15
	if reqPort != "" {
		env["SERVER_PORT"] = reqPort
	} else if requestScheme == "http" {
		env["SERVER_PORT"] = "80"
	} else if requestScheme == "https" {
		env["SERVER_PORT"] = "443"
	}

	// Some web apps rely on knowing HTTPS or not
	if req.TLS != nil {
		env["HTTPS"] = "on"
		// and pass the protocol details in a manner compatible with apache's mod_ssl
		// (which is why these have a SSL_ prefix and not TLS_).
		v, ok := tlsProtocolStrings[req.TLS.Version]
		if ok {
			env["SSL_PROTOCOL"] = v
		}
		// and pass the cipher suite in a manner compatible with apache's mod_ssl
		// for _, cs := range caddytls.SupportedCipherSuites() {
		// 	if cs.ID == req.TLS.CipherSuite {
		// 		env["SSL_CIPHER"] = cs.Name
		// 		break
		// 	}
		// }
	}

	// Add env variables from config (with support for placeholders in values)
	for key, value := range h.EnvVars {
		env[key] = value
	}

	// Add all HTTP headers to env variables
	for field, val := range req.Header {
		header := strings.ToUpper(field)
		header = headerNameReplacer.Replace(header)
		env["HTTP_"+header] = strings.Join(val, ", ")
	}
	return env, nil
}

// splitPos returns the index where path should
// be split based on h.SplitPath.
func (h *Handler) splitPos(path string) int {
	// TODO: from v1...
	// if httpserver.CaseSensitivePath {
	// 	return strings.Index(path, req.SplitPath)
	// }
	if len(h.SplitPath) == 0 {
		return 0
	}

	lowerPath := strings.ToLower(path)
	for _, split := range h.SplitPath {
		if idx := strings.Index(lowerPath, strings.ToLower(split)); idx > -1 {
			return idx + len(split)
		}
	}
	return -1
}

type envVars map[string]string

// loggableEnv is a simple type to allow for speeding up zap log encoding.
type loggableEnv struct {
	EnvVars        envVars
	LogCredentials bool
}

// Map of supported protocols to Apache ssl_mod format
// Note that these are slightly different from SupportedProtocols in caddytls/config.go
var tlsProtocolStrings = map[uint16]string{
	tls.VersionTLS10: "TLSv1",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")

// Interface guards
var (
	_ http.Handler = (*Handler)(nil)
)
