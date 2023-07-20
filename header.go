package traefik_forward_filter

import (
	"net"
	"net/http"
	"net/textproto"
	"strings"
)

const (
	xForwardedMethod = "X-Forwarded-Method"
	XForwardedProto  = "X-Forwarded-Proto"
	XForwardedFor    = "X-Forwarded-For"
	XForwardedHost   = "X-Forwarded-Host"
	XForwardedUri    = "X-Forwarded-Uri"
	Connection       = "Connection"
	KeepAlive        = "Keep-Alive"
	Te               = "Te" // canonicalized version of "TE"
	Trailers         = "Trailers"
	TransferEncoding = "Transfer-Encoding"
	Upgrade          = "Upgrade"
)

var hopHeaders = []string{
	Connection,
	KeepAlive,
	Te, // canonicalized version of "TE"
	Trailers,
	TransferEncoding,
	Upgrade,
}

func writeHeader(req, forwardReq *http.Request, allowedHeaders []string) {
	forwardReq.Header = make(http.Header)

	if len(allowedHeaders) == 0 {
		for k, vv := range req.Header {
			forwardReq.Header[k] = append(req.Header[k], vv...)
		}
	} else {
		for _, header := range allowedHeaders {
			if v := req.Header.Get(header); v != "" {
				forwardReq.Header.Set(header, v)
			}
		}
	}

	for _, header := range hopHeaders {
		forwardReq.Header.Del(header)
	}

	forwardReq.Header.Set("Host", forwardReq.URL.Hostname())

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := req.Header[XForwardedFor]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		forwardReq.Header.Set(XForwardedFor, clientIP)
	}

	forwardReq.Header.Set(xForwardedMethod, req.Method)
	forwardReq.Header.Set(XForwardedHost, req.Host)
	forwardReq.Header.Set(XForwardedUri, req.RequestURI)

	if xfp := req.Header.Get(XForwardedProto); xfp != "" {
		forwardReq.Header.Set(XForwardedProto, xfp)
	} else {
		if req.TLS != nil {
			forwardReq.Header.Set(XForwardedProto, "https")
		} else {
			forwardReq.Header.Set(XForwardedProto, "http")
		}
	}
}

const (
	connectionHeader = "Connection"
	upgradeHeader    = "Upgrade"
)

// Remover removes hop-by-hop headers listed in the "Connection" header.
// See RFC 7230, section 6.1.
func Remover(next http.Handler) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		removeConnectionHeaders(req.Header)
		req.Header.Del(connectionHeader)
		next.ServeHTTP(rw, req)
	}
}

func removeConnectionHeaders(h http.Header) {
	for _, f := range h[connectionHeader] {
		for _, sf := range strings.Split(f, ",") {
			if sf = textproto.TrimString(sf); sf != "" {
				h.Del(sf)
			}
		}
	}
}
