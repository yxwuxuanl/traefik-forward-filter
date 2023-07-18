package traefik_forward_filter

import (
	"net"
	"net/http"
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
	if len(allowedHeaders) == 0 {
		for k, vv := range req.Header {
			forwardReq.Header[k] = append(req.Header[k], vv...)
		}
	} else {
		headers := make(http.Header)

		for _, header := range allowedHeaders {
			if v := req.Header.Get(header); v != "" {
				headers.Set(header, v)
			}
		}
		forwardReq.Header = headers
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
