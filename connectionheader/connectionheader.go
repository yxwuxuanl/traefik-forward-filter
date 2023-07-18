package connectionheader

import (
	"net/http"
	"net/textproto"
	"strings"
)

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
