package traefik_forward_filter

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	FailureIgnore = "ignore"
	FailureAbort  = "abort"
)

const DefaultForwardTimeout = time.Millisecond * 100

var defaultFailureStatusCode = []int{500, 502, 503, 504}

type Config struct {
	Address            string            `json:"address,omitempty"`
	InsecureSkipVerify bool              `json:"insecureSkipVerify,omitempty"`
	ForwardHeaders     map[string]string `json:"forwardHeaders"`
	RequestHeaders     []string          `json:"requestHeaders,omitempty"`
	RequestWithBody    bool              `json:"requestWithBody,omitempty"`
	RequestTimeout     int               `json:"requestTimeout,omitempty"`
	ResponseHeaders    []string          `json:"responseHeaders,omitempty"`
	FailurePolicy      string            `json:"failurePolicy,omitempty"`
	FailureStatusCode  []int             `json:"failureStatusCode"`
}

func CreateConfig() *Config {
	return &Config{}
}

type ForwardFilter struct {
	Config
	next   http.Handler
	client *http.Client
	u      url.URL
}

var requestPool = sync.Pool{New: func() any {
	return new(http.Request)
}}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	u, err := url.Parse(config.Address)

	if err != nil {
		return nil, err
	}

	var timeout time.Duration

	if config.RequestTimeout > 0 {
		timeout = time.Duration(config.RequestTimeout) * time.Millisecond
	} else {
		timeout = DefaultForwardTimeout
	}

	client := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	if config.InsecureSkipVerify {
		tr := http.DefaultTransport.(*http.Transport).Clone()

		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}

		client.Transport = tr
	}

	switch config.FailurePolicy {
	case "":
		config.FailurePolicy = FailureIgnore
	case FailureIgnore, FailureAbort:
	default:
		return nil, errors.New("illegal failurePolicy")
	}

	config.RequestHeaders = canonicalHeaders(config.RequestHeaders)
	config.ResponseHeaders = canonicalHeaders(config.ResponseHeaders)

	if len(config.FailureStatusCode) == 0 {
		config.FailureStatusCode = defaultFailureStatusCode
	}

	ff := &ForwardFilter{
		Config: *config,
		next:   next,
		client: client,
		u:      *u,
	}

	return Remover(ff), nil
}

func (f *ForwardFilter) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	forwardReq := requestPool.Get().(*http.Request)
	defer func() {
		forwardReq.Header = nil
		forwardReq.Body = nil
		forwardReq.URL = nil
		forwardReq.Method = http.MethodGet

		requestPool.Put(forwardReq)
	}()

	u := f.u

	if u.Path == "" {
		u.Path = r.RequestURI
	}

	forwardReq.URL = &u
	writeHeader(r, forwardReq, f.RequestHeaders)

	if f.ForwardHeaders != nil {
		for k, v := range f.ForwardHeaders {
			forwardReq.Header.Set("X-Forwarded-"+k, v)
		}
	}

	if f.RequestWithBody {
		buf := new(bytes.Buffer)
		teeReader := io.TeeReader(r.Body, buf)

		forwardReq.Body = io.NopCloser(teeReader)
		forwardReq.Method = http.MethodPost

		if ct := r.Header.Get("Content-Type"); ct != "" {
			forwardReq.Header.Set("Content-Type", ct)
		}

		r.Body = io.NopCloser(buf)
		defer r.Body.Close()
	}

	var isPass bool

	response, err := f.client.Do(forwardReq)
	defer func() {
		if isPass {
			return
		}

		if err != nil {
			log.Println(err.Error())

			if f.FailurePolicy == FailureIgnore {
				f.next.ServeHTTP(rw, r)
				return
			}

			if response == nil {
				rw.WriteHeader(http.StatusBadGateway)
				return
			}
		}

		// bad status || 2xx with respond
		for _, header := range f.ResponseHeaders {
			if v := response.Header.Get(header); v != "" {
				rw.Header().Set(header, v)
			}
		}

		rw.WriteHeader(response.StatusCode)

		if response.ContentLength > 0 {
			io.Copy(rw, response.Body)
			response.Body.Close()
		}
	}()

	if err != nil {
		return
	}

	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if response.ContentLength == 0 {
			for _, header := range f.ResponseHeaders {
				if v := response.Header.Get(header); v != "" {
					r.Header.Set(header, v)
				}
			}

			isPass = true
			f.next.ServeHTTP(rw, r)
			return
		}
	}

	for _, status := range f.FailureStatusCode {
		if response.StatusCode == status {
			err = errors.New(response.Status)
			break
		}
	}
}

func canonicalHeaders(headers []string) []string {
	var _headers []string
	for _, header := range headers {
		_headers = append(_headers, http.CanonicalHeaderKey(header))
	}
	return _headers
}
