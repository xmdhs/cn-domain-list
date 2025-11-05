package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/tidwall/gjson"
)

func dnsHttp(ctx context.Context, domain string, Type string) (string, error) {
	u, err := url.Parse("https://dns.alidns.com/resolve?name=example.com&type=1")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("name", domain)
	q.Set("type", Type)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	reps, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer reps.Body.Close()

	b, err := io.ReadAll(reps.Body)
	if err != nil {
		return "", err
	}
	return gjson.GetBytes(b, "Answer.@reverse.0.data").String(), nil
}

func getNsIp(ctx context.Context, domain string, nsIp *sync.Map) (string, error) {
	nsServer, err := dnsHttp(ctx, domain, "2")
	if err != nil {
		return "", err
	}
	v, ok := nsIp.Load(nsServer)
	if ok {
		return v.(string), nil
	}
	ip, err := dnsHttp(ctx, nsServer, "1")
	if err != nil {
		return "", err
	}
	nsIp.Store(nsServer, ip)
	return ip, nil
}
