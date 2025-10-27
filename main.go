package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/goccy/go-yaml"
	"github.com/oschwald/geoip2-golang"
	"github.com/samber/lo"
	"github.com/schollz/progressbar/v3"
	"github.com/tidwall/gjson"
	"golang.org/x/sync/errgroup"
)

func main() {
	b := lo.Must(os.ReadFile("cloudflare-radar_top-1000000-domains.csv"))
	set := geosite()

	db := lo.Must(geoip2.Open("GeoLite2-Country.mmdb"))
	defer db.Close()

	ctx := context.Background()

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(64)

	dl, last := readLog(set)
	dlLock := &sync.Mutex{}

	sl := strings.Split(string(b), "\n")
	donmainLen := len(sl)

	f := lo.Must(os.OpenFile("domain.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644))
	defer f.Close()

	bar := progressbar.Default(int64(donmainLen))
	skip := last != ""
	for _, txt := range sl {
		if skip && last == txt {
			bar.Add(1)
			skip = false
		}
		if skip {
			bar.Add(1)
			continue
		}
		if _, ok := set[txt]; ok {
			bar.Add(1)
			continue
		}
		g.Go(func() error {
			defer bar.Add(1)
			return retry.Do(func() error {
				ctx, cancel := context.WithTimeout(gCtx, 10*time.Second)
				defer cancel()
				addrs := []string{txt, "www." + txt}
				var addr string
				var err error
				for _, a := range addrs {
					addr, err = dnsHttp(ctx, a)
					if err != nil {
						return err
					}
					if addr != "" {
						break
					}
				}
				if addr == "" {
					return nil
				}
				netip := net.ParseIP(addr)
				if netip == nil {
					return nil
				}
				c := lo.Must(db.Country(netip))
				if c.Country.IsoCode == "CN" {
					dlLock.Lock()
					dl = append(dl, txt)
					lo.Must(f.WriteString(txt + "\n"))
					dlLock.Unlock()
				}
				return nil
			}, retryOpts...)
		})
	}
	lo.Must0(g.Wait())
	slices.Sort(dl)
	uList := lo.Uniq(dl)
	uMap := make(map[string]struct{})
	uList = lo.Filter(uList, func(item string, index int) bool {
		uMap[item] = struct{}{}
		return item != ""
	})

	writeRuleFile(uList, "ext-cn-list")

	slices.Sort(sl)
	nCnList := lo.Uniq(sl)
	nCnList = lo.Filter(nCnList, func(item string, index int) bool {
		_, ok := uMap[item]
		return !ok
	})
	writeRuleFile(nCnList, "ext-not-cn-list")

	domainGroups := make(map[string][]string)
	for _, domain := range uList {
		hasher := sha256.New()
		hasher.Write([]byte(domain))
		hash := hex.EncodeToString(hasher.Sum(nil))
		firstChar := string(hash[0])
		domainGroups[firstChar] = append(domainGroups[firstChar], domain)
	}

	lo.Must0(os.MkdirAll("site", 0755))

	for char, domains := range domainGroups {
		geoData := geo{
			Version: 2,
			Rules: []rule{
				{
					DomainSuffix: domains,
				},
			},
		}
		filePath := "site/" + char + ".json"
		nf, err := os.Create(filePath)
		if err != nil {
			log.Printf("Failed to create file %s: %v", filePath, err)
			continue
		}
		defer nf.Close()

		e := json.NewEncoder(nf)
		e.SetIndent("", "    ")
		e.SetEscapeHTML(false)
		if err := e.Encode(geoData); err != nil {
			log.Printf("Failed to write to file %s: %v", filePath, err)
		}
	}
}

func writeRuleFile(dl []string, fileName string) {
	geoData := geo{
		Version: 2,
		Rules: []rule{
			{
				DomainSuffix: dl,
			},
		},
	}
	nf := lo.Must(os.Create(fileName + ".json"))
	defer nf.Close()
	e := json.NewEncoder(nf)
	e.SetIndent("", "    ")
	e.SetEscapeHTML(false)
	lo.Must0(e.Encode(geoData))

	clashList := lo.Map(dl, func(item string, index int) string {
		return "+." + item
	})

	c := clash{
		Payload: clashList,
	}
	b := lo.Must(yaml.Marshal(c))
	lo.Must0(os.WriteFile(fileName+".yaml", b, 0666))

}

func geosite() map[string]struct{} {
	m := map[string]struct{}{}
	readGeoSite("geosite-geolocation-!cn.json", m)
	return m
}

func readGeoSite(filename string, set map[string]struct{}) {
	b := lo.Must(os.ReadFile(filename))
	r := gjson.ParseBytes(b)
	dl := r.Get("rules.0.domain")
	dl.ForEach(func(key, value gjson.Result) bool {
		set[value.String()] = struct{}{}
		return true
	})
}

func readLog(set map[string]struct{}) ([]string, string) {
	b, err := os.ReadFile("domain.log")
	if err != nil {
		return []string{}, ""
	}
	list := strings.Split(string(b), "\n")
	var last string
	return lo.Filter(list, func(item string, index int) bool {
		_, ok := set[item]
		if !ok && item != "" {
			last = item
		}
		return !ok
	}), last
}

var retryOpts = []retry.Option{
	retry.Attempts(0),
	retry.LastErrorOnly(true),
	retry.OnRetry(func(n uint, err error) {
		log.Printf("#%d: %s\n", n, err)
	}),
}

type geo struct {
	Version int    `json:"version"`
	Rules   []rule `json:"rules"`
}

type rule struct {
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
}

type clash struct {
	Payload []string `yaml:"payload"`
}
