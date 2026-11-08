package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Found is one reference resolved to a host, with where it came from.
type Found struct {
	Target      string `json:"target"`      // the site being assessed
	Document    string `json:"document"`    // URL (or DNS name) the reference was read from
	Kind        string `json:"kind"`        // script, stylesheet, policy, spf-include, ...
	Location    string `json:"location"`    // where in that document
	URL         string `json:"url"`         // resolved reference
	Host        string `json:"host"`        // hostname in the reference
	Registrable string `json:"registrable"` // the domain that would be bought
}

// Result is everything found for one target.
type Result struct {
	Target   string   `json:"target"`
	Found    []Found  `json:"found"`
	Warnings []string `json:"warnings,omitempty"`
}

// Options bound the work per target.
type Options struct {
	MaxResources int           // subresources fetched per target (scripts, styles, manifests)
	MaxBody      int64         // bytes read per response
	Timeout      time.Duration // per request
	UserAgent    string
}

func DefaultOptions() Options {
	return Options{MaxResources: 60, MaxBody: 4 << 20, Timeout: 20 * time.Second,
		UserAgent: "Mozilla/5.0 (compatible; ghosted; +https://github.com/Splinters-io/ghosted)"}
}

type collector struct {
	result *Result
	own    string
	seen   map[string]bool
}

func (c *collector) add(document string, base *url.URL, r Ref) {
	raw := strings.TrimSpace(r.Raw)
	var u *url.URL
	var err error
	switch {
	case strings.HasPrefix(r.Kind, "spf-") || strings.HasPrefix(r.Kind, "dmarc-"):
		u = &url.URL{Host: strings.ToLower(raw)}
	case base != nil:
		u, err = base.Parse(raw)
	default:
		u, err = url.Parse(raw)
	}
	if err != nil || u == nil {
		return
	}
	host := strings.ToLower(u.Hostname())
	reg := Registrable(host)
	if reg == "" || reg == c.own {
		return
	}
	key := document + "\x00" + r.Kind + "\x00" + r.Location + "\x00" + u.String()
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	ref := u.String()
	if u.Scheme == "" && u.Path == "" {
		ref = host // SPF and DMARC name a host, not a URL
	}
	c.result.Found = append(c.result.Found, Found{c.result.Target, document, r.Kind, r.Location, ref, host, reg})
}

func (c *collector) warn(format string, args ...any) {
	c.result.Warnings = append(c.result.Warnings, fmt.Sprintf(format, args...))
}

// Scan fetches the target's landing page (following redirects), reads its headers and body, fetches
// the scripts, stylesheets, manifests and import-map modules it references, and reads SPF and DMARC
// for the host and its registrable domain.
func Scan(ctx context.Context, target string, o Options, mail bool) Result {
	start := target
	if !strings.Contains(start, "://") {
		start = "https://" + start
	}
	u, err := url.Parse(start)
	res := Result{Target: target}
	if err != nil || u.Hostname() == "" {
		res.Warnings = append(res.Warnings, "not a valid target: "+target)
		return res
	}
	res.Target = u.Hostname()
	c := &collector{result: &res, own: Registrable(u.Hostname()), seen: map[string]bool{}}
	if c.own == "" {
		c.warn("%s is not under a registrable domain", u.Hostname())
		return res
	}
	client := &http.Client{Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	fetch := func(raw string) (*url.URL, *http.Response, string, error) {
		current := raw
		for hop := 0; hop <= 5; hop++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
			if err != nil {
				return nil, nil, "", err
			}
			req.Header.Set("User-Agent", o.UserAgent)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
			resp, err := client.Do(req)
			if err != nil {
				return nil, nil, "", err
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, o.MaxBody))
			resp.Body.Close()
			here, _ := url.Parse(current)
			if loc := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
				next, err := here.Parse(loc)
				if err != nil {
					return nil, nil, "", err
				}
				c.add(current, here, Ref{Raw: next.String(), Kind: "redirect", Location: "Location header"})
				if next.Scheme != "http" && next.Scheme != "https" {
					return nil, nil, "", fmt.Errorf("redirect to %s", next.Scheme)
				}
				current = next.String()
				continue
			}
			return here, resp, string(body), nil
		}
		return nil, nil, "", fmt.Errorf("more than five redirects")
	}

	page, resp, body, err := fetch(u.String())
	if err != nil {
		c.warn("landing page not fetched: %v", err)
	} else {
		readHeaders(c, page.String(), page, resp.Header)
		parsed := ParseBody(body, orHTML(KindOf(resp.Header.Get("Content-Type"), page.String(), "document")))
		base := page
		if parsed.Base != "" {
			if b, err := page.Parse(parsed.Base); err == nil {
				base = b
			}
		}
		for _, w := range parsed.Warnings {
			c.warn("%s: %s", page, w)
		}
		queue := enqueue(nil, base, parsed.Refs)
		for _, r := range parsed.Refs {
			c.add(page.String(), base, r)
		}
		fetched := map[string]bool{page.String(): true}
		for len(queue) > 0 && len(fetched) <= o.MaxResources {
			item := queue[0]
			queue = queue[1:]
			if fetched[item.url] {
				continue
			}
			fetched[item.url] = true
			at, resp, body, err := fetch(item.url)
			if err != nil {
				c.warn("%s not fetched: %v", item.url, err)
				continue
			}
			kind := KindOf(resp.Header.Get("Content-Type"), at.String(), item.hint)
			if kind == "" || kind == "html" {
				continue
			}
			parsed := ParseBody(body, kind)
			for _, w := range parsed.Warnings {
				c.warn("%s: %s", at, w)
			}
			for _, r := range parsed.Refs {
				c.add(at.String(), at, r)
			}
			queue = enqueue(queue, at, parsed.Refs)
		}
		if len(queue) > 0 {
			c.warn("subresource limit (%d) reached; %d more were not fetched", o.MaxResources, len(queue))
		}
	}

	if mail {
		Mail(ctx, &res)
	}
	return res
}

// Mail adds the SPF and DMARC references for the result's target host and its registrable domain.
func Mail(ctx context.Context, res *Result) {
	own := Registrable(res.Target)
	if own == "" {
		return
	}
	c := &collector{result: res, own: own, seen: map[string]bool{}}
	names := []string{res.Target}
	if own != res.Target {
		names = append(names, own)
	}
	refs, warnings := MailAuth(ctx, net.DefaultResolver, names)
	for _, r := range refs {
		document := strings.TrimPrefix(r.Location, "SPF for ")
		if name, ok := strings.CutPrefix(r.Location, "DMARC for "); ok {
			document = "_dmarc." + name
		}
		c.add(document, nil, r)
	}
	res.Warnings = append(res.Warnings, warnings...)
}

func orHTML(kind string) string {
	if kind == "" {
		return "html"
	}
	return kind
}

func readHeaders(c *collector, document string, base *url.URL, h http.Header) {
	for _, p := range h.Values("Content-Security-Policy") {
		for _, r := range PolicyRefs(p, "CSP header") {
			c.add(document, base, r)
		}
	}
	for _, p := range h.Values("Content-Security-Policy-Report-Only") {
		for _, r := range PolicyRefs(p, "Report-only CSP header") {
			c.add(document, base, r)
		}
	}
}

type queued struct{ url, hint string }

// enqueue adds the references worth fetching: code, styles, manifests and import-map entries.
func enqueue(q []queued, base *url.URL, refs []Ref) []queued {
	for _, r := range refs {
		switch r.Kind {
		case "script", "module", "stylesheet", "manifest", "import_map", "preload":
		default:
			continue
		}
		u, err := base.Parse(strings.TrimSpace(r.Raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		u.Fragment = ""
		q = append(q, queued{u.String(), r.Kind})
	}
	return q
}

// HAR reads a browser HAR export: every request the browser made (including lazy loads that only
// happen after scrolling or interaction), CSP and redirect headers on each response, and the
// response bodies the export carries, read the same way as fetched documents.
func HAR(path, target string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Headers []struct{ Name, Value string } `json:"headers"`
					Content struct {
						MimeType string `json:"mimeType"`
						Text     string `json:"text"`
						Encoding string `json:"encoding"`
					} `json:"content"`
				} `json:"response"`
				ResourceType string `json:"_resourceType"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &har); err != nil {
		return Result{}, fmt.Errorf("not a HAR file: %w", err)
	}
	entries := har.Log.Entries
	if len(entries) == 0 {
		return Result{}, fmt.Errorf("HAR has no entries")
	}
	if target == "" {
		if u, err := url.Parse(entries[0].Request.URL); err == nil {
			target = u.Hostname()
		}
	}
	res := Result{Target: target}
	c := &collector{result: &res, own: Registrable(target), seen: map[string]bool{}}
	if c.own == "" {
		return res, fmt.Errorf("%s is not under a registrable domain; pass --target", target)
	}
	for i, e := range entries {
		at, err := url.Parse(e.Request.URL)
		if err != nil || (at.Scheme != "http" && at.Scheme != "https" && at.Scheme != "ws" && at.Scheme != "wss") {
			continue
		}
		label := fmt.Sprintf("HAR entry %d", i+1)
		kind := e.ResourceType
		if kind == "" {
			kind = "request"
		}
		c.add(label, nil, Ref{Raw: e.Request.URL, Kind: "observed_" + kind, Location: "browser request"})
		h := http.Header{}
		for _, x := range e.Response.Headers {
			h.Add(x.Name, x.Value)
		}
		readHeaders(c, e.Request.URL, at, h)
		if loc := h.Get("Location"); loc != "" {
			c.add(e.Request.URL, at, Ref{Raw: loc, Kind: "redirect", Location: "Location header"})
		}
		text := e.Response.Content.Text
		if e.Response.Content.Encoding == "base64" {
			b, err := base64.StdEncoding.DecodeString(text)
			if err != nil {
				c.warn("%s: body not decoded", label)
				continue
			}
			text = string(b)
		}
		if text == "" {
			continue
		}
		kind = KindOf(e.Response.Content.MimeType, e.Request.URL, e.ResourceType)
		parsed := ParseBody(text, kind)
		base := at
		if parsed.Base != "" {
			if b, err := at.Parse(parsed.Base); err == nil {
				base = b
			}
		}
		for _, w := range parsed.Warnings {
			c.warn("%s: %s", e.Request.URL, w)
		}
		for _, r := range parsed.Refs {
			c.add(e.Request.URL, base, r)
		}
	}
	return res, nil
}
