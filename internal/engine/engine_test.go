package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func raws(p Parsed) []string {
	var out []string
	for _, r := range p.Refs {
		out = append(out, r.Raw+" "+r.Kind)
	}
	sort.Strings(out)
	return out
}

func TestHTMLLinkHintsAndElements(t *testing.T) {
	p := HTML(`<link rel="DNS-PREFETCH" href="https://dns.example"><link rel="preconnect" href="https://connection.example"><link rel="preload" as="style" href="https://css.example/a.css"><link rel="prefetch" href="https://later.example/a.js"><img loading="lazy" src="https://image.example/pixel"><link rel="stylesheet" media="(width > 900px)" href="https://css.example/main.css">`)
	var kinds []string
	for _, r := range p.Refs {
		kinds = append(kinds, r.Kind)
	}
	want := []string{"dns_prefetch", "preconnect", "preload", "prefetch", "image", "stylesheet"}
	if !reflect.DeepEqual(kinds, want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
}

func TestHTMLMetaCSPSrcsetDataStyle(t *testing.T) {
	p := HTML(`<meta http-equiv="Content-Security-Policy" content="script-src 'self' *.cdn.example https://api.example; img-src data:">` +
		`<img srcset="https://a.example/1.png 1x, https://b.example/2.png 2x, data:image/png;base64,xx 3x">` +
		`<div data-src="https://lazy.example/x.jpg" style="background:url('https://bg.example/i.png')"></div>`)
	got := raws(p)
	want := []string{
		"https://a.example/1.png image",
		"https://api.example policy",
		"https://b.example/2.png image",
		"https://bg.example/i.png css_url",
		"https://cdn.example policy",
		"https://lazy.example/x.jpg html_attribute",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestScriptBlocksAreReadByType(t *testing.T) {
	p := HTML(`<script type="speculationrules">{"prerender":[{"source":"list","urls":["/next"]}]}</script>` +
		`<script type="text/template"><a href="https://template.example/">x</a></script>` +
		`<script type=" Text/JavaScript ">fetch('https://api.example/a')</script>` +
		`<script type="IMPORTMAP">{"imports":{"x":"https://esm.example/x.js"}}</script>`)
	got := raws(p)
	want := []string{"/next js_string", "https://api.example/a js_string", "https://esm.example/x.js import_map"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestJavaScriptEscapesImportsAndComments(t *testing.T) {
	p := JavaScript("// fetch('https://comment.example/x')\nimport x from 'https://cdn.example/a.js'; fetch('https:\\u002f\\u002fapi.example/v1'); const t=`wss://socket.example/${id}`; import('./lazy.js');")
	got := raws(p)
	want := []string{"./lazy.js module", "https://api.example/v1 js_string", "https://cdn.example/a.js module", "wss://socket.example/ js_string"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestJavaScriptThatDoesNotParseFallsBackToAbsoluteURLs(t *testing.T) {
	p := JavaScript(`this is not ( javascript "https://still.example/x"`)
	if len(p.Refs) != 1 || p.Refs[0].Raw != "https://still.example/x" || len(p.Warnings) == 0 {
		t.Fatalf("got %+v", p)
	}
}

func TestCSSImportsURLsImageSetAndComments(t *testing.T) {
	p := CSS(`/* url(https://comment.example/x) */ @import './theme.css'; @font-face { src: url('../font.woff2') } .x{background:url(https://img.example/a.png)} .y{background:image-set("https://hi.example/a.png" 1x)}`)
	got := raws(p)
	want := []string{"../font.woff2 css_url", "./theme.css stylesheet", "https://hi.example/a.png image", "https://img.example/a.png css_url"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestJSONURLKeysKeepRelativeURLsButNotProse(t *testing.T) {
	p := JSON(`{"scope":"Isolated customer workspace","start_url":".","src":"icon.png","href":"/x"}`, "data_reference")
	var got []string
	for _, r := range p.Refs {
		got = append(got, r.Raw)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, []string{".", "/x", "icon.png"}) {
		t.Fatalf("got %v", got)
	}
}

func TestPolicyRefsSkipKeywordsAndStripWildcards(t *testing.T) {
	got := raws(Parsed{Refs: PolicyRefs("default-src 'self' 'nonce-abc.def'; script-src *.Vendor.example https://*.cdn.example; report-uri https://report.example/csp", "CSP header")})
	want := []string{"https://*.Vendor.example policy", "https://cdn.example policy", "https://report.example/csp policy"}
	// The host part of a schemeless wildcard is stripped; the URL form keeps the scheme.
	want[0] = "https://Vendor.example policy"
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestSPFTerms(t *testing.T) {
	terms, lookups, notes := SPFTerms("v=spf1 ip4:192.0.2.0/24 +include:_spf.Supplier.net ~a:mail.example.org/24 -mx:mx.example.net//64 ?exists:%{i}._spf.example.com ptr:legacy.example.net a mx all redirect=spf.example.org.")
	want := [][2]string{{"include", "_spf.supplier.net"}, {"a", "mail.example.org"}, {"mx", "mx.example.net"}, {"ptr", "legacy.example.net"}, {"redirect", "spf.example.org"}}
	if !reflect.DeepEqual(terms, want) {
		t.Fatalf("terms = %v", terms)
	}
	// include, a, mx, exists, ptr, bare a, bare mx, redirect: eight DNS-querying terms.
	if lookups != 8 || len(notes) != 1 {
		t.Fatalf("lookups = %d, notes = %v", lookups, notes)
	}
}

func TestDMARCDestinations(t *testing.T) {
	got := DMARCDestinations("v=DMARC1; p=reject; rua=mailto:agg@Reports.Vendor.net!10m,mailto:dmarc@example.com; ruf=mailto:forensic@forensics.example.org; fo=1")
	want := [][2]string{{"rua", "reports.vendor.net"}, {"rua", "example.com"}, {"ruf", "forensics.example.org"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if len(DMARCDestinations("v=DMARC1; p=none; rua=https://example.com/")) != 0 {
		t.Fatal("non-mailto destination accepted")
	}
}

func TestRegistrable(t *testing.T) {
	cases := map[string]string{
		"mail.tripwire-dhs.us": "tripwire-dhs.us",
		"a.b.example.co.uk":    "example.co.uk",
		"gov.uk":               "",
		"192.0.2.1":            "",
		"localhost":            "",
		"fonts.googleapis.com": "googleapis.com",
		"x.y.github.io":        "github.io",
		"co.uk":                "",
	}
	for in, want := range cases {
		if got := Registrable(in); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHARReadsRequestsHeadersAndBodies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.har")
	har := `{"log":{"entries":[
	 {"request":{"url":"https://www.site.example/"},"response":{"headers":[{"name":"Content-Security-Policy","value":"script-src https://policy.example"}],"content":{"mimeType":"text/html","text":"<script src=\"https://static.example/a.js\"></script>"}},"_resourceType":"document"},
	 {"request":{"url":"https://lazy.example/chunk.js"},"response":{"headers":[],"content":{"mimeType":"application/javascript","text":"ZmV0Y2goImh0dHBzOi8vYXBpLmV4YW1wbGUvdjEiKQ==","encoding":"base64"}},"_resourceType":"script"},
	 {"request":{"url":"https://cdn.site.example/x.png"},"response":{"headers":[],"content":{"mimeType":"image/png"}},"_resourceType":"image"}
	]}}`
	if err := os.WriteFile(path, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := HAR(path, "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range r.Found {
		got[f.Registrable+" "+f.Kind] = true
		if f.Registrable == "site.example" {
			t.Fatalf("the site's own domain was reported: %+v", f)
		}
	}
	for _, want := range []string{"policy.example policy", "static.example script", "lazy.example observed_script", "api.example js_string"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}
