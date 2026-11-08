// Package engine finds the outside domains a site trusts and asks whether each one can be bought.
//
// The extraction rules follow the Ghosteds webapp (ghosteds.com): CSP headers and meta CSP,
// HTML references, CSS url()/@import/image-set(), JavaScript string and module references,
// JSON data (import maps, manifests, speculation rules), redirects, SPF terms and DMARC report
// addresses. Pages are not rendered; lazy loads that only happen in a browser come in via HAR.
package engine

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"golang.org/x/net/html"
)

// Ref is one place a URL or hostname was found. Raw may be relative; Resolve turns it into a URL.
type Ref struct {
	Raw      string // as written
	Kind     string // script, stylesheet, image, policy, spf-include, dmarc-rua...
	Location string // where in the source it was found, e.g. "<script> src", "CSP header: script-src"
}

// Parsed is the output of one document.
type Parsed struct {
	Refs     []Ref
	Base     string // <base href>, if any
	Warnings []string
}

const maxRefs = 3000

func urlLike(v string) bool {
	for _, p := range []string{"ws://", "wss://", "https://", "http://", "//", "./", "../", "/"} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

// absoluteURL reports whether v names a host by itself; relative references point at the
// document's own origin and cannot introduce an outside domain.
func absoluteURL(v string) bool {
	l := strings.ToLower(v)
	return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://") ||
		strings.HasPrefix(l, "wss://") || strings.HasPrefix(l, "ws://") || strings.HasPrefix(l, "//")
}

// KindOf decides how a response body is read, from its MIME type, URL and the reference kind.
func KindOf(mime, url, hint string) string {
	mime = strings.ToLower(strings.TrimSpace(strings.SplitN(mime, ";", 2)[0]))
	switch {
	case strings.Contains(mime, "html") || mime == "image/svg+xml" || mime == "application/xml" || mime == "text/xml":
		return "html"
	case strings.Contains(mime, "css"):
		return "css"
	case strings.Contains(mime, "javascript") || strings.Contains(mime, "ecmascript"):
		return "js"
	case strings.Contains(mime, "json"):
		return "json"
	case mime != "" && mime != "text/plain" && mime != "application/octet-stream":
		return ""
	}
	path := strings.ToLower(strings.SplitN(strings.SplitN(url, "?", 2)[0], "#", 2)[0])
	switch {
	case hint == "script" || hint == "module" || strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs") || strings.HasSuffix(path, ".cjs"):
		return "js"
	case hint == "stylesheet" || strings.HasSuffix(path, ".css"):
		return "css"
	case hint == "manifest" || strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".webmanifest"):
		return "json"
	case strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm"):
		return "html"
	}
	return ""
}

// ParseBody reads a document of the given kind (html, css, js, json).
func ParseBody(body, kind string) Parsed {
	switch kind {
	case "html":
		return HTML(body)
	case "css":
		return CSS(body)
	case "json":
		return JSON(body, "data_reference")
	case "js":
		return JavaScript(body)
	}
	return Parsed{}
}

// PolicyRefs lists every host source in a CSP. Keywords, schemes and nonces are not hosts.
func PolicyRefs(policy, location string) []Ref {
	var out []Ref
	for _, directive := range strings.Split(policy, ";") {
		words := strings.Fields(directive)
		if len(words) == 0 {
			continue
		}
		name := strings.ToLower(words[0])
		for _, v := range words[1:] {
			if !strings.Contains(v, ".") || strings.HasPrefix(v, "'") {
				continue
			}
			raw := v
			if strings.Contains(v, "://") {
				raw = strings.Replace(v, "://*.", "://", 1)
			} else {
				raw = "https://" + strings.TrimPrefix(v, "*.")
			}
			out = append(out, Ref{Raw: raw, Kind: "policy", Location: location + ": " + name})
		}
	}
	return out
}

var cssPatterns = []struct {
	re       *regexp.Regexp
	kind     string
	location string
}{
	{regexp.MustCompile(`(?i)@import\s+(?:url\(\s*)?["']?([^"'\s)]+)`), "stylesheet", "CSS @import"},
	{regexp.MustCompile(`(?i)url\(\s*["']?([^"')\s]+)`), "css_url", "CSS url()"},
	{regexp.MustCompile(`(?i)image-set\(([^)]*)\)`), "image", "CSS image-set()"},
}
var cssComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
var quoted = regexp.MustCompile(`["']([^"']+)["']`)

// CSS finds url(), @import and image-set() references, skipping comments and data: URLs.
func CSS(source string) Parsed {
	source = cssComment.ReplaceAllString(source, " ")
	var p Parsed
	seen := map[string]bool{}
	for _, pat := range cssPatterns {
		for _, m := range pat.re.FindAllStringSubmatch(source, -1) {
			values := []string{m[1]}
			if pat.kind == "image" {
				values = nil
				for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
					values = append(values, q[1])
				}
			}
			for _, v := range values {
				if v == "" || strings.HasPrefix(strings.ToLower(v), "data:") || seen[pat.kind+v] {
					continue
				}
				seen[pat.kind+v] = true
				p.Refs = append(p.Refs, Ref{Raw: v, Kind: pat.kind, Location: pat.location})
			}
		}
	}
	return capped(p, "CSS")
}

// JSON walks a JSON document. A string counts if it looks like a URL, or if it is a whitespace-free
// value under a URL-named key (src, url, href, start_url, scope, action, endpoint).
func JSON(source, kind string) Parsed {
	var p Parsed
	var v any
	if err := json.Unmarshal([]byte(source), &v); err != nil {
		p.Warnings = append(p.Warnings, "Embedded JSON could not be parsed; its references may be incomplete.")
		return p
	}
	urlKeys := map[string]bool{"src": true, "url": true, "href": true, "start_url": true, "scope": true, "action": true, "endpoint": true}
	var visit func(any, bool)
	visit = func(v any, urlContext bool) {
		if len(p.Refs) >= maxRefs {
			return
		}
		switch t := v.(type) {
		case string:
			if t != "" && len(t) <= 4096 && (urlLike(t) || (urlContext && !strings.ContainsAny(t, " \t\r\n"))) {
				p.Refs = append(p.Refs, Ref{Raw: t, Kind: kind, Location: "JSON data"})
			}
		case map[string]any:
			for k, x := range t {
				// Import map keys are specifiers that can themselves be URLs.
				if kind == "import_map" && urlLike(k) {
					p.Refs = append(p.Refs, Ref{Raw: k, Kind: kind, Location: "JSON data"})
				}
				visit(x, urlKeys[k])
			}
		case []any:
			for _, x := range t {
				visit(x, urlContext)
			}
		}
	}
	visit(v, false)
	return capped(p, "JSON")
}

// JavaScript parses the source and takes module specifiers, dynamic import() arguments and URL-like
// string and template literals. Comments are never read. If the source does not parse, absolute
// URLs are taken from the raw text instead and a warning says so.
func JavaScript(source string) Parsed {
	var p Parsed
	ast, err := js.Parse(parse.NewInputString(source), js.Options{})
	if err != nil {
		p.Warnings = append(p.Warnings, "JavaScript did not parse; absolute URLs were taken from the raw text and relative ones were missed.")
		for _, m := range rawURL.FindAllString(source, maxRefs) {
			p.Refs = append(p.Refs, Ref{Raw: unescapeJS(m), Kind: "js_string", Location: "JavaScript text"})
		}
		return capped(p, "JavaScript")
	}
	w := &jsWalker{p: &p}
	js.Walk(w, ast)
	return capped(p, "JavaScript")
}

var rawURL = regexp.MustCompile(`(?i)(?:https?|wss?):(?:\\?/){2}[a-z0-9][a-z0-9.\-]*\.[a-z][a-z0-9\-]*[^\s"'` + "`" + `<>)\\]*`)

type jsWalker struct{ p *Parsed }

func (w *jsWalker) add(raw, kind, location string) {
	if raw != "" && len(raw) <= 4096 && len(w.p.Refs) < maxRefs {
		w.p.Refs = append(w.p.Refs, Ref{Raw: raw, Kind: kind, Location: location})
	}
}

func (w *jsWalker) Enter(n js.INode) js.IVisitor {
	switch t := n.(type) {
	case *js.ImportStmt:
		if t.Module != nil {
			w.add(unquoteJS(string(t.Module)), "module", "JavaScript import")
		}
		return nil
	case *js.ExportStmt:
		if t.Module != nil {
			w.add(unquoteJS(string(t.Module)), "module", "JavaScript export from")
		}
	case *js.CallExpr:
		// Dynamic import() parses as a call on the "import" keyword literal.
		if callee, ok := t.X.(*js.LiteralExpr); ok && string(callee.Data) == "import" && len(t.Args.List) > 0 {
			if l, ok := t.Args.List[0].Value.(*js.LiteralExpr); ok && l.TokenType == js.StringToken {
				w.add(unquoteJS(string(l.Data)), "module", "JavaScript import()")
				return nil
			}
		}
	case *js.LiteralExpr:
		if t.TokenType == js.StringToken {
			if s := unquoteJS(string(t.Data)); urlLike(s) && !strings.ContainsAny(s, " \t\r\n") {
				w.add(s, "js_string", "JavaScript string")
			}
		}
	case *js.TemplateExpr:
		// Only the literal text before the first substitution can name a host.
		head := string(t.Tail)
		if len(t.List) > 0 {
			head = string(t.List[0].Value)
		}
		head = strings.TrimSuffix(strings.TrimPrefix(head, "`"), "`")
		head = strings.TrimSuffix(head, "${")
		if s := unescapeJS(head); absoluteURL(s) && !strings.ContainsAny(s, " \t\r\n") {
			w.add(s, "js_string", "JavaScript template")
		}
	}
	return w
}
func (w *jsWalker) Exit(js.INode) {}

func unquoteJS(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return unescapeJS(s)
}

// unescapeJS decodes JavaScript escapes, so "https://host" and "https:\/\/host" are read
// the way the browser reads them.
func unescapeJS(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch c := s[i]; c {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'x':
			if i+2 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
					b.WriteRune(rune(v))
					i += 2
					continue
				}
			}
			b.WriteByte(c)
		case 'u':
			if i+1 < len(s) && s[i+1] == '{' {
				if end := strings.IndexByte(s[i:], '}'); end > 0 {
					if v, err := strconv.ParseUint(s[i+2:i+end], 16, 32); err == nil && utf8.ValidRune(rune(v)) {
						b.WriteRune(rune(v))
						i += end
						continue
					}
				}
			} else if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 16); err == nil {
					b.WriteRune(rune(v))
					i += 4
					continue
				}
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// htmlAttrs is the webapp's table: which attribute of which element is a reference, and what kind.
var htmlAttrs = map[string][][2]string{
	"script": {{"src", "script"}},
	"link":   {{"href", "link"}},
	"iframe": {{"src", "frame"}}, "frame": {{"src", "frame"}},
	"form":   {{"action", "form"}},
	"input":  {{"formaction", "form"}, {"src", "image"}},
	"button": {{"formaction", "form"}},
	"image":  {{"href", "image"}, {"xlink:href", "image"}}, "use": {{"href", "image"}, {"xlink:href", "image"}},
	"img":   {{"src", "image"}},
	"audio": {{"src", "media"}, {"poster", "image"}}, "video": {{"src", "media"}, {"poster", "image"}},
	"source": {{"src", "media"}, {"poster", "image"}}, "track": {{"src", "media"}, {"poster", "image"}},
	"a": {{"href", "navigation"}}, "area": {{"href", "navigation"}},
	"object": {{"data", "object"}},
	"embed":  {{"src", "object"}},
	"base":   {{"href", "base"}},
}

func linkKind(rel string) string {
	words := strings.Fields(strings.ToLower(rel))
	has := func(w string) bool {
		for _, x := range words {
			if x == w {
				return true
			}
		}
		return false
	}
	switch {
	case has("stylesheet"):
		return "stylesheet"
	case has("modulepreload"), has("preload"):
		return "preload"
	case has("manifest"):
		return "manifest"
	case has("dns-prefetch"):
		return "dns_prefetch"
	case has("preconnect"):
		return "preconnect"
	case has("prefetch"):
		return "prefetch"
	}
	return "link"
}

// HTML reads element references, meta CSP, srcset, data-* URLs, inline style attributes and
// inline <style>/<script> blocks. Script blocks are read by type the way a browser treats them.
func HTML(source string) Parsed {
	var p Parsed
	z := html.NewTokenizer(strings.NewReader(source))
	var inline string // "style", "js", "json", "import_map" while inside such a block
	for elements := 0; elements < 20000 && len(p.Refs) < maxRefs; {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return finishHTML(p)
		case html.TextToken:
			if inline == "" {
				continue
			}
			text := string(z.Text())
			var sub Parsed
			switch inline {
			case "style":
				sub = CSS(text)
			case "js":
				sub = JavaScript(text)
			case "json":
				sub = JSON(text, "js_string")
			case "import_map":
				sub = JSON(text, "import_map")
			}
			tag := "script"
			if inline == "style" {
				tag = "style"
			}
			for _, r := range sub.Refs {
				r.Location = "inline <" + tag + "> / " + r.Location
				p.Refs = append(p.Refs, r)
			}
			p.Warnings = append(p.Warnings, sub.Warnings...)
		case html.EndTagToken:
			inline = ""
		case html.StartTagToken, html.SelfClosingTagToken:
			elements++
			name, _ := z.TagName()
			tag := string(name)
			attrs := map[string]string{}
			var order []string
			for {
				k, v, more := z.TagAttr()
				key := strings.ToLower(string(k))
				if _, dup := attrs[key]; !dup {
					attrs[key] = string(v)
					order = append(order, key)
				}
				if !more {
					break
				}
			}
			p.element(tag, attrs, order)
			inline = ""
			if tt == html.StartTagToken {
				if tag == "style" {
					inline = "style"
				} else if _, hasSrc := attrs["src"]; tag == "script" && !hasSrc {
					inline = scriptType(attrs["type"])
				}
			}
		}
	}
	p.Warnings = append(p.Warnings, "HTML reference budget reached (3,000).")
	return finishHTML(p)
}

func scriptType(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	switch {
	case t == "" || t == "module":
		return "js"
	case t == "importmap":
		return "import_map"
	case t == "speculationrules" || t == "application/json" || strings.HasSuffix(t, "+json"):
		return "json"
	case strings.Contains(t, "javascript") || strings.Contains(t, "ecmascript") || strings.Contains(t, "jscript"):
		return "js"
	}
	return "" // inert template block
}

func (p *Parsed) element(tag string, attrs map[string]string, order []string) {
	if tag == "base" && p.Base == "" {
		p.Base = attrs["href"]
	}
	if tag == "meta" && strings.EqualFold(attrs["http-equiv"], "content-security-policy") {
		if policy := attrs["content"]; policy != "" && len(policy) <= 8192 {
			p.Refs = append(p.Refs, PolicyRefs(policy, "meta CSP")...)
		}
	}
	for _, pair := range htmlAttrs[tag] {
		raw, ok := attrs[pair[0]]
		if !ok || raw == "" || len(raw) > 4096 {
			continue
		}
		kind := pair[1]
		if tag == "script" && attrs["type"] == "module" {
			kind = "module"
		}
		if tag == "link" {
			kind = linkKind(attrs["rel"])
		}
		p.Refs = append(p.Refs, Ref{Raw: raw, Kind: kind, Location: "<" + tag + "> " + pair[0]})
	}
	for _, name := range order {
		if v := attrs[name]; strings.HasPrefix(name, "data-") && urlLike(v) && len(v) <= 4096 {
			p.Refs = append(p.Refs, Ref{Raw: v, Kind: "html_attribute", Location: "<" + tag + "> " + name})
		}
	}
	if srcset, ok := attrs["srcset"]; ok {
		for _, candidate := range srcsetURLs(srcset) {
			if !strings.HasPrefix(strings.ToLower(candidate), "data:") {
				p.Refs = append(p.Refs, Ref{Raw: candidate, Kind: "image", Location: "<" + tag + "> srcset"})
			}
		}
	}
	if style, ok := attrs["style"]; ok {
		sub := CSS(style)
		for _, r := range sub.Refs {
			r.Location = "<" + tag + "> style / " + r.Location
			p.Refs = append(p.Refs, r)
		}
	}
}

// srcsetURLs splits a srcset the way the HTML spec does: a URL runs to whitespace (so a data: URL's
// comma stays inside it) and its descriptors run to the next comma.
func srcsetURLs(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ',' || s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
			i++
		}
		candidate := strings.TrimRight(s[start:i], ",")
		if candidate != "" {
			out = append(out, candidate)
		}
		if strings.HasSuffix(s[start:i], ",") {
			continue
		}
		for i < len(s) && s[i] != ',' {
			i++
		}
	}
	return out
}

func finishHTML(p Parsed) Parsed {
	seen := map[Ref]bool{}
	out := p.Refs[:0]
	for _, r := range p.Refs {
		if r.Raw != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	p.Refs = out
	return capped(p, "HTML")
}

func capped(p Parsed, what string) Parsed {
	if len(p.Refs) > maxRefs {
		p.Refs = p.Refs[:maxRefs]
		p.Warnings = append(p.Warnings, what+" reference budget reached (3,000).")
	}
	return p
}
