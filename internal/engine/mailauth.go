package engine

import (
	"context"
	"net"
	"strings"
	"time"
)

// SPF and DMARC follow the webapp: SPF for the hostname and its registrable domain, following
// include and redirect up to RFC 7208's ten DNS-querying terms, and DMARC for both names, with at
// most 30 TXT lookups. Domains named by include, redirect, a, mx, exists and ptr terms and by
// DMARC rua/ruf addresses are references. SPF macros are not expanded. No mail is sent.

const (
	spfLookupLimit = 10
	txtLookupLimit = 30
	dnsTimeout     = 10 * time.Second
)

// SPFTerms returns the (term, domain) pairs in one SPF record, the number of DNS-querying terms,
// and notes on what was not followed. Bare a/mx/ptr refer to the queried name itself.
func SPFTerms(record string) (terms [][2]string, lookups int, notes []string) {
	for _, word := range strings.Fields(record)[1:] {
		term := strings.TrimLeft(strings.ToLower(word), "+-~?")
		var name, arg string
		if rest, ok := strings.CutPrefix(term, "redirect="); ok {
			name, arg = "redirect", rest
		} else {
			name, arg, _ = strings.Cut(term, ":")
			if i := strings.IndexByte(name, '/'); i >= 0 {
				name = name[:i] // bare "a/24"
			}
		}
		switch name {
		case "include", "redirect", "a", "mx", "exists", "ptr":
		default:
			continue
		}
		lookups++
		if i := strings.IndexByte(arg, '/'); i >= 0 {
			arg = arg[:i]
		}
		arg = strings.TrimSuffix(arg, ".")
		if arg == "" {
			continue
		}
		if strings.Contains(arg, "%") {
			notes = append(notes, "SPF macro not expanded: "+word)
			continue
		}
		terms = append(terms, [2]string{name, arg})
	}
	return terms, lookups, notes
}

// DMARCDestinations returns (tag, domain) for every rua/ruf mailto address.
func DMARCDestinations(record string) [][2]string {
	var out [][2]string
	for _, part := range strings.Split(record, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if !ok || (key != "rua" && key != "ruf") {
			continue
		}
		for _, addr := range strings.Split(value, ",") {
			addr = strings.TrimSpace(addr)
			if !strings.HasPrefix(strings.ToLower(addr), "mailto:") {
				continue
			}
			_, domain, ok := strings.Cut(addr, "@")
			if !ok {
				continue
			}
			if i := strings.IndexByte(domain, '!'); i >= 0 {
				domain = domain[:i]
			}
			if domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), "."); domain != "" {
				out = append(out, [2]string{key, domain})
			}
		}
	}
	return out
}

func isSPF(v string) bool {
	l := strings.ToLower(v)
	return l == "v=spf1" || strings.HasPrefix(l, "v=spf1 ")
}
func isDMARC(v string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "v=dmarc1")
}

// MailAuth collects SPF and DMARC references for the given names (normally the host and its
// registrable domain).
func MailAuth(ctx context.Context, resolver *net.Resolver, names []string) (refs []Ref, warnings []string) {
	txtLookups := 0
	txt := func(name string) ([]string, bool) {
		if txtLookups >= txtLookupLimit {
			return nil, false
		}
		txtLookups++
		c, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		values, err := resolver.LookupTXT(c, name)
		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
				return nil, true
			}
			warnings = append(warnings, "TXT lookup failed for "+name+": "+err.Error())
			return nil, true
		}
		return values, true
	}
	for _, name := range names {
		// SPF, following include and redirect breadth-first within the lookup limit.
		lookups := 0
		queue := []string{name}
		seen := map[string]bool{}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			if seen[current] {
				continue
			}
			seen[current] = true
			values, ok := txt(current)
			if !ok {
				warnings = append(warnings, "TXT lookup budget (30) reached; SPF for "+name+" not fully followed.")
				break
			}
			for _, v := range values {
				if !isSPF(v) {
					continue
				}
				terms, n, notes := SPFTerms(v)
				lookups += n
				warnings = append(warnings, notes...)
				for _, t := range terms {
					refs = append(refs, Ref{Raw: t[1], Kind: "spf-" + t[0], Location: "SPF for " + current})
					if (t[0] == "include" || t[0] == "redirect") && lookups <= spfLookupLimit {
						queue = append(queue, t[1])
					}
				}
			}
			if lookups > spfLookupLimit {
				warnings = append(warnings, "SPF for "+name+" exceeds ten DNS lookups; terms past the limit were not followed.")
				break
			}
		}
		if values, ok := txt("_dmarc." + name); ok {
			for _, v := range values {
				if isDMARC(v) {
					for _, d := range DMARCDestinations(v) {
						refs = append(refs, Ref{Raw: d[1], Kind: "dmarc-" + d[0], Location: "DMARC for " + name})
					}
				}
			}
		}
	}
	return refs, warnings
}
