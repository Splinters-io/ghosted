package engine

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Statuses. AVAILABLE (and AVAILABLE_RESERVED / AVAILABLE_PREORDER) come only from the registrar.
const (
	StatusRegistered     = "REGISTERED"      // delegated in DNS; the registrar was not asked
	StatusUnsupportedTLD = "UNSUPPORTED_TLD" // AWS cannot register this suffix; check manually
	StatusUnchecked      = "UNCHECKED"       // not delegated and AWS was not asked (--no-aws)
	StatusError          = "ERROR"           // AWS call failed; no claim is made
)

//go:embed aws_tlds.txt
var awsTLDList string

var awsTLDs = func() map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(awsTLDList, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			m[strings.ToLower(line)] = true
		}
	}
	return m
}()

// Availability is the answer for one registrable domain.
type Availability struct {
	Domain   string `json:"domain"`
	Status   string `json:"status"`
	Provider string `json:"provider"` // dns-delegation, aws-route53, none
	Detail   string `json:"detail,omitempty"`
}

// Purchasable is true only for a registrar answer saying the domain can be bought.
func (a Availability) Purchasable() bool { return strings.HasPrefix(a.Status, "AVAILABLE") }

// Checker decides availability DNS-first: a domain with its own NS records is registered and AWS
// is not asked. Everything else under a suffix AWS sells goes to Route 53, one call at a time.
type Checker struct {
	UseAWS  bool
	Spacing time.Duration // between AWS calls; Route 53 Domains throttles at about one call per 4 s

	dnsServer string
	aws       *route53domains.Client
	gate      sync.Mutex
	lastCall  time.Time
	cacheMu   sync.Mutex
	cache     map[string]Availability
	wildcard  map[string]bool
}

// NewChecker uses the system resolver from /etc/resolv.conf (or server, host:port, if given).
func NewChecker(ctx context.Context, useAWS bool, server string) (*Checker, error) {
	c := &Checker{UseAWS: useAWS, Spacing: 4 * time.Second, cache: map[string]Availability{}, wildcard: map[string]bool{}}
	if server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(conf.Servers) == 0 {
			server = "1.1.1.1:53"
		} else {
			server = conf.Servers[0] + ":" + conf.Port
		}
	}
	c.dnsServer = server
	if useAWS {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
		if err != nil {
			return nil, fmt.Errorf("AWS config: %w (use --no-aws for DNS-only checks)", err)
		}
		c.aws = route53domains.NewFromConfig(cfg)
	}
	return c, nil
}

// Registrable returns the domain someone would buy for host (example.co.uk for a.b.example.co.uk),
// or "" for IP addresses, single labels and public suffixes themselves.
func Registrable(host string) string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || !strings.Contains(host, ".") || strings.Trim(host, "0123456789.:[]") == "" {
		return ""
	}
	suffix := suffixOf(host)
	if suffix == "" || suffix == host {
		return ""
	}
	rest := strings.TrimSuffix(host, "."+suffix)
	return rest[strings.LastIndexByte(rest, '.')+1:] + "." + suffix
}

// suffixOf returns the ICANN public suffix of a name: what a registrar sells under. Private
// suffixes in the list (googleapis.com, github.io, ...) are someone's registered domain, so a
// name under one is bought by buying that domain.
func suffixOf(name string) string {
	labels := strings.Split(name, ".")
	best := ""
	for i := len(labels) - 1; i >= 0; i-- {
		candidate := strings.Join(labels[i:], ".")
		if s, icann := publicsuffix.PublicSuffix(candidate); s == candidate && icann {
			best = candidate
		} else if i < len(labels)-1 && best == "" {
			break
		}
	}
	if best == "" {
		// Not in the list: the default rule makes the last label the suffix.
		best = labels[len(labels)-1]
	}
	return best
}

// hasNameservers is true only when name has NS records of its own. NXDOMAIN, no data, errors and
// timeouts are all false, so they fall through to the registrar and nothing is claimed from them.
func (c *Checker) hasNameservers(name string) bool {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeNS)
	m.RecursionDesired = true
	client := &dns.Client{Timeout: dnsTimeout}
	for attempt := 0; attempt < 2; attempt++ {
		r, _, err := client.Exchange(m, c.dnsServer)
		if err != nil {
			continue
		}
		if r.Truncated {
			client.Net = "tcp"
			continue
		}
		for _, rr := range r.Answer {
			if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, dns.Fqdn(name)) {
				return true
			}
		}
		return false
	}
	return false
}

// suffixAnswersEverything guards against suffixes that answer every name: a random label under the
// suffix must not look delegated before delegation is believed.
func (c *Checker) suffixAnswersEverything(suffix string) bool {
	c.cacheMu.Lock()
	known, ok := c.wildcard[suffix]
	c.cacheMu.Unlock()
	if ok {
		return known
	}
	probe := fmt.Sprintf("ghosted-probe-%016x.%s", rand.Uint64(), suffix)
	answers := c.hasNameservers(probe)
	c.cacheMu.Lock()
	c.wildcard[suffix] = answers
	c.cacheMu.Unlock()
	return answers
}

// Check returns the availability of a registrable domain. Results are kept for the run.
func (c *Checker) Check(ctx context.Context, domain string) Availability {
	c.cacheMu.Lock()
	if a, ok := c.cache[domain]; ok {
		c.cacheMu.Unlock()
		return a
	}
	c.cacheMu.Unlock()
	a := c.check(ctx, domain)
	c.cacheMu.Lock()
	c.cache[domain] = a
	c.cacheMu.Unlock()
	return a
}

func (c *Checker) check(ctx context.Context, domain string) Availability {
	suffix := suffixOf(domain)
	if c.hasNameservers(domain) && !c.suffixAnswersEverything(suffix) {
		return Availability{domain, StatusRegistered, "dns-delegation", "delegated in DNS (has NS records), so it is registered"}
	}
	if !awsTLDs[suffix] {
		return Availability{domain, StatusUnsupportedTLD, "none", "AWS Route 53 cannot register ." + suffix + "; check with a registrar for that suffix"}
	}
	if !c.UseAWS {
		return Availability{domain, StatusUnchecked, "none", "not delegated in DNS; AWS not asked (--no-aws)"}
	}
	return c.askAWS(ctx, domain)
}

func (c *Checker) askAWS(ctx context.Context, domain string) Availability {
	c.gate.Lock()
	defer c.gate.Unlock()
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if wait := c.Spacing - time.Since(c.lastCall); wait > 0 {
			time.Sleep(wait)
		}
		c.lastCall = time.Now()
		resp, err := c.aws.CheckDomainAvailability(ctx, &route53domains.CheckDomainAvailabilityInput{DomainName: aws.String(domain)})
		if err == nil {
			return Availability{domain, string(resp.Availability), "aws-route53", ""}
		}
		lastErr = err
		msg := err.Error()
		if strings.Contains(msg, "UnsupportedTLD") {
			return Availability{domain, StatusUnsupportedTLD, "aws-route53", "AWS returned UnsupportedTLD; check with a registrar for that suffix"}
		}
		if !strings.Contains(msg, "Throttl") && !strings.Contains(msg, "TooManyRequests") || errors.Is(err, context.Canceled) {
			break
		}
		time.Sleep(30 * time.Second)
	}
	return Availability{domain, StatusError, "aws-route53", "no availability claim made: " + lastErr.Error()}
}
