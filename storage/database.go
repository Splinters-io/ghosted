package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database represents an isolated scan database
type Database struct {
	db       *sql.DB
	scanPath string // Full path to scan directory
}

// New creates a new isolated database for this scan
func New(scanPath string) (*Database, error) {
	// Ensure scan directory exists
	if err := os.MkdirAll(scanPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create scan directory: %w", err)
	}

	dbPath := filepath.Join(scanPath, "database.db")
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	d := &Database{
		db:       db,
		scanPath: scanPath,
	}

	if err := d.createSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return d, nil
}

// OpenExisting opens an existing database without creating schema
func OpenExisting(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	scanPath := filepath.Dir(dbPath)

	d := &Database{
		db:       db,
		scanPath: scanPath,
	}

	return d, nil
}

func (d *Database) createSchema() error {
	schema := `
	-- Subdomain enumeration results
	CREATE TABLE IF NOT EXISTS subdomains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		subdomain TEXT NOT NULL UNIQUE,
		source TEXT NOT NULL,
		discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- CSP headers extracted
	CREATE TABLE IF NOT EXISTS csp_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		origin_domain TEXT NOT NULL,
		csp_header TEXT NOT NULL,
		fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(origin_domain)
	);

	-- External domains found in CSP
	CREATE TABLE IF NOT EXISTS external_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		reference_count INTEGER DEFAULT 0,
		is_dangerous BOOLEAN DEFAULT 0,
		category TEXT
	);

	-- Trust relationships (which origin trusts which external)
	CREATE TABLE IF NOT EXISTS trust_relationships (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		origin_domain TEXT NOT NULL,
		external_domain TEXT NOT NULL,
		csp_directive TEXT,
		UNIQUE(origin_domain, external_domain)
	);

	-- Domain availability checks
	CREATE TABLE IF NOT EXISTS availability_checks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL UNIQUE,
		status TEXT NOT NULL,
		available BOOLEAN,
		checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		cost_usd REAL DEFAULT 0.01,
		api_response TEXT
	);

	-- PublicWWW research results
	CREATE TABLE IF NOT EXISTS publicwww_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		site_url TEXT NOT NULL,
		snippet TEXT,
		researched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(domain, site_url)
	);

	-- High-risk findings
	CREATE TABLE IF NOT EXISTS high_risk_findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		status TEXT NOT NULL,
		affected_origins TEXT,
		severity TEXT,
		attack_vectors TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	-- Wordlist progress tracking
	CREATE TABLE IF NOT EXISTS wordlist_progress (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		wordlist_name TEXT NOT NULL UNIQUE,
		wordlist_path TEXT NOT NULL,
		completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		subdomains_found INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_external_domains_dangerous ON external_domains(is_dangerous);
	CREATE INDEX IF NOT EXISTS idx_trust_origin ON trust_relationships(origin_domain);
	CREATE INDEX IF NOT EXISTS idx_trust_external ON trust_relationships(external_domain);
	`

	_, err := d.db.Exec(schema)
	return err
}

// Close closes the database
func (d *Database) Close() error {
	return d.db.Close()
}

// Query executes a query that returns rows
func (d *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

// QueryRow executes a query that returns a single row
func (d *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.db.QueryRow(query, args...)
}

// Exec executes a query without returning rows
func (d *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

// SaveSubdomain saves a discovered subdomain
func (d *Database) SaveSubdomain(subdomain, source string) error {
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO subdomains (subdomain, source)
		VALUES (?, ?)
	`, strings.ToLower(subdomain), source)
	return err
}

// SaveCSPRecord saves a CSP header
func (d *Database) SaveCSPRecord(origin, cspHeader string) error {
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO csp_records (origin_domain, csp_header)
		VALUES (?, ?)
	`, strings.ToLower(origin), cspHeader)
	return err
}

// SaveExternalDomain saves an external domain with metadata
func (d *Database) SaveExternalDomain(domain, category string, isDangerous bool) error {
	_, err := d.db.Exec(`
		INSERT OR IGNORE INTO external_domains (domain, category, is_dangerous, reference_count)
		VALUES (?, ?, ?, 0)
	`, domain, category, isDangerous)
	return err
}

// FlagDangerous marks a domain as dangerous
func (d *Database) FlagDangerous(domain string) error {
	_, err := d.db.Exec(`
		UPDATE external_domains
		SET is_dangerous = 1
		WHERE domain = ?
	`, domain)
	return err
}

// SaveTrustRelationship saves a trust relationship
func (d *Database) SaveTrustRelationship(origin, external, directive string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Insert relationship
	_, err = tx.Exec(`
		INSERT OR IGNORE INTO trust_relationships (origin_domain, external_domain, csp_directive)
		VALUES (?, ?, ?)
	`, strings.ToLower(origin), strings.ToLower(external), directive)
	if err != nil {
		return err
	}

	// Increment reference count
	_, err = tx.Exec(`
		UPDATE external_domains
		SET reference_count = reference_count + 1
		WHERE domain = ?
	`, strings.ToLower(external))
	if err != nil {
		return err
	}

	return tx.Commit()
}

// SaveAvailabilityCheck saves domain availability check result
func (d *Database) SaveAvailabilityCheck(domain, status string, available bool, apiResponse string) error {
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO availability_checks (domain, status, available, api_response, cost_usd)
		VALUES (?, ?, ?, ?, 0.01)
	`, domain, status, available, apiResponse)
	return err
}

// SaveHighRiskFinding saves a high-risk finding
func (d *Database) SaveHighRiskFinding(domain, status, affectedOrigins, severity, attackVectors string) error {
	_, err := d.db.Exec(`
		INSERT INTO high_risk_findings (domain, status, affected_origins, severity, attack_vectors)
		VALUES (?, ?, ?, ?, ?)
	`, domain, status, affectedOrigins, severity, attackVectors)
	return err
}

// GetAllExternalDomains returns all external domains sorted by reference count
func (d *Database) GetAllExternalDomains() ([]ExternalDomain, error) {
	rows, err := d.db.Query(`
		SELECT domain, reference_count, is_dangerous, category
		FROM external_domains
		ORDER BY reference_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []ExternalDomain
	for rows.Next() {
		var ed ExternalDomain
		if err := rows.Scan(&ed.Domain, &ed.ReferenceCount, &ed.IsDangerous, &ed.Category); err != nil {
			return nil, err
		}

		// Get trusting domains
		trustRows, err := d.db.Query(`
			SELECT origin_domain
			FROM trust_relationships
			WHERE external_domain = ?
			ORDER BY origin_domain
		`, ed.Domain)
		if err != nil {
			return nil, err
		}

		for trustRows.Next() {
			var origin string
			if err := trustRows.Scan(&origin); err != nil {
				trustRows.Close()
				return nil, err
			}
			ed.TrustingDomains = append(ed.TrustingDomains, origin)
		}
		trustRows.Close()

		domains = append(domains, ed)
	}

	return domains, rows.Err()
}

// GetAvailableDomains returns domains that are available or expired
func (d *Database) GetAvailableDomains() ([]AvailabilityResult, error) {
	rows, err := d.db.Query(`
		SELECT domain, status, available, checked_at
		FROM availability_checks
		WHERE available = 1
		ORDER BY domain
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AvailabilityResult
	for rows.Next() {
		var ar AvailabilityResult
		var checkedAt string
		if err := rows.Scan(&ar.Domain, &ar.Status, &ar.Available, &checkedAt); err != nil {
			return nil, err
		}
		ar.CheckedAt, _ = time.Parse("2006-01-02 15:04:05", checkedAt)

		// Get affected origins (DISTINCT to avoid case duplicates)
		trustRows, err := d.db.Query(`
			SELECT DISTINCT LOWER(origin_domain)
			FROM trust_relationships
			WHERE external_domain = ?
			ORDER BY LOWER(origin_domain)
		`, ar.Domain)
		if err != nil {
			return nil, err
		}

		for trustRows.Next() {
			var origin string
			if err := trustRows.Scan(&origin); err != nil {
				trustRows.Close()
				return nil, err
			}
			ar.AffectedOrigins = append(ar.AffectedOrigins, origin)
		}
		trustRows.Close()

		results = append(results, ar)
	}

	return results, rows.Err()
}

// GetStatistics returns scan statistics
func (d *Database) GetStatistics() (ScanStats, error) {
	var stats ScanStats

	// Subdomains
	err := d.db.QueryRow("SELECT COUNT(*) FROM subdomains").Scan(&stats.TotalSubdomains)
	if err != nil {
		return stats, err
	}

	// CSP records
	err = d.db.QueryRow("SELECT COUNT(*) FROM csp_records").Scan(&stats.SubdomainsWithCSP)
	if err != nil {
		return stats, err
	}

	// External domains
	err = d.db.QueryRow("SELECT COUNT(*) FROM external_domains").Scan(&stats.UniqueExternalDomains)
	if err != nil {
		return stats, err
	}

	// Dangerous domains
	err = d.db.QueryRow("SELECT COUNT(*) FROM external_domains WHERE is_dangerous = 1").Scan(&stats.DangerousDomains)
	if err != nil {
		return stats, err
	}

	// Availability checks
	err = d.db.QueryRow("SELECT COUNT(*) FROM availability_checks").Scan(&stats.DomainsChecked)
	if err != nil {
		return stats, err
	}

	// Available domains
	err = d.db.QueryRow("SELECT COUNT(*) FROM availability_checks WHERE available = 1").Scan(&stats.AvailableDomains)
	if err != nil {
		return stats, err
	}

	return stats, nil
}

// SaveWordlistProgress marks a wordlist as completed
func (d *Database) SaveWordlistProgress(wordlistName, wordlistPath string, subdomainsFound int) error {
	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO wordlist_progress (wordlist_name, wordlist_path, subdomains_found, completed_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`, wordlistName, wordlistPath, subdomainsFound)
	return err
}

// IsWordlistCompleted checks if a wordlist has already been processed
func (d *Database) IsWordlistCompleted(wordlistName string) (bool, error) {
	var count int
	err := d.db.QueryRow(`
		SELECT COUNT(*) FROM wordlist_progress WHERE wordlist_name = ?
	`, wordlistName).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetCompletedWordlists returns list of completed wordlist names
func (d *Database) GetCompletedWordlists() ([]string, error) {
	rows, err := d.db.Query(`
		SELECT wordlist_name FROM wordlist_progress ORDER BY completed_at
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wordlists []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		wordlists = append(wordlists, name)
	}
	return wordlists, rows.Err()
}

// Types
type ExternalDomain struct {
	Domain          string
	ReferenceCount  int
	IsDangerous     bool
	Category        string
	TrustingDomains []string
}

type AvailabilityResult struct {
	Domain          string
	Status          string
	Available       bool
	CheckedAt       time.Time
	AffectedOrigins []string
}

type ScanStats struct {
	TotalSubdomains       int
	SubdomainsWithCSP     int
	UniqueExternalDomains int
	DangerousDomains      int
	DomainsChecked        int
	AvailableDomains      int
}
