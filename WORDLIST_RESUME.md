# Wordlist Resume Feature

## Problem Solved

Previously, if you ran beast mode with `--wordlists 0` (passive only) and later wanted to run with `--wordlists 1` (active enumeration), the system would skip the domain entirely because it detected an existing scan. This made it impossible to incrementally add wordlist-based enumeration to an existing scan.

## Solution

The system now tracks which wordlists have been completed in the database and allows you to resume scans with additional wordlists. Only **new/unprocessed** wordlists will be executed.

## How It Works

### 1. **Wordlist Progress Tracking**

A new database table `wordlist_progress` tracks:
- Wordlist name (e.g., `FUZZSUBS_CYFARE_1.txt`)
- Wordlist path
- Completion timestamp
- Number of subdomains found

### 2. **Smart Resume Logic**

When you run a scan on a domain that's already been scanned:

- **If `--wordlists 0` (passive only)**: Skips entirely (passive was already done)
- **If `--wordlists 1+` (active)**: Resumes and processes only pending wordlists

### 3. **Workflow**

**Initial scan (passive only):**
```bash
./ghosted beast targets.txt --wordlists 0
```
- Runs subfinder for passive enumeration
- No wordlists processed
- Scan saved to database

**Resume with wordlists:**
```bash
./ghosted beast targets.txt --wordlists 1
```
- Detects existing scan
- Opens existing database
- Checks which wordlists are completed: **none**
- Runs ALL wordlists (FUZZSUBS_CYFARE_1.txt, FUZZSUBS_CYFARE_2.txt)
- Marks each wordlist as completed
- Continues with CSP fetching, parsing, and checking

**Run again with same command:**
```bash
./ghosted beast targets.txt --wordlists 1
```
- Detects existing scan
- Opens existing database
- Checks which wordlists are completed: **all of them**
- Skips wordlist enumeration entirely
- Continues with CSP fetching on existing subdomains

## Output Examples

### First run (passive only):
```
[*] Running subfinder for example.com...
[OK] Subfinder found 150 subdomains
[*] No wordlists to process (level 0)
```

### Resume with wordlists:
```
[*] Found existing scan: output/beast_example.com_20251006_120000
[*] Resuming with wordlist level 1 (will skip completed wordlists)

Mode: RESUME (processing pending wordlists)

═══════════════════════════════════════════════════════════════
 PHASE 1: RESUME WORDLIST ENUMERATION (BEAST MODE - 500 DNS/sec)
═══════════════════════════════════════════════════════════════

[*] Running subfinder for example.com...
[OK] Subfinder found 150 subdomains

[*] Running dnsx with 2 pending wordlist(s) in parallel...
  Wordlist 1/2: FUZZSUBS_CYFARE_1.txt (starting)
  Wordlist 2/2: FUZZSUBS_CYFARE_2.txt (starting)
  [OK] Wordlist 1/2: FUZZSUBS_CYFARE_1.txt found 45 subdomains
  [OK] Wordlist 2/2: FUZZSUBS_CYFARE_2.txt found 38 subdomains

[OK] Enumeration complete: 233 total subdomains
```

### Second resume (all wordlists already done):
```
[*] Found existing scan: output/beast_example.com_20251006_120000
[*] Resuming with wordlist level 1 (will skip completed wordlists)

Mode: RESUME (processing pending wordlists)

[*] Running subfinder for example.com...
[OK] Subfinder found 150 subdomains

  [SKIP] Wordlist FUZZSUBS_CYFARE_1.txt already processed
  [SKIP] Wordlist FUZZSUBS_CYFARE_2.txt already processed
[*] Skipped 2 already-processed wordlist(s)
[*] All wordlists already processed, skipping enumeration phase

[OK] Enumeration complete: 233 total subdomains
```

## Database Schema

### New Table: `wordlist_progress`
```sql
CREATE TABLE wordlist_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    wordlist_name TEXT NOT NULL UNIQUE,
    wordlist_path TEXT NOT NULL,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    subdomains_found INTEGER DEFAULT 0
);
```

### Helper Methods
```go
// Mark wordlist as completed
db.SaveWordlistProgress(name, path, count)

// Check if wordlist was already processed
completed, _ := db.IsWordlistCompleted(name)

// Get list of completed wordlists
wordlists, _ := db.GetCompletedWordlists()
```

## Key Files Modified

1. **storage/database.go**
   - Added `wordlist_progress` table
   - Added helper methods for tracking

2. **scanner/enumerator.go**
   - Modified `Enumerate()` to check completed wordlists
   - Saves progress after each wordlist completes

3. **cmd/ghosted/main.go**
   - Updated `runScan()` and `runScanBeast()` resume logic
   - Opens existing database when resuming
   - Retrieves all subdomains from DB when resuming

## Benefits

- **Incremental Enumeration**: Start with passive, add active later
- **No Duplicate Work**: Skips already-processed wordlists
- **Resume After Interruption**: If interrupted, resume without re-running completed wordlists
- **Progress Tracking**: Database shows exactly which wordlists completed
- **Efficient**: Only processes pending wordlists

## Use Cases

1. **Budget-Conscious Scanning**: Run passive first (free), then add active enumeration only for interesting targets
2. **Interrupted Scans**: If scan crashes during wordlist 2, resume picks up where it left off
3. **Staged Operations**: Run lightweight scans first, deep scans on specific targets later
4. **Large Wordlist Sets**: Process one wordlist at a time instead of all at once
