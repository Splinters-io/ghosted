package logs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Logger handles structured logging for receipts
type Logger struct {
	scanPath      string
	scanLogPath   string
	apiLogPath    string
	errorLogPath  string
	scanLog       *os.File
	apiLog        *os.File
	errorLog      *os.File
}

// NewLogger creates a new logger for a scan
func NewLogger(scanPath string) (*Logger, error) {
	logsDir := filepath.Join(scanPath, "logs")
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create logs directory: %w", err)
	}

	scanLogPath := filepath.Join(logsDir, "scan.log")
	apiLogPath := filepath.Join(logsDir, "api_calls.jsonl")
	errorLogPath := filepath.Join(logsDir, "errors.log")

	scanLog, err := os.OpenFile(scanLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open scan log: %w", err)
	}

	apiLog, err := os.OpenFile(apiLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		scanLog.Close()
		return nil, fmt.Errorf("failed to open API log: %w", err)
	}

	errorLog, err := os.OpenFile(errorLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		scanLog.Close()
		apiLog.Close()
		return nil, fmt.Errorf("failed to open error log: %w", err)
	}

	return &Logger{
		scanPath:     scanPath,
		scanLogPath:  scanLogPath,
		apiLogPath:   apiLogPath,
		errorLogPath: errorLogPath,
		scanLog:      scanLog,
		apiLog:       apiLog,
		errorLog:     errorLog,
	}, nil
}

// Close closes all log files
func (l *Logger) Close() error {
	var errs []error
	if err := l.scanLog.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := l.apiLog.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := l.errorLog.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing logs: %v", errs)
	}
	return nil
}

// Info logs an informational message
func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] INFO: %s\n", timestamp, msg)
	l.scanLog.WriteString(line)
	l.scanLog.Sync()
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] ERROR: %s\n", timestamp, msg)
	l.errorLog.WriteString(line)
	l.errorLog.Sync()
	l.scanLog.WriteString(line)
	l.scanLog.Sync()
}

// Command logs a command execution
func (l *Logger) Command(cmd string, args []string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] COMMAND: %s %v\n", timestamp, cmd, args)
	l.scanLog.WriteString(line)
	l.scanLog.Sync()
}

// APICall logs an API call with full request/response
func (l *Logger) APICall(provider, domain, status string, request, response interface{}) {
	entry := APICallEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Provider:  provider,
		Domain:    domain,
		Status:    status,
		Request:   request,
		Response:  response,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		l.Error("Failed to marshal API call log: %v", err)
		return
	}

	l.apiLog.WriteString(string(data) + "\n")
	l.apiLog.Sync()
}

// Statistics logs scan statistics
func (l *Logger) Statistics(stats map[string]interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	l.scanLog.WriteString(fmt.Sprintf("\n[%s] SCAN STATISTICS:\n", timestamp))

	for key, value := range stats {
		l.scanLog.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
	}

	l.scanLog.WriteString("\n")
	l.scanLog.Sync()
}

// Phase logs a scan phase starting
func (l *Logger) Phase(name string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("\n[%s] === PHASE: %s ===\n\n", timestamp, name)
	l.scanLog.WriteString(line)
	l.scanLog.Sync()
}

// APICallEntry represents a single API call log entry
type APICallEntry struct {
	Timestamp string      `json:"timestamp"`
	Provider  string      `json:"provider"`
	Domain    string      `json:"domain"`
	Status    string      `json:"status"`
	Request   interface{} `json:"request"`
	Response  interface{} `json:"response"`
}
