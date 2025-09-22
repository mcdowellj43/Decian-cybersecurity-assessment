package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// Logger provides structured logging for the agent
type Logger struct {
	verbose bool
}

// LogLevel represents logging levels
type LogLevel string

const (
	DEBUG LogLevel = "DEBUG"
	INFO  LogLevel = "INFO"
	WARN  LogLevel = "WARN"
	ERROR LogLevel = "ERROR"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// NewLogger creates a new logger instance
func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
	}
}

// Debug logs a debug message (only if verbose mode is enabled)
func (l *Logger) Debug(message string, fields ...map[string]interface{}) {
	if l.verbose {
		l.log(DEBUG, message, fields...)
	}
}

// Info logs an info message
func (l *Logger) Info(message string, fields ...map[string]interface{}) {
	l.log(INFO, message, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields ...map[string]interface{}) {
	l.log(WARN, message, fields...)
}

// Error logs an error message
func (l *Logger) Error(message string, fields ...map[string]interface{}) {
	l.log(ERROR, message, fields...)
}

// Fatal logs an error message and exits the program
func (l *Logger) Fatal(message string, fields ...map[string]interface{}) {
	l.log(ERROR, message, fields...)
	os.Exit(1)
}

// log handles the actual logging
func (l *Logger) log(level LogLevel, message string, fields ...map[string]interface{}) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
	}

	// Merge all field maps
	if len(fields) > 0 {
		entry.Fields = make(map[string]interface{})
		for _, fieldMap := range fields {
			for k, v := range fieldMap {
				entry.Fields[k] = v
			}
		}
	}

	// Format output based on verbose mode
	if l.verbose {
		// JSON format for verbose mode
		jsonData, err := json.Marshal(entry)
		if err != nil {
			log.Printf("Failed to marshal log entry: %v", err)
			return
		}
		fmt.Println(string(jsonData))
	} else {
		// Simple format for normal mode
		timestamp := entry.Timestamp.Format("2006-01-02 15:04:05")
		if entry.Fields != nil && len(entry.Fields) > 0 {
			fmt.Printf("[%s] %s: %s %v\n", timestamp, level, message, entry.Fields)
		} else {
			fmt.Printf("[%s] %s: %s\n", timestamp, level, message)
		}
	}
}