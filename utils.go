package jwt

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

const tokenChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/-_="

func readCertFile(filePath string) (string, error) {
	var buffer bytes.Buffer
	var RecordingEnabled bool
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "-----") {
			if strings.Contains(line, "BEGIN CERTIFICATE") {
				RecordingEnabled = true
				continue
			}
			if strings.Contains(line, "END CERTIFICATE") {
				break
			}
		}
		if RecordingEnabled {
			buffer.WriteString(strings.TrimSpace(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func readFile(filePath string) (string, error) {
	var buffer bytes.Buffer
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer fileHandle.Close()

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		buffer.WriteString(strings.TrimSpace(line))
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return buffer.String(), nil
}

func containsTokenCharset(s string) bool {
	dots := 0
	for _, c := range s {
		if !strings.ContainsRune(tokenChars, c) {
			return false
		}
		// Match dot
		if c == 46 {
			dots++
		}
	}
	if dots != 2 {
		return false
	}
	return true
}
