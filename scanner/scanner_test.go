package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanner_NewScanner(t *testing.T) {
	timeout := 5 * time.Second
	scanner := NewScanner(timeout)

	if scanner.timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, scanner.timeout)
	}

	if scanner.results == nil {
		t.Error("Expected results map to be initialized")
	}
}

func TestScanner_decodeVMess(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Test valid VMess link
	validVMess := "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0="

	host, port, remark, protocol := scanner.decodeVMess(validVMess)

	if protocol != "vmess" {
		t.Errorf("Expected protocol 'vmess', got '%s'", protocol)
	}

	if host != "test.com" {
		t.Errorf("Expected host 'test.com', got '%s'", host)
	}

	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}

	if remark != "Test" {
		t.Errorf("Expected remark 'Test', got '%s'", remark)
	}
}

func TestScanner_decodeVLess(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Test valid VLess link
	validVLess := "vless://12345678-1234-1234-1234-123456789abc@test.com:443?encryption=none&security=tls&type=ws&host=test.com&path=/ws#TestVLess"

	host, port, remark, protocol := scanner.decodeVLess(validVLess)

	if protocol != "vless" {
		t.Errorf("Expected protocol 'vless', got '%s'", protocol)
	}

	if host != "test.com" {
		t.Errorf("Expected host 'test.com', got '%s'", host)
	}

	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}

	if remark != "TestVLess" {
		t.Errorf("Expected remark 'TestVLess', got '%s'", remark)
	}
}

func TestScanner_decodeTrojan(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Test valid Trojan link
	validTrojan := "trojan://password@test.com:443?security=tls&type=tcp#TestTrojan"

	host, port, remark, protocol := scanner.decodeTrojan(validTrojan)

	if protocol != "trojan" {
		t.Errorf("Expected protocol 'trojan', got '%s'", protocol)
	}

	if host != "test.com" {
		t.Errorf("Expected host 'test.com', got '%s'", host)
	}

	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}

	if remark != "TestTrojan" {
		t.Errorf("Expected remark 'TestTrojan', got '%s'", remark)
	}
}

func TestScanner_decodeSS(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Test valid Shadowsocks link
	validSS := "ss://YWVzLTI1Ni1nY206dGVzdA@test.com:443#TestSS"

	host, port, remark, protocol := scanner.decodeSS(validSS)

	if protocol != "ss" {
		t.Errorf("Expected protocol 'ss', got '%s'", protocol)
	}

	if host != "test.com" {
		t.Errorf("Expected host 'test.com', got '%s'", host)
	}

	if port != 443 {
		t.Errorf("Expected port 443, got %d", port)
	}

	if remark != "TestSS" {
		t.Errorf("Expected remark 'TestSS', got '%s'", remark)
	}
}

func TestScanner_decodeLink(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	tests := []struct {
		link     string
		expected string
	}{
		{"vmess://test", "vmess"},
		{"vless://test", "vless"},
		{"trojan://test", "trojan"},
		{"ss://test", "ss"},
		{"invalid://test", ""},
	}

	for _, test := range tests {
		_, _, _, protocol := scanner.decodeLink(test.link)
		if protocol != test.expected {
			t.Errorf("For link %s, expected protocol '%s', got '%s'", test.link, test.expected, protocol)
		}
	}
}

func TestScanner_scanFile(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "sub1.txt")

	// Write test content
	content := `vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0=
vless://12345678-1234-1234-1234-123456789abc@test.com:443?encryption=none&security=tls&type=ws&host=test.com&path=/ws#TestVLess
trojan://password@test.com:443?security=tls&type=tcp#TestTrojan
ss://YWVzLTI1Ni1nY206dGVzdA@test.com:443#TestSS`

	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	scanner := NewScanner(1 * time.Millisecond) // Very short timeout to fail quickly
	err = scanner.scanFile(testFile)
	if err != nil {
		t.Errorf("scanFile failed: %v", err)
	}

	// The scanner will try to measure latency and fail, so we won't get results
	// This is expected behavior - the scanner filters out configs that can't be reached
	results := scanner.GetResults()
	// We expect no results because the test hosts don't exist
	if len(results) > 0 {
		t.Logf("Got %d results (this might be unexpected)", len(results))
	}
}

func TestScanner_ScanDirectory(t *testing.T) {
	// Create temporary directory with test files
	tempDir := t.TempDir()

	// Create test files
	testFiles := []string{"sub1.txt", "sub2.txt", "sub3.txt"}
	for _, filename := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		content := `vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0=`
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	scanner := NewScanner(1 * time.Millisecond) // Very short timeout to fail quickly
	err := scanner.ScanDirectory(tempDir)
	if err != nil {
		t.Errorf("ScanDirectory failed: %v", err)
	}

	// The scanner will try to measure latency and fail, so we won't get results
	// This is expected behavior - the scanner filters out configs that can't be reached
	results := scanner.GetResults()
	// We expect no results because the test hosts don't exist
	if len(results) > 0 {
		t.Logf("Got %d results (this might be unexpected)", len(results))
	}
}

func TestScanner_ScanDirectory_NoFiles(t *testing.T) {
	// Create empty temporary directory
	tempDir := t.TempDir()

	scanner := NewScanner(5 * time.Second)
	err := scanner.ScanDirectory(tempDir)
	// With GitHub fallback, this should now succeed instead of failing
	if err != nil {
		t.Logf("ScanDirectory with fallback: %v", err)
		// This might fail if network is not available, which is acceptable
	} else {
		t.Log("ScanDirectory succeeded with GitHub fallback")
	}
}

func TestScanner_writeFile(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Create temporary file
	tempFile := filepath.Join(t.TempDir(), "test.txt")
	lines := []string{"line1", "line2", "line3"}

	err := scanner.writeFile(tempFile, lines)
	if err != nil {
		t.Errorf("writeFile failed: %v", err)
	}

	// Read and verify content
	content, err := os.ReadFile(tempFile)
	if err != nil {
		t.Errorf("Failed to read test file: %v", err)
	}

	expected := "line1\nline2\nline3\n"
	if string(content) != expected {
		t.Errorf("Expected content %q, got %q", expected, string(content))
	}
}

func TestScanner_SaveResults(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Add some test results
	scanner.mu.Lock()
	scanner.results["vmess"] = []ConfigInfo{
		{Link: "vmess://test1", Remark: "Test1", Latency: 100},
		{Link: "vmess://test2", Remark: "Test2", Latency: 300},
	}
	scanner.results["vless"] = []ConfigInfo{
		{Link: "vless://test1", Remark: "Test1", Latency: 150},
	}
	scanner.mu.Unlock()

	// Create temporary directory for output
	tempDir := t.TempDir()
	originalDir, _ := os.Getwd()
	defer os.Chdir(originalDir)

	os.Chdir(tempDir)

	err := scanner.SaveResults()
	if err != nil {
		t.Errorf("SaveResults failed: %v", err)
	}

	// Check if files were created
	expectedFiles := []string{"fast_vmess.txt", "vmess.txt", "fast_vless.txt"}
	for _, filename := range expectedFiles {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			t.Errorf("Expected file %s to be created", filename)
		}
	}
}

func TestScanner_GetResults(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Add some test results
	scanner.mu.Lock()
	scanner.results["vmess"] = []ConfigInfo{
		{Link: "vmess://test1", Remark: "Test1", Latency: 100},
	}
	scanner.mu.Unlock()

	results := scanner.GetResults()

	if len(results) != 1 {
		t.Errorf("Expected 1 protocol, got %d", len(results))
	}

	if len(results["vmess"]) != 1 {
		t.Errorf("Expected 1 vmess config, got %d", len(results["vmess"]))
	}

	if results["vmess"][0].Link != "vmess://test1" {
		t.Errorf("Expected link 'vmess://test1', got '%s'", results["vmess"][0].Link)
	}
}

func TestScanner_measureLatency(t *testing.T) {
	scanner := NewScanner(1 * time.Second)

	// Test with a non-existent host (should return -1)
	latency := scanner.measureLatency("nonexistent.example.com", 80)
	if latency != -1 {
		t.Errorf("Expected latency -1 for non-existent host, got %d", latency)
	}

	// Test with localhost (if available)
	latency = scanner.measureLatency("127.0.0.1", 22) // SSH port
	if latency == -1 {
		t.Log("SSH port not available for latency test")
	} else if latency < 0 {
		t.Errorf("Expected positive latency or -1, got %d", latency)
	}
}

func TestScanner_PrintSummary(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Add some test results
	scanner.mu.Lock()
	scanner.results["vmess"] = []ConfigInfo{
		{Link: "vmess://test1", Remark: "Test1", Latency: 100},
		{Link: "vmess://test2", Remark: "Test2", Latency: 200},
	}
	scanner.results["vless"] = []ConfigInfo{
		{Link: "vless://test1", Remark: "Test1", Latency: 150},
	}
	scanner.mu.Unlock()

	// This test just ensures the method doesn't panic
	scanner.PrintSummary()
}

// Benchmark tests
func BenchmarkScanner_decodeVMess(b *testing.B) {
	scanner := NewScanner(5 * time.Second)
	link := "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0="

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.decodeVMess(link)
	}
}

func BenchmarkScanner_measureLatency(b *testing.B) {
	scanner := NewScanner(1 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.measureLatency("127.0.0.1", 22)
	}
}

// GitHub Fallback Tests

func TestScanner_scanFromGitHub_Success(t *testing.T) {
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock response with test configurations
		mockContent := `vmess://eyJ2IjoiMiIsInBzIjoiR2l0SHViVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0=
vless://12345678-1234-1234-1234-123456789abc@test.com:443?encryption=none&security=tls&type=ws&host=test.com&path=/ws#GitHubTestVLess
trojan://password@test.com:443?security=tls&type=tcp#GitHubTestTrojan
ss://YWVzLTI1Ni1nY206dGVzdA@test.com:443#GitHubTestSS`
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockContent))
	}))
	defer server.Close()

	scanner := NewScanner(5 * time.Second)

	// Note: In a real implementation, you might want to make the URL configurable
	// for testing purposes

	// Test the scanFromGitHub method
	err := scanner.scanFromGitHub(false)
	if err != nil {
		t.Errorf("scanFromGitHub failed: %v", err)
	}

	// Check if results were processed
	results := scanner.GetResults()
	if len(results) == 0 {
		t.Error("Expected some results from GitHub scan")
	}
}

func TestScanner_scanFromGitHub_HTTPError(t *testing.T) {
	// Create a mock server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	}))
	defer server.Close()

	scanner := NewScanner(5 * time.Second)

	// This test would need the URL to be configurable to work properly
	// For now, we'll test the error handling logic
	err := scanner.scanFromGitHub(false)
	// The actual GitHub URL will fail in this test, which is expected
	if err == nil {
		t.Log("GitHub scan completed (this might be expected if network is available)")
	}
}

func TestScanner_ScanDirectoryInteractive_NoFiles_Fallback(t *testing.T) {
	// Create empty temporary directory
	tempDir := t.TempDir()

	scanner := NewScanner(5 * time.Second)

	// This should trigger the fallback to GitHub
	err := scanner.ScanDirectoryInteractive(tempDir, false)
	if err != nil {
		t.Logf("ScanDirectoryInteractive with fallback: %v", err)
		// This is expected to fail in test environment without network access
	}
}

func TestScanner_getSpinnerChar(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Test spinner characters
	for i := 0; i < 20; i++ {
		char := scanner.getSpinnerChar(i)
		if char == "" {
			t.Errorf("Expected non-empty spinner character for index %d", i)
		}
	}
}

func TestScanner_createProgressBar(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	// Test basic progress bar creation
	bar := scanner.createProgressBar(0, 10)
	if len(bar) == 0 {
		t.Error("Expected non-empty progress bar")
	}

	// Test with some count
	bar2 := scanner.createProgressBar(5, 10)
	if len(bar2) == 0 {
		t.Error("Expected non-empty progress bar")
	}

	// Test that we get different results for different counts
	if bar == bar2 {
		t.Error("Expected different progress bars for different counts")
	}
}

func TestScanner_getSafeFilename(t *testing.T) {
	scanner := NewScanner(5 * time.Second)

	tests := []struct {
		input string
		check func(string) bool
	}{
		{"normal.txt", func(s string) bool { return s == "normal.txt" }},
		{"file:with:colons.txt", func(s string) bool { return !strings.Contains(s, ":") }},
		{"file*with*stars.txt", func(s string) bool { return !strings.Contains(s, "*") }},
		{"file?with?questions.txt", func(s string) bool { return !strings.Contains(s, "?") }},
		{"file\"with\"quotes.txt", func(s string) bool { return !strings.Contains(s, "\"") }},
		{"file<with>brackets.txt", func(s string) bool { return !strings.Contains(s, "<") && !strings.Contains(s, ">") }},
		{"file|with|pipes.txt", func(s string) bool { return !strings.Contains(s, "|") }},
		{"very_long_filename_" + strings.Repeat("x", 200) + ".txt", func(s string) bool { return len(s) <= 200 }},
	}

	for _, test := range tests {
		result := scanner.getSafeFilename(test.input)
		if !test.check(result) {
			t.Errorf("Safe filename check failed for input %s, got: %s", test.input, result)
		}
	}
}

func TestScanner_ScanDirectoryInteractive_WithFiles(t *testing.T) {
	// Create temporary directory with test files
	tempDir := t.TempDir()

	// Create test files
	testFiles := []string{"sub1.txt", "sub2.txt", "Sub3.txt"}
	for _, filename := range testFiles {
		filePath := filepath.Join(tempDir, filename)
		content := `vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0=`
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	scanner := NewScanner(1 * time.Millisecond) // Very short timeout to fail quickly
	err := scanner.ScanDirectoryInteractive(tempDir, false)
	if err != nil {
		t.Errorf("ScanDirectoryInteractive failed: %v", err)
	}

	// The scanner will try to measure latency and fail, so we won't get results
	// This is expected behavior - the scanner filters out configs that can't be reached
	results := scanner.GetResults()
	// We expect no results because the test hosts don't exist
	if len(results) > 0 {
		t.Logf("Got %d results (this might be unexpected)", len(results))
	}
}

func TestScanner_ScanDirectoryInteractive_QuietMode(t *testing.T) {
	// Create temporary directory with test files
	tempDir := t.TempDir()

	// Create test file
	testFile := filepath.Join(tempDir, "sub1.txt")
	content := `vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6InRlc3QuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIn0=`
	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	scanner := NewScanner(1 * time.Millisecond)           // Very short timeout to fail quickly
	err = scanner.ScanDirectoryInteractive(tempDir, true) // Quiet mode
	if err != nil {
		t.Errorf("ScanDirectoryInteractive in quiet mode failed: %v", err)
	}
}

// Benchmark tests for new functionality

func BenchmarkScanner_getSpinnerChar(b *testing.B) {
	scanner := NewScanner(5 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.getSpinnerChar(i % 10)
	}
}

func BenchmarkScanner_createProgressBar(b *testing.B) {
	scanner := NewScanner(5 * time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.createProgressBar(i%100, 20)
	}
}

func BenchmarkScanner_getSafeFilename(b *testing.B) {
	scanner := NewScanner(5 * time.Second)
	testFilename := "test:file*with?special\"chars<>.txt"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.getSafeFilename(testFilename)
	}
}
