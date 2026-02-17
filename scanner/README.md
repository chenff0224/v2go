# VPN Config Scanner

A Go implementation of a VPN configuration scanner that processes sub*.txt files, decodes various VPN protocols (VMess, VLess, Trojan, Shadowsocks), measures latency, and saves results organized by protocol and speed.

## Features

- **Multi-Protocol Support**: VMess, VLess, Trojan, Shadowsocks
- **Latency Measurement**: Tests connection latency to filter out slow servers
- **Automatic Categorization**: Separates fast (<200ms) and normal (200-800ms) configs
- **Concurrent Processing**: Efficient scanning with configurable timeouts
- **Comprehensive Testing**: Full test suite with benchmarks

## Usage

### Command Line Interface

```bash
# Run scanner on test data
go run scanner_main.go -dir=test_data -timeout=2s

# Run scanner on current directory
go run scanner_main.go -dir=. -timeout=3s

# Show help
go run scanner_main.go -help
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "time"
)

func main() {
    // Create scanner with 3-second timeout
    scanner := NewScanner(3 * time.Second)
    
    // Scan directory for sub*.txt files
    err := scanner.ScanDirectory("./configs")
    if err != nil {
        fmt.Printf("Scan failed: %v\n", err)
        return
    }
    
    // Print summary
    scanner.PrintSummary()
    
    // Save results to files
    err = scanner.SaveResults()
    if err != nil {
        fmt.Printf("Save failed: %v\n", err)
        return
    }
}
```

## API Reference

### Scanner

```go
type Scanner struct {
    timeout time.Duration
    results map[string][]ConfigInfo
    mu      sync.RWMutex
}
```

### Methods

- `NewScanner(timeout time.Duration) *Scanner` - Create new scanner instance
- `ScanDirectory(dirPath string) error` - Scan directory for sub*.txt files
- `SaveResults() error` - Save results to protocol-specific files
- `GetResults() map[string][]ConfigInfo` - Get current scan results
- `PrintSummary()` - Print scan summary

### ConfigInfo

```go
type ConfigInfo struct {
    Link    string
    Remark  string
    Latency int
    Host    string
    Port    int
}
```

## Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run tests with race detection
make test-verbose

# Run benchmarks
go test -bench=.
```

## Output Files

The scanner creates the following output files:

- `fast_vmess.txt` - Fast VMess configs (<200ms)
- `vmess.txt` - Normal VMess configs (200-800ms)
- `fast_vless.txt` - Fast VLess configs (<200ms)
- `vless.txt` - Normal VLess configs (200-800ms)
- `fast_trojan.txt` - Fast Trojan configs (<200ms)
- `trojan.txt` - Normal Trojan configs (200-800ms)
- `fast_ss.txt` - Fast Shadowsocks configs (<200ms)
- `ss.txt` - Normal Shadowsocks configs (200-800ms)

## Protocol Support

### VMess
- Decodes base64-encoded JSON configuration
- Extracts host, port, and remark from config

### VLess
- Parses URL-encoded configuration
- Extracts host, port, and remark from fragment

### Trojan
- Parses URL-encoded configuration
- Extracts host, port, and remark from fragment

### Shadowsocks
- Parses URL-encoded configuration
- Extracts host, port, and remark from fragment

## Performance

The scanner is designed for efficiency:

- **Concurrent Processing**: Uses goroutines for parallel scanning
- **Memory Efficient**: Processes files line by line
- **Configurable Timeouts**: Prevents hanging on slow connections
- **Duplicate Detection**: Avoids processing duplicate configurations

## Example Output

```
🛰 VPN Config Scanner
===================
📂 Scanning directory: ./test_data
⏱️ Timeout: 2s

📄 Found 2 files to scan
📁 Scanning file: sub1.txt
📁 Scanning file: sub2.txt

📊 Scan Summary:
  vmess: 2 configs
  vless: 2 configs
  trojan: 2 configs
  ss: 2 configs
  Total: 8 configs
⏱️ Scan completed in: 1.234s

💾 Saving results...
✅ Saved 1 fast vmess configs to fast_vmess.txt
✅ Saved 1 normal vmess configs to vmess.txt
✅ Saved 1 fast vless configs to fast_vless.txt
✅ Saved 1 normal vless configs to vless.txt
✅ Saved 1 fast trojan configs to fast_trojan.txt
✅ Saved 1 normal trojan configs to trojan.txt
✅ Saved 1 fast ss configs to fast_ss.txt
✅ Saved 1 normal ss configs to ss.txt
✅ Results saved successfully!
```

## Dependencies

No external dependencies required. Uses only Go standard library.

## License

This project is part of the v2go VPN configuration aggregator.
