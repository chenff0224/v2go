package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
)

// ASCII Art Banner
const banner = `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  __   _____ ___  ___    ___  ___   _   _  _ _  _ ___ ___     ║
║  \ \ / /_  ) __|/ _ \  / __|/ __| /_\ | \| | \| | __| _ \    ║
║   \ V / / / (_ | (_) | \__ \ (__ / _ \| .` + "`" + ` | .` + "`" + ` | _||   /    ║
║    \_/ /___\___|\___/  |___/\___/_/ \_\_|\_|_|\_|___|_|_\    ║
║                                                              ║
║                    VPN Configuration Scanner                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`

// Color codes for cross-platform compatibility
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

// Progress indicators
const (
	SpinnerChars = "|/-\\"
	ProgressBar  = "█"
	EmptyBar     = "░"
)

func main() {
	// Command line flags
	var (
		dir            = flag.String("dir", ".", "Directory to scan for sub*.txt files")
		timeout        = flag.Duration("timeout", 3*time.Second, "Timeout for latency measurements")
		measureLatency = flag.Bool("latency", false, "Enable latency measurement (slower but more accurate)")
		help           = flag.Bool("help", false, "Show help message")
		noColor        = flag.Bool("no-color", false, "Disable colored output")
		quiet          = flag.Bool("quiet", false, "Quiet mode (minimal output)")
		github         = flag.Bool("github", false, "Force fetch from GitHub repository instead of local files")
	)

	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// Initialize color support
	initColors(*noColor)

	// Show banner
	if !*quiet {
		showBanner()
	}

	// Create scanner instance
	scanner := NewScanner(*timeout)

	// Set latency measurement flag
	scanner.SetLatencyMeasurement(*measureLatency)

	// Check if directory exists
	if _, err := os.Stat(*dir); os.IsNotExist(err) {
		printError("Directory does not exist: %s", *dir)
		os.Exit(1)
	}

	// Start scanning with interactive progress
	if !*quiet {
		printInfo("Scanning directory: %s", *dir)
		printInfo("Timeout: %v", *timeout)
		if *measureLatency {
			printWarning("Latency measurement enabled (slower but more accurate)")
		}
		printInfo("Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
		fmt.Println()
	}

	start := time.Now()
	var err error

	// Check if GitHub flag is set
	if *github {
		if !*quiet {
			printInfo("Forcing GitHub fallback mode")
		}
		err = scanner.scanFromGitHub(*quiet)
	} else {
		err = scanner.ScanDirectoryInteractive(*dir, *quiet)
	}
	scanDuration := time.Since(start)

	if err != nil {
		printError("Scan failed: %v", err)
		os.Exit(1)
	}

	// Print summary
	if !*quiet {
		fmt.Println()
		scanner.PrintSummary()
		printSuccess("Scan completed in: %v", scanDuration)
	} else {
		scanner.PrintSummary()
	}

	// Save results
	if !*quiet {
		printInfo("Saving results...")
	}
	err = scanner.SaveResults()
	if err != nil {
		printError("Failed to save results: %v", err)
		os.Exit(1)
	}

	if !*quiet {
		printSuccess("Results saved successfully!")
	}
}

func showHelp() {
	fmt.Println("VPN Config Scanner")
	fmt.Println("=================")
	fmt.Println()
	fmt.Println("A powerful VPN configuration scanner that processes sub*.txt files,")
	fmt.Println("decodes various VPN protocols, measures latency, and saves results")
	fmt.Println("organized by protocol and speed.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run scanner_main.go [options]")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run scanner_main.go -dir=./configs -timeout=5s")
	fmt.Println("  go run scanner_main.go -latency -dir=.")
	fmt.Println("  go run scanner_main.go -quiet -no-color")
	fmt.Println("  go run scanner_main.go -github  # Force fetch from GitHub")
	fmt.Println("  go run scanner_main.go -github -quiet  # GitHub mode with minimal output")
}

func showBanner() {
	fmt.Print(ColorCyan)
	fmt.Print(banner)
	fmt.Print(ColorReset)
	fmt.Println()
}

func initColors(noColor bool) {
	if noColor || runtime.GOOS == "windows" {
		// Disable colors on Windows or when requested
		// This is a simple approach - in production you might want to use a proper color library
	}
}

func printError(format string, args ...interface{}) {
	fmt.Printf("%s❌ %s%s\n", ColorRed, fmt.Sprintf(format, args...), ColorReset)
}

func printSuccess(format string, args ...interface{}) {
	fmt.Printf("%s✅ %s%s\n", ColorGreen, fmt.Sprintf(format, args...), ColorReset)
}

func printInfo(format string, args ...interface{}) {
	fmt.Printf("%sℹ️  %s%s\n", ColorBlue, fmt.Sprintf(format, args...), ColorReset)
}

func printWarning(format string, args ...interface{}) {
	fmt.Printf("%s⚠️  %s%s\n", ColorYellow, fmt.Sprintf(format, args...), ColorReset)
}
