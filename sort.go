package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func sortConfigs() {
	fmt.Println("Starting protocol-based config sorting...")

	// Setup paths for new directory structure in current directory
	protocolDir := "Splitted-By-Protocol"

	// Create directory if it doesn't exist
	if err := os.MkdirAll(protocolDir, 0755); err != nil {
		fmt.Printf("Error creating protocol directory: %v\n", err)
		return
	}

	// Define file paths
	files := map[string]string{
		"vmess":  filepath.Join(protocolDir, "vmess.txt"),
		"vless":  filepath.Join(protocolDir, "vless.txt"),
		"trojan": filepath.Join(protocolDir, "trojan.txt"),
		"ss":     filepath.Join(protocolDir, "ss.txt"),
		"ssr":    filepath.Join(protocolDir, "ssr.txt"),
		"hy2":    filepath.Join(protocolDir, "hy2.txt"),
		"tuic":   filepath.Join(protocolDir, "tuic.txt"),
		"warp":   filepath.Join(protocolDir, "warp.txt"),
	}

	// Clear existing files
	for protocol, filePath := range files {
		if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
			fmt.Printf("Error clearing %s file: %v\n", protocol, err)
			return
		}
	}

	// Process local file
	fmt.Println("Processing local AllConfigsSub.txt...")
	localFile, err := os.Open("AllConfigsSub.txt")
	if err != nil {
		fmt.Printf("Error opening local config file: %v\n", err)
		return
	}
	defer localFile.Close()

	// Process the file line by line for memory efficiency
	scanner := bufio.NewScanner(localFile)

	// Collect configs by protocol
	protocolConfigs := make(map[string][]string)
	// Track duplicates for each protocol
	seenConfigs := make(map[string]map[string]bool)
	for protocol := range files {
		seenConfigs[protocol] = make(map[string]bool)
	}

	vmessFile, err := os.OpenFile(files["vmess"], os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening vmess file: %v\n", err)
		return
	}
	defer vmessFile.Close()

	vmessWriter := bufio.NewWriter(vmessFile)
	defer vmessWriter.Flush()

	configCount := make(map[string]int)
	duplicateCount := make(map[string]int)

	// 【新增】定义一个切片，用来单独收集去重后的所有唯一节点，供 Clash 转换使用
	var allUniqueConfigs []string

	fmt.Println("Processing configurations...")
	unknownCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check protocol and categorize
		matched := false
		for protocol := range files {
			prefix := protocol + "://"
			if protocol == "warp" {
				prefix = "warp://"
			}

			if strings.HasPrefix(line, prefix) {
				matched = true
				if seenConfigs[protocol][line] {
					duplicateCount[protocol]++
					break
				}
				seenConfigs[protocol][line] = true
				configCount[protocol]++

				// 【新增】将去重后的唯一节点塞入 Clash 收集器，完全不干扰后面的原生写入逻辑
				allUniqueConfigs = append(allUniqueConfigs, line)

				if protocol == "vmess" {
					if _, err := vmessWriter.WriteString(line + "\n"); err != nil {
						fmt.Printf("Error writing vmess config: %v\n", err)
						return
					}
				} else {
					protocolConfigs[protocol] = append(protocolConfigs[protocol], line)
				}
				break
			}
		}

		if !matched {
			unknownCount++
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	// Flush vmess writer
	vmessWriter.Flush()

	// 原有逻辑：将其他协议以 Base64 编码形式写入文件（完全保留，确保原有订阅不崩溃）
	for protocol, configs := range protocolConfigs {
		if len(configs) == 0 {
			continue
		}

		// Join all configs for this protocol
		content := strings.Join(configs, "\n")

		// Base64 encode the content
		encodedContent := base64.StdEncoding.EncodeToString([]byte(content))

		// Write to file
		if err := os.WriteFile(files[protocol], []byte(encodedContent), 0644); err != nil {
			fmt.Printf("Error writing %s file: %v\n", protocol, err)
			return
		}
	}

	// 【核心追加】在原有文件全部安全写完后，独立触发 Clash YAML 的生成
	fmt.Println("Generating Clash YAML file...")
	generateClashYaml(allUniqueConfigs)

	// Sort protocols for consistent output
	protocols := []string{"vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp"}

	// Print summary
	fmt.Println("\nProtocol sorting completed!")
	fmt.Println("Configuration counts (after removing duplicates):")
	for _, protocol := range protocols {
		count := configCount[protocol]
		fmt.Printf("  %s: %d configs\n", protocol, count)
	}
	if unknownCount > 0 {
		fmt.Printf("  Unknown/Other: %d configs\n", unknownCount)
	}

	total := 0
	totalDuplicates := 0
	for _, count := range configCount {
		total += count
	}
	for _, count := range duplicateCount {
		totalDuplicates += count
	}
	fmt.Printf("  Total unique identified: %d configs\n", total)

	if totalDuplicates > 0 {
		fmt.Println("\nDuplicates removed during sorting:")
		for _, protocol := range protocols {
			count := duplicateCount[protocol]
			if count > 0 {
				fmt.Printf("  %s: %d duplicates\n", protocol, count)
			}
		}
		fmt.Printf("  Total duplicates removed: %d\n", totalDuplicates)
		fmt.Printf("  Main file total lines: %d\n", total+totalDuplicates+unknownCount)
	}
}

// 【新增辅助函数】解析并构建 Clash 专用的 YAML 配置文件
func generateClashYaml(configs []string) {
	var proxyLines []string
	var proxyNames []string

	vmessIdx, vlessIdx, trojanIdx, ssIdx, hy2Idx := 1, 1, 1, 1, 1

	for _, link := range configs {
		if strings.HasPrefix(link, "vmess://") {
			b64Data := strings.TrimPrefix(link, "vmess://")
			if rem := len(b64Data) % 4; rem > 0 {
				b64Data += strings.Repeat("=", 4-rem)
			}
			decoded, err := base64.StdEncoding.DecodeString(b64Data)
			if err != nil {
				continue
			}
			var data map[string]interface{}
			if err := json.Unmarshal(decoded, &data); err != nil {
				continue
			}

			name := fmt.Sprintf("Vmess_%d", vmessIdx)
			if ps, ok := data["ps"].(string); ok && ps != "" {
				name = sanitizeName(ps)
			} else {
				vmessIdx++
			}

			server, _ := data["add"].(string)
			portStr := fmt.Sprintf("%v", data["port"])
			uuid, _ := data["id"].(string)
			cipher := "auto"
			if c, ok := data["scy"].(string); ok && c != "" {
				cipher = c
			}

			if server == "" || portStr == "" || uuid == "" {
				continue
			}

			line := fmt.Sprintf("  - name: \"%s\"\n    type: vmess\n    server: %s\n    port: %s\n    uuid: %s\n    alterId: 0\n    cipher: %s\n    udp: true", name, server, portStr, uuid, cipher)
			
			if net, ok := data["net"].(string); ok && net == "ws" {
				line += "\n    network: ws"
				if path, ok := data["path"].(string); ok && path != "" {
					line += fmt.Sprintf("\n    ws-opts:\n      path: %s", path)
					if host, ok := data["host"].(string); ok && host != "" {
						line += fmt.Sprintf("\n      headers:\n        Host: %s", host)
					}
				}
			}
			if tls, ok := data["tls"].(string); ok && (tls == "tls" || tls == "1") {
				line += "\n    tls: true"
			}

			proxyLines = append(proxyLines, line)
			proxyNames = append(proxyNames, name)

		} else if strings.HasPrefix(link, "vless://") || strings.HasPrefix(link, "trojan://") || strings.HasPrefix(link, "ss://") || strings.HasPrefix(link, "hy2://") {
			u, err := url.Parse(link)
			if err != nil {
				continue
			}

			var name string
			remark := u.Fragment
			if remark != "" {
				name = sanitizeName(remark)
			}

			if strings.HasPrefix(link, "vless://") {
				if name == "" {
					name = fmt.Sprintf("Vless_%d", vlessIdx)
					vlessIdx++
				}
				uuid := u.User.Username()
				host, port, _ := strings.Cut(u.Host, ":")
				if host == "" || port == "" {
					continue
				}
				line := fmt.Sprintf("  - name: \"%s\"\n    type: vless\n    server: %s\n    port: %s\n    uuid: %s\n    cipher: auto\n    udp: true", name, host, port, uuid)
				
				q := u.Query()
				if q.Get("security") == "tls" || q.Get("security") == "reality" {
					line += "\n    tls: true"
					if q.Get("sni") != "" {
						line += fmt.Sprintf("\n    servername: %s", q.Get("sni"))
					}
					if q.Get("security") == "reality" {
						line += fmt.Sprintf("\n    client-fingerprint: %s", q.Get("fp"))
						line += fmt.Sprintf("\n    reality-opts:\n      public-key: %s", q.Get("pbk"))
						if q.Get("sid") != "" {
							line += fmt.Sprintf("\n      short-id: %s", q.Get("sid"))
						}
					}
				}
				if q.Get("type") == "ws" {
					line += "\n    network: ws"
					if q.Get("path") != "" {
						line += fmt.Sprintf("\n    ws-opts:\n      path: %s", q.Get("path"))
						if q.Get("host") != "" {
							line += fmt.Sprintf("\n      headers:\n        Host: %s", q.Get("host"))
						}
					}
				}
				proxyLines = append(proxyLines, line)
				proxyNames = append(proxyNames, name)

			} else if strings.HasPrefix(link, "trojan://") {
				if name == "" {
					name = fmt.Sprintf("Trojan_%d", trojanIdx)
					trojanIdx++
				}
				password := u.User.Username()
				host, port, _ := strings.Cut(u.Host, ":")
				if host == "" || port == "" {
					continue
				}
				line := fmt.Sprintf("  - name: \"%s\"\n    type: trojan\n    server: %s\n    port: %s\n    password: %s\n    udp: true", name, host, port, password)
				q := u.Query()
				if q.Get("sni") != "" {
					line += fmt.Sprintf("\n    servername: %s", q.Get("sni"))
				}
				proxyLines = append(proxyLines, line)
				proxyNames = append(proxyNames, name)

			} else if strings.HasPrefix(link, "hy2://") {
				if name == "" {
					name = fmt.Sprintf("Hysteria2_%d", hy2Idx)
					hy2Idx++
				}
				auth := u.User.Username()
				host, port, _ := strings.Cut(u.Host, ":")
				if host == "" || port == "" {
					continue
				}
				line := fmt.Sprintf("  - name: \"%s\"\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s", name, host, port, auth)
				q := u.Query()
				if q.Get("sni") != "" {
					line += fmt.Sprintf("\n    sni: %s", q.Get("sni"))
				}
				proxyLines = append(proxyLines, line)
				proxyNames = append(proxyNames, name)

			} else if strings.HasPrefix(link, "ss://") {
				if name == "" {
					name = fmt.Sprintf("Shadowsocks_%d", ssIdx)
					ssIdx++
				}
				
				var cipher, password, host, port string
				if strings.Contains(u.Host, "@") {
					host, port, _ = strings.Cut(u.Host, ":")
					cipher = u.User.Username()
					password, _ = u.User.Password()
				} else {
					userB64 := u.User.Username()
					if rem := len(userB64) % 4; rem > 0 {
						userB64 += strings.Repeat("=", 4-rem)
					}
					dec, err := base64.StdEncoding.DecodeString(userB64)
					if err == nil {
						c, p, found := strings.Cut(string(dec), ":")
						if found {
							cipher = c
							password = p
						}
					}
					host, port, _ = strings.Cut(u.Host, ":")
				}

				if cipher == "" || password == "" || host == "" || port == "" {
					continue
				}

				line := fmt.Sprintf("  - name: \"%s\"\n    type: ss\n    server: %s\n    port: %s\n    cipher: %s\n    password: %s\n    udp: true", name, host, port, cipher, password)
				proxyLines = append(proxyLines, line)
				proxyNames = append(proxyNames, name)
			}
		}
	}

	if len(proxyLines) == 0 {
		fmt.Println("No valid proxies parsed for Clash.")
		return
	}

	var sb strings.Builder
	sb.WriteString("port: 7890\nsocks-port: 7891\nmixed-port: 7892\nallow-lan: true\nmode: rule\nlog-level: info\nexternal-controller: 127.0.0.1:9090\n\nproxies:\n")
	for _, pl := range proxyLines {
		sb.WriteString(pl + "\n")
	}

	sb.WriteString("\nproxy-groups:\n")
	sb.WriteString("  - name: 🚀 节点选择\n    type: select\n    proxies:\n      - ⚡ 自动测速\n")
	for _, name := range proxyNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	sb.WriteString("  - name: ⚡ 自动测速\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n")
	for _, name := range proxyNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	sb.WriteString("\nrules:\n  - DOMAIN-SUFFIX,google.com,🚀 节点选择\n  - DOMAIN-KEYWORD,github,🚀 节点选择\n  - MATCH,🚀 节点选择\n")

	err := os.WriteFile("clash.yaml", []byte(sb.String()), 0644)
	if err != nil {
		fmt.Printf("Error writing clash.yaml: %v\n", err)
	} else {
		fmt.Println("Successfully generated clash.yaml with", len(proxyLines), "proxies!")
	}
}

func sanitizeName(name string) string {
	name, _ = url.QueryUnescape(name)
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "'", "")
	name = strings.ReplaceAll(name, ":", "-")
	return strings.TrimSpace(name)
}
