package main

import (
	"bufio"
	"context"
	"crypto/tls" // 引入tls包用于处理证书验证
	"fmt"
	"io" // **修复: 添加缺失的 "io" 包**
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime" // 引入runtime包用于检测操作系统
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3" // 引入进度条库
	"golang.org/x/net/proxy"
)

const (
	defaultTestURL         = "http://myip.ipip.net" // 默认测试目标改为IP查询网站
	defaultProxiesFile     = "proxies.txt"
	defaultUsernamesFile   = "username.txt"
	defaultPasswordsFile   = "password.txt"
	defaultCredentialsFile = "proxy_credentials.txt"
	outputDir              = "proxy_output" // 目录名改为更通用
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

// main function to drive the program
func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println(`
 _____ _                  _                           
|   __|_|___ ___ ___ ___ _| |___ ___ ___ ___ ___ ___ 
|__   | |   | -_|  _| -_| . | . |  _| -_| . | -_|_ -|
|_____|_|_|_|___|_| |___|___|___|_| |___|  _|___|___|
                                      |_|          
	`)
	fmt.Println("================== Universal Proxy Scanner v5.3 (IP Verification Edition) ==================")

	// **核心改动 1: 程序启动时获取真实IP**
	fmt.Println("正在获取您的真实公网IP地址...")
	realIP, err := getPublicIP(defaultTestURL)
	if err != nil {
		fmt.Printf("❌ 无法获取真实IP地址，IP验证将不可用: %v\n", err)
		realIP = "UNKNOWN"
	} else {
		fmt.Printf("✅ 您的真实IP地址是: %s\n", realIP)
	}


	testURL := selectTestTarget(reader)

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
		case 1:
			runModeMenu("socks5", testURL, realIP, reader)
		case 2:
			runModeMenu("http", testURL, realIP, reader)
		case 3:
			runModeMenu("https", testURL, realIP, reader)
		case 4:
			testURL = selectTestTarget(reader)
		case 5:
			fmt.Println("正在退出...")
			return
		default:
			fmt.Println("❌ 无效的输入，请重新选择。")
		}
	}
}

// getPublicIP directly connects to a URL and returns the body content (expected to be an IP).
func getPublicIP(testURL string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "curl/7.79.1") // Use a simple UA for IP checks

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	// 提取IP部分，兼容 "当前 IP：1.2.3.4  来自于..." 格式
	ipString := string(body)
	if strings.Contains(ipString, "当前 IP：") {
		parts := strings.Split(ipString, "：")
		if len(parts) > 1 {
			ipParts := strings.Split(parts[1], " ")
			return ipParts[0], nil
		}
	}
	return strings.TrimSpace(ipString), nil
}


// selectTestTarget allows the user to choose a connectivity check URL.
func selectTestTarget(reader *bufio.Reader) string {
	fmt.Println("\n--- 测试目标选择 ---")
	fmt.Println("1: IPIP.net (IP验证, 推荐)")
	fmt.Println("2: Google (全球, http)")
	fmt.Println("3: Xiaomi (中国大陆稳定, http)")
	fmt.Println("4: Baidu (中国大陆稳定, https)")
	fmt.Println("5: 自定义URL")
	fmt.Print("请选择一个测试目标: ")

	choiceStr, _ := reader.ReadString('\n')
	choice, _ := strconv.Atoi(strings.TrimSpace(choiceStr))

	var targetURL string
	switch choice {
	case 1:
		targetURL = "http://myip.ipip.net"
	case 2:
		targetURL = "http://www.google.com/generate_204"
	case 3:
		targetURL = "http://connect.rom.miui.com/generate_204"
	case 4:
		targetURL = "https://www.baidu.com"
	case 5:
		fmt.Print("请输入自定义测试URL: ")
		customURL, _ := reader.ReadString('\n')
		customURL = strings.TrimSpace(customURL)
		if customURL == "" {
			fmt.Println("[!] 输入为空，使用默认目标。")
			targetURL = defaultTestURL
		} else {
			targetURL = customURL
		}
	default:
		fmt.Println("[!] 无效选择，使用默认目标。")
		targetURL = defaultTestURL
	}
	fmt.Printf("[*] 测试目标已设为: %s\n", targetURL)
	return targetURL
}

// runModeMenu shows the secondary menu for scan modes.
func runModeMenu(proxyType, testURL, realIP string, reader *bufio.Reader) {
	if proxyType == "https" && !strings.HasPrefix(testURL, "https://") {
		fmt.Println("\n[警告] 您正在使用HTTP测试目标来测试HTTPS代理。")
		fmt.Println("这很可能会失败，因为许多HTTPS代理仅允许连接到标准HTTPS端口(443)。")
		fmt.Println("建议返回主菜单并选择一个HTTPS测试目标(例如Baidu)。")
	}

	for {
		fmt.Printf("\n--- [%s 模式] ---", strings.ToUpper(proxyType))
		if runtime.GOOS == "windows" {
			fmt.Println("\n1: -> 测试单个代理")
			fmt.Println("2: >> 从文件批量扫描")
			fmt.Println("3: <- 返回上级菜单")
		} else {
			fmt.Printf("\n1: 🧪 测试单个代理")
			fmt.Printf("\n2: 🚀 从文件批量扫描")
			fmt.Printf("\n3: ↩️  返回上级菜单\n")
		}
		fmt.Print("请选择操作: ")

		modeStr, _ := reader.ReadString('\n')
		mode, _ := strconv.Atoi(strings.TrimSpace(modeStr))

		switch mode {
		case 1:
			handleSingleProxyTest(proxyType, testURL, realIP, reader)
		case 2:
			handleBatchScan(proxyType, testURL, realIP, reader)
		case 3:
			return // Return to the main menu
		default:
			fmt.Println("❌ 无效的输入，请重新选择。")
		}
	}
}

// handleSingleProxyTest handles the logic for testing a single proxy.
func handleSingleProxyTest(proxyType, testURL, realIP string, reader *bufio.Reader) {
	fmt.Printf("输入代理地址 (格式: %s://user:pass@host:port 或 ip:port): ", proxyType)
	proxyInput, _ := reader.ReadString('\n')
	proxyInput = strings.TrimSpace(proxyInput)

	if proxyInput == "" {
		return
	}

	fmt.Print("输入超时时间 (秒, 默认10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeout <= 0 {
		timeout = 10
	}

	var proxyAddr string
	var auth *proxy.Auth

	if strings.HasPrefix(proxyInput, proxyType+"://") {
		parsedURL, err := url.Parse(proxyInput)
		if err != nil {
			fmt.Printf("❌ 无效的URI格式: %v\n", err)
			return
		}
		proxyAddr = parsedURL.Host
		if parsedURL.User != nil {
			user := parsedURL.User.Username()
			pass, _ := parsedURL.User.Password()
			auth = &proxy.Auth{User: user, Password: pass}
			fmt.Printf("从URI中解析到凭据: user=%s\n", user)
		}
	} else {
		proxyAddr = proxyInput
		fmt.Print("输入用户名 (留空则无): ")
		user, _ := reader.ReadString('\n')
		user = strings.TrimSpace(user)

		fmt.Print("输入密码 (留空则无): ")
		pass, _ := reader.ReadString('\n')
		pass = strings.TrimSpace(pass)

		if user != "" || pass != "" {
			auth = &proxy.Auth{User: user, Password: pass}
		}
	}

	fmt.Printf("正在测试代理: %s...\n", proxyAddr)
	if success, err := checkConnection(proxyType, testURL, proxyAddr, auth, time.Duration(timeout)*time.Second, realIP); success {
		fmt.Println("✅ 代理可用")
	} else {
		if err != nil {
			fmt.Printf("❌ 代理不可用。原因: %v\n", err)
		} else {
			fmt.Println("❌ 代理不可用或已超时。")
		}
	}
}

// handleBatchScan handles the logic for batch scanning from files.
func handleBatchScan(proxyType, testURL, realIP string, reader *bufio.Reader) {
	fmt.Printf("输入代理列表文件名 (默认: %s): ", defaultProxiesFile)
	proxyFilename, _ := reader.ReadString('\n')
	proxyFilename = strings.TrimSpace(proxyFilename)
	if proxyFilename == "" {
		proxyFilename = defaultProxiesFile
	}

	fmt.Print("选择凭据模式 (1:无凭据, 2:独立凭据文件, 3:弱密码文件): ")
	authModeStr, _ := reader.ReadString('\n')
	authMode, _ := strconv.Atoi(strings.TrimSpace(authModeStr))

	usernamesFile := defaultUsernamesFile
	passwordsFile := defaultPasswordsFile
	credentialsFile := defaultCredentialsFile
	var err error

	if authMode == 2 {
		fmt.Printf("输入用户文件名 (默认: %s): ", defaultUsernamesFile)
		usernamesFile, _ = reader.ReadString('\n')
		usernamesFile = strings.TrimSpace(usernamesFile)
		if usernamesFile == "" {
			usernamesFile = defaultUsernamesFile
		}
		fmt.Printf("输入密码文件名 (默认: %s): ", defaultPasswordsFile)
		passwordsFile, _ = reader.ReadString('\n')
		passwordsFile = strings.TrimSpace(passwordsFile)
		if passwordsFile == "" {
			passwordsFile = defaultPasswordsFile
		}
	} else if authMode == 3 {
		fmt.Printf("输入弱密码文件名 (默认: %s): ", defaultCredentialsFile)
		credentialsFile, _ = reader.ReadString('\n')
		credentialsFile = strings.TrimSpace(credentialsFile)
		if credentialsFile == "" {
			credentialsFile = defaultCredentialsFile
		}
	}

	fmt.Print("输入并发数 (默认50): ")
	concurrencyStr, _ := reader.ReadString('\n')
	concurrency, err := strconv.Atoi(strings.TrimSpace(concurrencyStr))
	if err != nil || concurrency <= 0 {
		concurrency = 50
	}

	fmt.Print("输入超时时间 (秒, 默认10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeout, err := strconv.Atoi(strings.TrimSpace(timeoutStr))
	if err != nil || timeout <= 0 {
		timeout = 10
	}

	batchScan(proxyType, testURL, realIP, proxyFilename, concurrency, time.Duration(timeout)*time.Second, authMode, usernamesFile, passwordsFile, credentialsFile)
}

// batchScan scans proxies from a file concurrently.
func batchScan(proxyType, testURL, realIP, proxyFilename string, concurrency int, timeout time.Duration, authMode int, usernamesFile, passwordsFile, credentialsFile string) {
	proxiesFile, err := os.Open(proxyFilename)
	if err != nil {
		fmt.Printf("❌ 无法读取代理文件 '%s': %v\n", proxyFilename, err)
		return
	}
	defer proxiesFile.Close()

	fileInfo, err := proxiesFile.Stat()
	if err != nil {
		fmt.Printf("❌ 无法获取文件信息 '%s': %v\n", proxyFilename, err)
		return
	}
	bar := progressbar.NewOptions64(fileInfo.Size(),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("[cyan][Scanning...][reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]█[reset]",
			SaucerHead:    "[yellow]▶[reset]",
			SaucerPadding: " ",
			BarStart:      "|",
			BarEnd:        "|",
		}))
	if runtime.GOOS == "windows" {
		bar = progressbar.NewOptions64(fileInfo.Size(),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionEnableColorCodes(false),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionSetDescription("[Scanning...]"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}))
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("❌ 无法创建输出目录 '%s': %v\n", outputDir, err)
		return
	}

	currentTime := time.Now().Format("2006-01-02_15-04-05")
	outputFilename := fmt.Sprintf("%s_%s.txt", proxyType, currentTime)
	outputPath := filepath.Join(outputDir, outputFilename)

	workingFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("❌ 无法创建有效代理文件 '%s': %v\n", outputPath, err)
		return
	}
	defer workingFile.Close()

	var wg sync.WaitGroup
	proxyChan := make(chan string, concurrency)
	resultsChan := make(chan string, concurrency)
	var foundCount int64 = 0

	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range resultsChan {
			foundCount++
			workingFile.WriteString(result + "\n")
		}
	}()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for proxyAddr := range proxyChan {
				if workingProxyURI, _ := testProxy(proxyType, testURL, realIP, proxyAddr, authMode, timeout, usernamesFile, passwordsFile, credentialsFile); workingProxyURI != "" {
					resultsChan <- workingProxyURI
				}
			}
		}()
	}

	reader := bufio.NewReader(proxiesFile)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line != "" {
			proxyChan <- line
		}
		bar.Add(len(line) + 1)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("\n读取文件时出错: %v\n", err)
			break
		}
	}

	close(proxyChan)
	wg.Wait()
	close(resultsChan)
	resultWg.Wait()

	bar.Finish()

	fmt.Println()
	if runtime.GOOS == "windows" {
		fmt.Printf("\n[+] 批量扫描完成，共发现 %d 个可用代理。\n", foundCount)
		fmt.Printf("[+] 结果已保存至: %s\n", outputPath)
	} else {
		fmt.Printf("\n🎉 批量扫描完成，共发现 %d 个可用代理。\n", foundCount)
		fmt.Printf("💾 结果已保存至: %s\n", outputPath)
	}
}

// testProxy performs the actual test and returns the full working proxy URI string and an error.
func testProxy(proxyType, testURL, realIP, proxyAddr string, authMode int, timeout time.Duration, usernamesFile, passwordsFile, credentialsFile string) (string, error) {
	var auth *proxy.Auth

	checkAndFormat := func(auth *proxy.Auth) (string, error) {
		success, err := checkConnection(proxyType, testURL, proxyAddr, auth, timeout, realIP)
		if success {
			if auth != nil && auth.User != "" {
				return fmt.Sprintf("%s://%s:%s@%s", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr), nil
			}
			return fmt.Sprintf("%s://%s", proxyType, proxyAddr), nil
		}
		return "", err
	}

	switch authMode {
	case 1: // No auth
		return checkAndFormat(nil)
	case 2: // Separate username/password files
		usernames, errUser := readLines(usernamesFile)
		passwords, errPass := readLines(passwordsFile)
		if errUser != nil || errPass != nil {
			return "", nil // Don't return error for missing credential files
		}
		for _, user := range usernames {
			for _, pass := range passwords {
				auth = &proxy.Auth{User: user, Password: pass}
				if result, _ := checkAndFormat(auth); result != "" {
					return result, nil
				}
			}
		}
	case 3: // Combined credentials file
		creds, err := readLines(credentialsFile)
		if err != nil {
			return "", nil // Don't return error for missing credential files
		}
		for _, cred := range creds {
			parts := strings.SplitN(cred, ":", 2)
			if len(parts) == 2 {
				user, pass := parts[0], parts[1]
				auth = &proxy.Auth{User: user, Password: pass}
				if result, _ := checkAndFormat(auth); result != "" {
					return result, nil
				}
			}
		}
	}
	return "", nil
}


// checkConnection attempts to connect to the test URL through the proxy and returns a boolean and an error.
func checkConnection(proxyType, testURL, proxyAddr string, auth *proxy.Auth, timeout time.Duration, realIP string) (bool, error) {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 100,
	}

	if proxyType == "http" || proxyType == "https" {
		proxyURL, err := buildProxyURL(proxyType, proxyAddr, auth)
		if err != nil {
			return false, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		if proxyType == "https" {
			transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr != proxyAddr {
					addr = proxyAddr
				}
				dialer := &net.Dialer{Timeout: timeout}
				conn, err := tls.DialWithDialer(dialer, network, addr, &tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return nil, err
				}
				return conn, nil
			}
		}
	} else { // "socks5"
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		})
		if err != nil {
			return false, err
		}
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// **核心改动 2: IP验证逻辑**
	// 如果测试目标是IP查询网站，则进行IP对比
	if strings.Contains(testURL, "ipip.net") {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false, fmt.Errorf("无法读取响应体")
		}
		proxyIP := string(body)
		if strings.Contains(proxyIP, "当前 IP：") {
			parts := strings.Split(proxyIP, "：")
			if len(parts) > 1 {
				ipParts := strings.Split(parts[1], " ")
				proxyIP = ipParts[0]
			}
		}
		proxyIP = strings.TrimSpace(proxyIP)

		if realIP == "UNKNOWN" || proxyIP == "" {
			return false, fmt.Errorf("无法获取IP进行验证")
		}
		if proxyIP == realIP {
			return false, fmt.Errorf("IP地址未改变 (透明代理)")
		}
		// IP不同，验证通过
		return true, nil
	}

	// 对于非IP验证的URL，沿用之前的状态码检查
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, fmt.Errorf("bad status: %s", resp.Status)
}

// buildProxyURL is a helper function to construct the proxy URL string.
func buildProxyURL(scheme, proxyAddr string, auth *proxy.Auth) (*url.URL, error) {
	var proxyURLString string
	if auth != nil && auth.User != "" {
		proxyURLString = fmt.Sprintf("%s://%s:%s@%s", scheme, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)
	} else {
		proxyURLString = fmt.Sprintf("%s://%s", scheme, proxyAddr)
	}
	return url.Parse(proxyURLString)
}

// readLines reads a file and returns its lines as a slice of strings.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
