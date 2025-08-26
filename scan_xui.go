package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime" // 引入 runtime 包以调用GC
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall" // 引入 syscall 以便重新启动
	"time"
)

// XUI_SIGNATURES 存放了用于识别 x-ui 面板的特征字符串
var XUI_SIGNATURES = []string{
	`src="/assets/js/model/xray.js`,
	`href="/assets/ant-design-vue`,
	`location.href = basePath + 'panel/'`,
	`location.href = basePath + 'xui/'`,
	`-Login</title>`,
	`<title>登录</title>`,
	`<div id="app">`,
}

const (
	swapFilePath    = "/tmp/scanner_swapfile"
	childProcFlag   = "--run-as-child"
	swapSizeInBytes = 2 * 1024 * 1024 * 1024 // 2GB
)

// bufferPool 使用 sync.Pool 来复用读取响应体时所需的内存缓冲区。
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4*1024)
		return &b
	},
}

// AppConfig 结构体用于存储应用程序的配置
type AppConfig struct {
	FilePath       string
	OutputFilePath string
	Concurrency    int
	Timeout        time.Duration
}

// main 是程序的入口函数
func main() {
	if len(os.Args) > 1 && os.Args[1] == childProcFlag {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	} else {
		relaunchAsLowPriority()
	}

	log.SetFlags(0)

	if runtime.GOOS == "linux" {
		if os.Geteuid() == 0 {
			log.Println("[系统] 以 root 权限运行，尝试进行系统级优化...")
			setupSwap()
			adjustOOMScore()
		} else {
			log.Println("[系统] 警告: 未以 root 权限运行，无法进行 Swap 创建和 OOM 分数调整。")
		}
	}

	config, err := getUserConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	var workerWg, writerWg sync.WaitGroup
	jobs := make(chan string, config.Concurrency)
	results := make(chan string, config.Concurrency)
	var processedCounter, dispatchedCounter, successCounter int64

	outputFile, err := os.OpenFile(config.OutputFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("无法打开结果文件: %v", err)
	}
	defer outputFile.Close()

	writerWg.Add(1)
	go fileWriter(&writerWg, results, outputFile, &successCounter)

	log.Printf("启动 %d 个扫描协程...", config.Concurrency)
	for i := 1; i <= config.Concurrency; i++ {
		workerWg.Add(1)
		go worker(&workerWg, jobs, results, config.Timeout, &processedCounter)
	}

	go func() {
		defer close(jobs)
		inputFile, err := os.Open(config.FilePath)
		if err != nil {
			log.Printf("\n错误: 无法打开文件 '%s': %v", config.FilePath, err)
			return
		}
		defer inputFile.Close()

		scanner := bufio.NewScanner(inputFile)
		const maxCapacity = 1024 * 1024
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() {
			line := scanner.Text()
			target := parseLine(line)
			if target != "" {
				jobs <- target
				atomic.AddInt64(&dispatchedCounter, 1)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Printf("\n[文件读取错误]: %v. 请检查文件格式或权限。", err)
		}
	}()

	log.Println("扫描已开始...")
	done := make(chan struct{})
	go func() {
		workerWg.Wait()
		close(results)
		close(done)
	}()

	progressTicker := time.NewTicker(time.Second)
	defer progressTicker.Stop()
	gcTicker := time.NewTicker(30 * time.Second) // 新增：30秒的GC定时器
	defer gcTicker.Stop()

	for {
		select {
		case <-done:
			writerWg.Wait()
			fmt.Println()
			processed := atomic.LoadInt64(&processedCounter)
			dispatched := atomic.LoadInt64(&dispatchedCounter)
			success := atomic.LoadInt64(&successCounter)
			log.Printf("扫描完成。从文件解析并分发 %d 个目标，实际处理 %d 个，成功 %d 个。", dispatched, processed, success)
			if dispatched > 0 {
				log.Printf("成功的结果已保存到 %s", config.OutputFilePath)
			} else {
				log.Println("警告：未从输入文件中解析出任何有效目标。")
			}
			return
		case <-progressTicker.C:
			fmt.Printf("\r进度: 已处理 %d / 已分发 %d | 成功: %d",
				atomic.LoadInt64(&processedCounter),
				atomic.LoadInt64(&dispatchedCounter),
				atomic.LoadInt64(&successCounter))
		case <-gcTicker.C:
			runtime.GC() // 定时强制垃圾回收
		}
	}
}

// --- 系统优化函数 ---

func relaunchAsLowPriority() {
	if runtime.GOOS != "linux" {
		return
	}
	nicePath, err1 := exec.LookPath("nice")
	ionicePath, err2 := exec.LookPath("ionice")

	if err1 != nil || err2 != nil {
		log.Println("[系统] 未找到 nice 或 ionice 命令，无法以低优先级启动。将以正常优先级运行。")
		return
	}

	log.Println("[系统] 检测到初次启动，将以低CPU和IO优先级并优化内存设置后重新启动自身...")
	
	env := os.Environ()
	env = append(env, "GOGC=50")
	log.Println("[系统] GOGC=50 已设置。")

	if totalMem, err := getMemoryTotal(); err == nil {
		limit := int(float64(totalMem) * 0.7)
		env = append(env, fmt.Sprintf("GOMEMLIMIT=%dB", limit))
		log.Printf("[系统] GOMEMLIMIT=%dMB 已设置。", limit/(1024*1024))
	} else {
		log.Printf("[系统] 无法获取总内存，跳过 GOMEMLIMIT 设置: %v", err)
	}

	args := append([]string{childProcFlag}, os.Args[1:]...)
	cmd := exec.Command(ionicePath, "-c", "3", nicePath, "-n", "19", os.Args[0])
	cmd.Args = append(cmd.Args, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = env

	err := syscall.Exec(cmd.Path, cmd.Args, cmd.Env)
	if err != nil {
		log.Fatalf("[系统] 重新启动失败: %v", err)
	}
}

func getMemoryTotal() (uint64, error) {
	if runtime.GOOS != "linux" {
		return 0, fmt.Errorf("该功能仅支持Linux")
	}
	// 修正：使用 os.ReadFile 替代 ioutil.ReadFile
	memInfo, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(memInfo), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return val * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("在 /proc/meminfo 中未找到 MemTotal")
}

func setupSwap() {
	// 修正：使用 os.ReadFile 替代 ioutil.ReadFile
	out, err := os.ReadFile("/proc/swaps")
	if err != nil {
		log.Printf("[系统] 无法检查 swap: %v", err)
		return
	}
	if len(strings.Split(string(out), "\n")) > 2 {
		log.Println("[系统] 检测到已存在的 Swap，跳过创建。")
		return
	}

	log.Printf("[系统] 未检测到 Swap，正在创建 2GB 临时 Swap 文件于 %s...", swapFilePath)

	if err := exec.Command("fallocate", "-l", strconv.FormatInt(swapSizeInBytes, 10), swapFilePath).Run(); err != nil {
		log.Printf("[系统] fallocate 创建 swap 文件失败: %v。尝试使用 dd...", err)
		if err := exec.Command("dd", "if=/dev/zero", "of="+swapFilePath, "bs=1M", "count=2048").Run(); err != nil {
			log.Printf("[系统] dd 创建 swap 文件也失败了: %v。无法创建 Swap。", err)
			return
		}
	}

	if err := os.Chmod(swapFilePath, 0600); err != nil { log.Printf("[系统] 设置 swap 文件权限失败: %v", err); return }
	if err := exec.Command("mkswap", swapFilePath).Run(); err != nil { log.Printf("[系统] mkswap 格式化失败: %v", err); return }
	if err := exec.Command("swapon", swapFilePath).Run(); err != nil { log.Printf("[系统] swapon 启用失败: %v", err); return }

	log.Println("[系统] 临时 Swap 文件创建并启用成功。")

	go func() {
		<-time.After(time.Second)
		defer func() {
			log.Println("[系统] 程序退出，正在清理临时 Swap 文件...")
			exec.Command("swapoff", swapFilePath).Run()
			os.Remove(swapFilePath)
			log.Println("[系统] 清理完成。")
		}()
	}()
}

func adjustOOMScore() {
	score := "-500"
	// 修正：使用 os.WriteFile 替代 ioutil.WriteFile
	err := os.WriteFile("/proc/self/oom_score_adj", []byte(score), 0644)
	if err != nil {
		log.Printf("[系统] 调整 OOM Score 失败: %v", err)
	} else {
		log.Printf("[系统] OOM Score 调整成功，降低被杀死的概率。")
	}
}

func fileWriter(wg *sync.WaitGroup, results <-chan string, file *os.File, counter *int64) {
	defer wg.Done()
	for result := range results {
		atomic.AddInt64(counter, 1)
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Printf("\n[文件写入错误]: %v", err)
		}
	}
}

func parseLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") { return "" }
	if strings.Contains(line, "Host:") && strings.Contains(line, "Ports:") {
		fields := strings.Fields(line)
		var ip, port string
		for i, field := range fields {
			if field == "Host:" && i+1 < len(fields) { ip = fields[i+1] }
			if field == "Ports:" && i+1 < len(fields) { port = strings.Split(fields[i+1], "/")[0] }
		}
		if ip != "" && port != "" { return fmt.Sprintf("%s:%s", ip, port) }
	}
	if strings.Contains(line, ":") { return line }
	return ""
}

func getUserConfig() (AppConfig, error) {
	config := AppConfig{}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入包含目标列表的文件路径 (ip:port 或 masscan 格式): ")
	filePath, _ := reader.ReadString('\n')
	config.FilePath = strings.TrimSpace(filePath)
	fmt.Print("请输入结果保存文件名 (默认 results.txt): ")
	outputFilePath, _ := reader.ReadString('\n')
	outputFilePath = strings.TrimSpace(outputFilePath)
	if outputFilePath == "" { config.OutputFilePath = "results.txt" } else { config.OutputFilePath = outputFilePath }
	fmt.Print("请输入并发协程数 (默认 30): ")
	concurrencyStr, _ := reader.ReadString('\n')
	concurrencyStr = strings.TrimSpace(concurrencyStr)
	if concurrencyStr == "" {
		config.Concurrency = 30
	} else {
		concurrency, err := strconv.Atoi(concurrencyStr)
		if err != nil || concurrency <= 0 { return config, fmt.Errorf("无效的并发数: %s", concurrencyStr) }
		config.Concurrency = concurrency
	}
	fmt.Print("请输入网络超时时间（秒，默认 10）: ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	if timeoutStr == "" {
		config.Timeout = 10 * time.Second
	} else {
		timeoutSec, err := strconv.Atoi(timeoutStr)
		if err != nil || timeoutSec <= 0 { return config, fmt.Errorf("无效的超时时间: %s", timeoutStr) }
		config.Timeout = time.Duration(timeoutSec) * time.Second
	}
	fmt.Println("------------------------------------")
	return config, nil
}

func worker(wg *sync.WaitGroup, jobs <-chan string, results chan<- string, timeout time.Duration, counter *int64) {
	defer wg.Done()
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: -1,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	for target := range jobs {
		checkTarget(target, client, results)
		atomic.AddInt64(counter, 1)
	}
}

func checkTarget(target string, client *http.Client, results chan<- string) {
	if target == "" { return }
	if checkProtocol("https", target, client, results) { return }
	checkProtocol("http", target, client, results)
}

func checkProtocol(protocol, target string, client *http.Client, results chan<- string) bool {
	url := fmt.Sprintf("%s://%s", protocol, target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return false }
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil { return false }
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		bufPtr := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(bufPtr)
		buf := *bufPtr
		n, err := io.ReadFull(io.LimitReader(resp.Body, int64(len(buf))), buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF { return false }
		if n == 0 { return false }
		content := string(buf[:n])
		for _, signature := range XUI_SIGNATURES {
			if strings.Contains(content, signature) {
				fmt.Printf("\r[成功] 发现x-ui面板: %s (特征: %s)\n", url, signature)
				results <- target
				return true
			}
		}
	}
	return false
}
