import paramiko
import socket
import time
import os

# --- 配置 ---
INPUT_FILE = 'good.txt'
REAL_SERVERS_FILE = 'reallygood.txt'
HONEYPOT_SERVERS_FILE = 'honeypot.txt'
CONNECTION_TIMEOUT = 10  # 连接超时时间（秒）
COMMAND_TIMEOUT = 10     # 命令执行超时时间（秒）
TEST_COMMAND = 'uname -a' # 用于测试的无害命令

# --- 辅助函数 ---

def parse_line(line):
    """解析输入文件中的每一行，提取IP、端口、用户名和密码"""
    try:
        # 分割主体和凭据部分
        main_part, creds_part = line.strip().split(' - ', 1)
        # 分割IP和端口
        ip, port_str = main_part.split(':')
        port = int(port_str)
        # 分割用户名和密码
        user_part, pass_part = creds_part.split(', ', 1)
        user = user_part.split(': ')[1]
        password = pass_part.split(': ')[1]
        return ip, port, user, password
    except (ValueError, IndexError) as e:
        print(f"[-] 无法解析行: '{line.strip()}'. 错误: {e}. 跳过...")
        return None

def is_honeypot(ip, port, user, password):
    """
    尝试连接SSH并执行命令来判断是否为蜜罐。
    返回一个元组: (is_honeypot_bool, reason_string)
    """
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # 记录开始时间
        start_time = time.time()
        
        print(f"[~] 正在尝试连接: {ip}:{port}...")
        ssh_client.connect(
            hostname=ip,
            port=port,
            username=user,
            password=password,
            timeout=CONNECTION_TIMEOUT,
            allow_agent=False,
            look_for_keys=False
        )
        
        # 检查连接时间
        connection_time = time.time() - start_time
        if connection_time > (CONNECTION_TIMEOUT * 0.8): # 如果连接时间接近超时
             return (True, f"连接过于缓慢 ({connection_time:.2f}s)")

        print(f"[+] 成功认证: {ip}:{port}")

        # 尝试执行一个命令
        stdin, stdout, stderr = ssh_client.exec_command(TEST_COMMAND, timeout=COMMAND_TIMEOUT)
        
        # 读取标准输出和标准错误
        exit_status = stdout.channel.recv_exit_status() # 等待命令完成
        output = stdout.read().decode('utf-8', errors='ignore').strip()
        error = stderr.read().decode('utf-8', errors='ignore').strip()

        # 分析结果
        if exit_status != 0:
            return (True, f"命令 '{TEST_COMMAND}' 返回了非零退出状态: {exit_status}. 错误信息: {error}")
        
        if not output:
             return (True, f"命令 '{TEST_COMMAND}' 没有产生任何输出")

        # 简单检查输出是否看起来像一个通用的、硬编码的值
        generic_outputs = ["linux", "generic", "dummy kernel"]
        if any(go in output.lower() for go in generic_outputs) and len(output.split()) < 5:
            return (True, f"命令输出看起来过于通用: '{output}'")
        
        print(f"[✓] 似乎是真实系统: {ip}:{port}")
        return (False, "通过基本交互测试")

    except paramiko.AuthenticationException:
        # 认证失败通常意味着它是一个真实系统，只是凭据错误
        print(f"[-] 认证失败: {ip}:{port}. 可能是一个真实系统，但凭据无效。")
        return (False, "认证失败")
    except paramiko.SSHException as e:
        # 其他SSH协议级别的问题，很可能是蜜罐的特征
        return (True, f"SSH协议错误: {e}")
    except socket.timeout:
        # 连接或执行超时
        return (True, f"操作超时 (超过 {CONNECTION_TIMEOUT}s)")
    except Exception as e:
        # 其他未知异常
        return (True, f"发生未知错误: {e}")
    finally:
        if ssh_client:
            ssh_client.close()


def process_files():
    """
    主处理函数，流式读取文件并分类。
    """
    # 使用集合来自动处理重复项
    real_hosts = set()
    honeypot_hosts = set()

    # 检查输入文件是否存在
    if not os.path.exists(INPUT_FILE):
        print(f"[!] 错误: 输入文件 '{INPUT_FILE}' 不存在。")
        return

    print(f"[*] 开始处理文件: {INPUT_FILE}")

    # 以流式方式打开和读取文件
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parsed_data = parse_line(line)
            if not parsed_data:
                continue
            
            ip, port, user, password = parsed_data
            
            # 格式化主机标识符以用于去重
            host_identifier = f"{ip}:{port} - User: {user}, Password: {password}"
            
            # 如果这个主机之前已经处理过，就跳过
            if host_identifier in real_hosts or host_identifier in honeypot_hosts:
                print(f"[~] 已处理过 '{host_identifier}', 跳过...")
                continue

            is_hp, reason = is_honeypot(ip, port, user, password)
            
            if is_hp:
                print(f"[!] 蜜罐嫌疑: {ip}:{port}. 原因: {reason}")
                honeypot_hosts.add(host_identifier)
            else:
                real_hosts.add(host_identifier)

    # 将结果写入文件
    print("\n[*] 处理完成。正在将结果写入文件...")
    
    with open(REAL_SERVERS_FILE, 'w', encoding='utf-8') as f:
        for host in sorted(list(real_hosts)):
            f.write(host + '\n')
    print(f"[+] {len(real_hosts)} 个非蜜罐服务器已保存到 {REAL_SERVERS_FILE}")

    with open(HONEYPOT_SERVERS_FILE, 'w', encoding='utf-8') as f:
        for host in sorted(list(honeypot_hosts)):
            f.write(host + '\n')
    print(f"[+] {len(honeypot_hosts)} 个疑似蜜罐服务器已保存到 {HONEYPOT_SERVERS_FILE}")


if __name__ == '__main__':
    process_files()
