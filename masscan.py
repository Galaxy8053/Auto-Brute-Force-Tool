# -*- coding: utf-8 -*-

import os

def convert_masscan_grepable_output():
    """
    一个交互式脚本，用于将 Masscan 的 Grepable 格式 (-oG) TXT 输出文件转换为 'ip:port' 格式。
    此版本经过修正，可以处理以 'Timestamp:' 开头的行。
    """
    print("--- Masscan 结果转换脚本 (Grepable 格式专用) ---")
    print("本脚本将 'Host: 1.2.3.4 () Ports: 80/open/tcp,...' 或")
    print("'Timestamp: ... Host: 1.2.3.4 () Ports: 80/open/tcp,...' 格式的行转换为 '1.2.3.4:80'")

    # 1. 获取用户输入的源文件路径
    while True:
        input_file_path = input("\n请输入 Masscan 结果文件名 (例如 results.txt): ").strip()
        if os.path.exists(input_file_path):
            break
        else:
            print(f"错误: 文件 '{input_file_path}' 不存在，请检查文件名和路径。")

    # 2. 获取用户指定的输出文件路径
    default_output_name = f"converted_{os.path.basename(input_file_path)}"
    output_file_path = input(f"请输入转换后保存的文件名 (默认: {default_output_name}): ").strip()
    if not output_file_path:
        output_file_path = default_output_name

    # 3. 开始转换
    converted_count = 0
    total_lines = 0
    processed_hosts = 0

    print(f"\n正在读取文件: {input_file_path}")
    print(f"准备写入文件: {output_file_path}")

    try:
        with open(input_file_path, 'r', encoding='utf-8', errors='ignore') as infile, \
             open(output_file_path, 'w', encoding='utf-8') as outfile:

            for line in infile:
                total_lines += 1
                line = line.strip()

                # 【关键修正】: 检查行中是否 *包含* 关键信息，而不是检查行首。
                # 忽略注释行 (#) 和不包含主机与端口信息的行。
                if line.startswith("#") or "Host:" not in line or "Ports:" not in line:
                    continue
                
                processed_hosts += 1
                try:
                    # 使用默认 split() 可以同时处理空格和制表符
                    parts = line.split()
                    
                    # 【关键修正】: 动态查找 "Host:" 的位置来定位 IP 地址，而不是使用固定索引。
                    host_keyword_index = parts.index("Host:")
                    ip_addr = parts[host_keyword_index + 1]

                    # 找到 'Ports:' 关键字的索引位置
                    ports_keyword_index = parts.index("Ports:")
                    
                    # 'Ports:' 之后的所有内容都属于端口信息
                    port_section_str = " ".join(parts[ports_keyword_index + 1:])
                    port_list = port_section_str.split(',')

                    for port_info in port_list:
                        port_info = port_info.strip() # 去除前后空格
                        if not port_info:
                            continue
                        
                        # 端口号是 '1080/open/tcp/...' 中的第一部分
                        port = port_info.split('/')[0]
                        
                        # 验证端口确实是数字
                        if port.isdigit():
                            formatted_line = f"{ip_addr}:{port}\n"
                            outfile.write(formatted_line)
                            converted_count += 1
                        else:
                             print(f"警告: 在行中未能解析出有效端口: {line}")

                except (ValueError, IndexError):
                    # 如果某行格式不完整 (例如缺少 'Ports:' 关键字)，则跳过
                    print(f"警告: 跳过格式异常的行: {line}")
                    continue
    
    except Exception as e:
        print(f"\n处理文件时发生未知错误: {e}")
        return

    print("\n--- 转换完成 ---")
    print(f"总共读取行数: {total_lines}")
    print(f"已处理主机行: {processed_hosts}")
    print(f"成功转换 IP:Port 记录: {converted_count}")
    if converted_count > 0:
        print(f"✅ 结果已保存到文件: {output_file_path}")
    else:
        print(f"⚠️ 转换完成，但没有找到任何有效数据。请检查输入文件 '{input_file_path}' 的格式。")


if __name__ == "__main__":
    convert_masscan_grepable_output()
