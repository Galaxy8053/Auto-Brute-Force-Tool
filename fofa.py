import os
import json
import logging
import base64
import requests
import urllib.parse
import traceback
from datetime import datetime, timedelta
from functools import wraps
# v20.x 版本的正确导入方式
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters
)

# --- 禁用SSL证书验证警告 ---
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 基础配置 ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- 全局变量和常量 ---
CONFIG_FILE = 'config.json'

# Conversation states
GET_KEY = range(1)
ASK_DATE_RANGE = range(1, 2)
GET_PROXY = range(2,3)

# --- 权限与配置管理 ---
def load_config():
    """加载配置文件，如果不存在则创建"""
    if not os.path.exists(CONFIG_FILE):
        encoded_super_admin_id = 'NzY5NzIzNTM1OA=='
        SUPER_ADMIN_ID = int(base64.b64decode(encoded_super_admin_id).decode('utf-8'))
        config = {"apis": [], "admins": [SUPER_ADMIN_ID], "super_admin": SUPER_ADMIN_ID, "proxy": ""}
        save_config(config)
        return config
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        if 'proxy' not in config: # 兼容旧版config
            config['proxy'] = ""
            save_config(config)
        return config

def save_config(config):
    """保存配置到文件"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

CONFIG = load_config()

def restricted(func):
    """装饰器：限制只有管理员才能访问"""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            await update.message.reply_text("抱歉，您没有权限执行此命令。")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

def super_admin_restricted(func):
    """装饰器：限制只有超级管理员才能访问"""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id != CONFIG.get('super_admin'):
            await update.message.reply_text("抱歉，只有超级管理员才能执行此命令。")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped


# --- Fofa 核心逻辑 (增加调试信息) ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36"
}
TIMEOUT = 30

def get_proxies():
    """获取代理配置"""
    if CONFIG.get("proxy"):
        return { "http": CONFIG["proxy"], "https": CONFIG["proxy"] }
    return None

def _make_request(url: str) -> (dict, str, dict):
    """
    统一的网络请求函数，返回(成功数据, 错误信息, 调试信息)
    """
    proxies = get_proxies()
    debug_info = {
        "URL": url,
        "Headers": HEADERS,
        "Proxies": proxies,
        "Response_Status": None,
        "Response_Headers": None,
        "Response_Body": None,
        "Exception": None
    }
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=proxies)
        debug_info["Response_Status"] = res.status_code
        debug_info["Response_Headers"] = dict(res.headers)
        
        try:
            data = res.json()
            debug_info["Response_Body"] = data
            if data.get("error"):
                return None, data.get("errmsg", "Fofa返回了一个未知错误。"), debug_info
            return data, None, debug_info
        except json.JSONDecodeError:
            debug_info["Response_Body"] = res.text
            err_msg = f"服务器返回的不是有效的JSON格式。状态码: {res.status_code}。内容预览: {res.text[:200]}"
            debug_info["Exception"] = err_msg
            return None, err_msg, debug_info

    except requests.exceptions.RequestException as e:
        err_msg = f"网络请求失败: {type(e).__name__} - {e}"
        debug_info["Exception"] = traceback.format_exc()
        return None, err_msg, debug_info

def verify_fofa_api(key):
    url = f"https://fofa.info/api/v1/info/my?key={key}"
    data, error, _ = _make_request(url)
    return data is not None, data or {"errmsg": error}

def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}"
    return _make_request(url)


# --- Bot 命令处理函数 ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text('欢迎使用 Fofa 查询 Bot！\n使用 /help 查看所有可用命令。')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = """
    *Fofa查询机器人指令手册*

    `/kkfofa <查询语句>` - 核心查询命令。
    `/debug <查询语句>` - [管理员] 以调试模式执行查询，返回详细网络信息。

    *API与代理管理 (管理员)*:
    `/addapi` - 添加一个新的Fofa API Key。
    `/root` - 查看/管理已存储的API Key和代理。
    `/setproxy` - 设置或更新网络代理。
    `/delproxy` - 删除当前的网络代理。

    *权限管理 (超级管理员)*:
    `/vip <add/remove> <用户ID>` - 添加或移除管理员。
    
    *通用*:
    `/help` - 显示此帮助信息。
    `/cancel` - 取消当前操作。
    """
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@restricted
async def add_api_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("好的，请直接发送您的 Fofa API Key。")
    return GET_KEY

async def get_key(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    key = update.message.text
    await update.message.reply_text("正在验证API密钥，请稍候...")
    is_valid, data = verify_fofa_api(key)
    if is_valid:
        if key not in CONFIG['apis']:
            CONFIG['apis'].append(key)
            save_config(CONFIG)
            await update.message.reply_text(f"成功：API密钥已验证并成功添加！\n你好, {data.get('username', 'user')}!")
        else:
            await update.message.reply_text(f"提示：这个API Key已经存在。\n你好, {data.get('username', 'user')}!")
    else:
        await update.message.reply_text(f"错误：API验证失败！原因: {data.get('errmsg', '未知错误')}")
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text('操作已取消。')
    context.user_data.clear()
    return ConversationHandler.END

@restricted
async def manage_api(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if not args:
        api_message = "当前没有存储任何API密钥。"
        if CONFIG['apis']:
            api_message = "已存储的API Key列表 (为保护隐私，仅显示部分):\n"
            for i, key in enumerate(CONFIG['apis']):
                masked_key = key[:4] + '...' + key[-4:]
                api_message += f"{i+1}. `{masked_key}`\n"
            api_message += "\n使用 `/root remove <编号>` 来删除API Key。"
        
        proxy_message = f"当前代理: `{CONFIG.get('proxy') or '未设置'}`"
        
        await update.message.reply_text(f"{api_message}\n\n{proxy_message}", parse_mode=ParseMode.MARKDOWN)

    elif args[0].lower() == 'remove' and len(args) > 1:
        try:
            index = int(args[1]) - 1
            if 0 <= index < len(CONFIG['apis']):
                CONFIG['apis'].pop(index)
                save_config(CONFIG)
                await update.message.reply_text(f"成功移除了编号为 {index+1} 的API Key。")
            else:
                await update.message.reply_text("错误：编号无效。")
        except ValueError:
            await update.message.reply_text("错误：请输入有效的编号。")
    else:
        await update.message.reply_text("用法: `/root` 或 `/root remove <编号>`")

@restricted
async def set_proxy_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("请输入您的代理地址，格式为 `http://user:pass@host:port` 或 `socks5://host:port`\n例如: `http://127.0.0.1:7890`")
    return GET_PROXY

async def get_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    proxy_url = update.message.text
    CONFIG['proxy'] = proxy_url
    save_config(CONFIG)
    await update.message.reply_text(f"代理已更新为: `{proxy_url}`\n正在尝试通过新代理验证第一个API Key...", parse_mode=ParseMode.MARKDOWN)
    
    if CONFIG['apis']:
        is_valid, data = verify_fofa_api(CONFIG['apis'][0])
        if is_valid:
            await update.message.reply_text("通过代理验证成功！")
        else:
            await update.message.reply_text(f"警告：通过新代理验证失败！原因: {data.get('errmsg', '未知错误')}")
    else:
        await update.message.reply_text("提示：您还未添加任何API Key，无法进行代理验证。")

    return ConversationHandler.END

@restricted
async def del_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    CONFIG['proxy'] = ""
    save_config(CONFIG)
    await update.message.reply_text("代理已成功删除。")

@super_admin_restricted
async def manage_vip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    args = context.args
    if len(args) != 2:
        admin_list = "\n".join([f"- `{admin_id}`" for admin_id in CONFIG['admins']])
        await update.message.reply_text(f"用法: `/vip <add/remove> <user_id>`\n\n*当前管理员列表:*\n{admin_list}", parse_mode=ParseMode.MARKDOWN)
        return
    action, user_id_str = args
    try:
        user_id = int(user_id_str)
        if action.lower() == 'add':
            if user_id not in CONFIG['admins']:
                CONFIG['admins'].append(user_id)
                save_config(CONFIG)
                await update.message.reply_text(f"成功添加管理员: {user_id}")
            else: await update.message.reply_text("该用户已经是管理员。")
        elif action.lower() == 'remove':
            if user_id == CONFIG.get('super_admin'):
                await update.message.reply_text("不能移除超级管理员！")
                return
            if user_id in CONFIG['admins']:
                CONFIG['admins'].remove(user_id)
                save_config(CONFIG)
                await update.message.reply_text(f"成功移除管理员: {user_id}")
            else: await update.message.reply_text("该用户不是管理员。")
        else: await update.message.reply_text("无效的操作。请使用 `add` 或 `remove`。")
    except ValueError:
        await update.message.reply_text("错误: User ID必须是数字。")

@restricted
async def debug_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not CONFIG['apis']:
        await update.message.reply_text("调试失败：请先添加API Key。")
        return
    
    query_text = " ".join(context.args)
    if not query_text:
        await update.message.reply_text("用法: `/debug <查询语句>`")
        return

    key = CONFIG['apis'][0]
    await update.message.reply_text("🔬 *正在以调试模式执行请求...*", parse_mode=ParseMode.MARKDOWN)

    b64_query = base64.b64encode(query_text.encode('utf-8')).decode('utf-8')
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size=1&fields=host"
    
    data, error, debug_info = _make_request(url)

    # 格式化调试信息
    debug_report = f"""
*🕵️‍♂️ Fofa API 调试报告 🕵️‍♂️*

*--- 请求详情 ---*
*URL*: `{debug_info["URL"]}`
*代理*: `{debug_info["Proxies"] or '无'}`

*--- 响应详情 ---*
*状态码*: `{debug_info["Response_Status"]}`
*响应头*: 
`{json.dumps(debug_info["Response_Headers"], indent=2)}`

*--- 结果 ---*
*请求是否成功?* {'✅ 是' if data else '❌ 否'}
*错误信息*: `{error or '无'}`

*--- 底层异常 (如有) ---*
`{debug_info["Exception"] or '无'}`

*--- 原始响应体 (预览) ---*
```
{str(debug_info["Response_Body"])[:1000]}
