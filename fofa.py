import os
import json
import logging
import base64
import requests
import urllib.parse
import traceback
import sys
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
# 过滤掉 PTBUserWarning
logging.getLogger("telegram.ext").addFilter(lambda record: "PTBUserWarning" not in record.getMessage())
logger = logging.getLogger(__name__)

# --- 全局变量和常量 ---
CONFIG_FILE = 'config.json'

# Conversation states
GET_KEY = range(1)
ASK_DATE_RANGE = range(1, 2)
GET_PROXY = range(2,3)
REMOVE_API_PROMPT = range(3,4)

# --- 权限与配置管理 ---
def load_config():
    """加载配置文件，如果不存在则创建"""
    if not os.path.exists(CONFIG_FILE):
        encoded_super_admin_id = 'NzY5NzIzNTM1OA=='
        if not is_base64(encoded_super_admin_id):
            logger.error("致命错误：SUPER_ADMIN_ID 不是有效的Base64编码！为了您的安全，脚本已停止运行。")
            sys.exit(1)
        SUPER_ADMIN_ID = int(base64.b64decode(encoded_super_admin_id).decode('utf-8'))
        config = {
            "apis": [], 
            "admins": [SUPER_ADMIN_ID], 
            "super_admin": SUPER_ADMIN_ID, 
            "proxy": "",
            "dedup_mode": "exact"
        }
        save_config(config)
        return config
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        if 'proxy' not in config: config['proxy'] = ""
        if 'dedup_mode' not in config: config['dedup_mode'] = "exact"
        save_config(config)
        return config

def save_config(config):
    """保存配置到文件"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def is_base64(s):
    """检查字符串是否为有效的Base64编码"""
    try:
        if len(s.strip()) % 4 != 0: return False
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

CONFIG = load_config()

def restricted(func):
    """装饰器：限制只有管理员才能访问"""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            await update.message.reply_text("⛔️ 抱歉，您没有权限执行此命令。")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

def super_admin_restricted(func):
    """装饰器：限制只有超级管理员才能访问"""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id != CONFIG.get('super_admin'):
            await update.message.reply_text("⛔️ 抱歉，只有超级管理员才能执行此命令。")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped


# --- Fofa 核心逻辑 ---
HEADERS = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36" }
TIMEOUT = 30

def get_proxies():
    """获取代理配置"""
    if CONFIG.get("proxy"):
        return { "http": CONFIG["proxy"], "https": CONFIG["proxy"] }
    return None

def _make_request(url: str) -> (dict, str, dict):
    proxies = get_proxies()
    debug_info = { "URL": url, "Headers": HEADERS, "Proxies": proxies, "Response_Status": None, "Response_Headers": None, "Response_Body": None, "Exception": None }
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=proxies)
        debug_info["Response_Status"] = res.status_code
        debug_info["Response_Headers"] = dict(res.headers)
        try:
            data = res.json()
            debug_info["Response_Body"] = data
            if data.get("error"): return None, data.get("errmsg", "Fofa返回未知错误。"), debug_info
            return data, None, debug_info
        except json.JSONDecodeError:
            debug_info["Response_Body"] = res.text
            err_msg = f"服务器返回非JSON格式。状态码: {res.status_code}。内容: {res.text[:200]}"
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

def fetch_host_details(key, host):
    url = f"https://fofa.info/api/v1/host/{host}?key={key}"
    data, error, _ = _make_request(url)
    return data, error

# --- Bot 命令处理函数 ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        '👋 欢迎使用 Fofa 查询机器人！\n\n'
        '我是一个功能强大的Fofa助手，可以帮您进行资产搜索和情报查询。\n\n'
        '👇 点击输入框旁的 **菜单** 或输入 `/` 来查看所有可用命令。',
        parse_mode=ParseMode.MARKDOWN
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = """
    *📖 Fofa查询机器人指令手册*\n
    *🔍 核心功能*
    `/kkfofa <查询语句>` - 执行资产搜索。
    `/host <IP/Domain>` - 查询单个主机详细情报。\n
    *⚙️ 管理与设置 (仅管理员)*
    `/settings` - 打开交互式设置菜单。\n
    *💡 重要提示*
    如果查询包含 `||` 符号, 请选中查询内容后使用快捷键 `Ctrl+Shift+M` (或用```包裹) 以代码模式发送。\n
    *❓ 通用*
    `/help` - 显示此帮助信息。
    `/cancel` - 取消当前操作。
    """
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@restricted
async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    is_super = update.effective_user.id == CONFIG.get('super_admin')
    keyboard = [
        [InlineKeyboardButton("🔑 API 管理", callback_data='settings_api')],
        [InlineKeyboardButton("🌐 代理设置", callback_data='settings_proxy')],
        [InlineKeyboardButton("🗑️ 去重模式", callback_data='settings_dedup')],
    ]
    if is_super:
        keyboard.append([InlineKeyboardButton("🛡️ 权限管理", callback_data='settings_vip')])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("⚙️ *设置菜单*\n\n请选择您要管理的项目:", reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

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
            await update.message.reply_text(f"✅ 成功：API密钥已验证并成功添加！\n你好, {data.get('username', 'user')}!")
        else:
            await update.message.reply_text(f"ℹ️ 提示：这个API Key已经存在。\n你好, {data.get('username', 'user')}!")
    else:
        await update.message.reply_text(f"❌ 错误：API验证失败！原因: {data.get('errmsg', '未知错误')}")
    return ConversationHandler.END

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text('操作已取消。')
    context.user_data.clear()
    return ConversationHandler.END

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
        if is_valid: await update.message.reply_text("✅ 通过代理验证成功！")
        else: await update.message.reply_text(f"⚠️ 警告：通过新代理验证失败！原因: {data.get('errmsg', '未知错误')}")
    else: await update.message.reply_text("ℹ️ 提示：您还未添加任何API Key，无法进行代理验证。")
    return ConversationHandler.END

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
    url = f"[https://fofa.info/api/v1/search/all?key=](https://fofa.info/api/v1/search/all?key=){key}&qbase64={b64_query}&size=1&fields=host"
    data, error, debug_info = _make_request(url)
    headers_str = json.dumps(debug_info.get("Response_Headers"), indent=2, ensure_ascii=False)
    success_str = '✅ 是' if data else '❌ 否'
    exception_str = debug_info.get("Exception") or '无'
    body_str = str(debug_info.get("Response_Body"))[:1000]
    debug_report = (f"*🕵️‍♂️ Fofa API 调试报告 🕵️‍♂️*\n\n" f"*--- 请求详情 ---*\n" f"*URL*: `{debug_info['URL']}`\n" f"*代理*: `{debug_info['Proxies'] or '无'}`\n\n" f"*--- 响应详情 ---*\n" f"*状态码*: `{debug_info['Response_Status']}`\n" f"*响应头*:\n`{headers_str}`\n\n" f"*--- 结果 ---*\n" f"*请求是否成功?* {success_str}\n" f"*错误信息*: `{error or '无'}`\n\n" f"*--- 底层异常 (如有) ---*\n" f"`{exception_str}`\n\n" f"*--- 原始响应体 (预览) ---*\n" f"```\n{body_str}\n```")
    await update.message.reply_text(debug_report, parse_mode=ParseMode.MARKDOWN)

@restricted
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not CONFIG['apis']:
        await update.message.reply_text("❌ 错误：请先使用 `/settings` 添加至少一个Fofa API。")
        return ConversationHandler.END
    api_key = CONFIG['apis'][0] 
    query_text = " ".join(context.args)
    if not query_text:
        await update.message.reply_text("请输入查询语句。\n用法: `/kkfofa <查询语句>`")
        return ConversationHandler.END
    job_data = {'base_query': query_text, 'chat_id': update.effective_chat.id, 'api_key': api_key}
    if "daterange:" in query_text.lower():
        try:
            parts = query_text.lower().split("daterange:")
            job_data['base_query'] = parts[0].strip()
            date_parts = parts[1].strip().split("to")
            job_data['start_date'] = datetime.strptime(date_parts[0].strip(), "%Y-%m-%d")
            job_data['end_date'] = datetime.strptime(date_parts[1].strip(), "%Y-%m-%d")
            context.application.job_queue.run_once(run_date_range_query, 0, data=job_data, name=f"date_range_{job_data['chat_id']}")
            await update.message.reply_text(f"⏳ 已收到按天下载任务！\n*查询*: `{job_data['base_query']}`\n*时间*: `{job_data['start_date'].date()}` 到 `{job_data['end_date'].date()}`\n任务已在后台开始。", parse_mode=ParseMode.MARKDOWN)
        except (ValueError, IndexError):
            await update.message.reply_text("❌ 错误：日期范围格式不正确。\n请使用: `daterange:YYYY-MM-DD to YYYY-MM-DD`")
        return ConversationHandler.END
    msg = await update.message.reply_text("🔄 正在查询数据总数，请稍候...")
    data, error, _ = fetch_fofa_data(api_key, query_text, page_size=1)
    if error:
        await msg.edit_text(f"❌ 查询出错: {error}")
        return ConversationHandler.END
    total_size = data.get('size', 0)
    if total_size == 0:
        await msg.edit_text("🤷‍♀️ 未找到相关结果。")
        return ConversationHandler.END
    context.user_data['query'] = query_text
    context.user_data['total_size'] = total_size
    if total_size <= 10000:
        await msg.edit_text(f"✅ 查询到 {total_size} 条结果，符合免费额度，正在为您下载...")
        job_data['total_size'] = total_size
        context.application.job_queue.run_once(run_full_download_query, 0, data=job_data, name=f"full_download_{job_data['chat_id']}")
        return ConversationHandler.END
    else:
        keyboard = [[InlineKeyboardButton("🗓️ 按天下载 (穷人模式)", callback_data='mode_daily')],[InlineKeyboardButton("💎 全部下载 (消耗F点)", callback_data='mode_full')],[InlineKeyboardButton("👀 仅预览前20条", callback_data='mode_preview')],[InlineKeyboardButton("❌ 取消", callback_data='mode_cancel')],]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await msg.edit_text(f"📊 查询到 {total_size} 条结果，已超出免费额度(10000条)。\n请选择下载模式:", reply_markup=reply_markup)
        return 1

async def query_mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    await query.answer()
    mode = query.data
    base_query = context.user_data.get('query')
    total_size = context.user_data.get('total_size')
    chat_id = query.message.chat_id
    api_key = CONFIG['apis'][0]
    if mode == 'mode_daily':
        await query.edit_message_text(text="您选择了按天下载模式。\n🗓️ 请输入起止日期 (格式: `YYYY-MM-DD to YYYY-MM-DD`)")
        return ASK_DATE_RANGE
    elif mode == 'mode_full':
        await query.edit_message_text(text=f"⏳ 已开始全量下载任务 ({total_size}条)，请注意这可能会消耗您的F点或会员权益。")
        job_data = {'base_query': base_query, 'total_size': total_size, 'chat_id': chat_id, 'api_key': api_key}
        context.application.job_queue.run_once(run_full_download_query, 0, data=job_data, name=f"full_download_{chat_id}")
        return ConversationHandler.END
    elif mode == 'mode_preview':
        data, error, _ = fetch_fofa_data(api_key, base_query, page_size=20)
        if error:
            await query.edit_message_text(f"❌ 预览失败: {error}")
            return ConversationHandler.END
        results = data.get('results', [])
        message = f"*查询语句*: `{base_query}`\n*总数*: `{total_size}`\n\n*👀 前20条预览结果*:\n"
        if results: message += "\n".join([f"`{res}`" for res in results])
        else: message += "没有预览结果。"
        await query.edit_message_text(message, parse_mode=ParseMode.MARKDOWN)
        return ConversationHandler.END
    elif mode == 'mode_cancel':
        await query.edit_message_text(text="操作已取消。")
        context.user_data.clear()
        return ConversationHandler.END
    return ConversationHandler.END

async def get_date_range_from_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    date_range_str = update.message.text
    base_query = context.user_data.get('query')
    chat_id = update.effective_chat.id
    api_key = CONFIG['apis'][0]
    try:
        date_parts = date_range_str.lower().split("to")
        start_date = datetime.strptime(date_parts[0].strip(), "%Y-%m-%d")
        end_date = datetime.strptime(date_parts[1].strip(), "%Y-%m-%d")
        await update.message.reply_text(f"✅ 日期范围确认！任务已在后台开始。\n*查询*: `{base_query}`\n*时间*: `{start_date.date()}` 到 `{end_date.date()}`", parse_mode=ParseMode.MARKDOWN)
        job_data = {'chat_id': chat_id, 'base_query': base_query, 'start_date': start_date, 'end_date': end_date, 'api_key': api_key}
        context.application.job_queue.run_once(run_date_range_query, 0, data=job_data, name=f"date_range_{chat_id}")
        context.user_data.clear()
        return ConversationHandler.END
    except (ValueError, IndexError):
        await update.message.reply_text("❌ 格式错误，请重新输入 (格式: `YYYY-MM-DD to YYYY-MM-DD`)\n或使用 /cancel 取消。")
        return ASK_DATE_RANGE

@restricted
async def host_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not CONFIG['apis']:
        await update.message.reply_text("❌ 错误：请先添加Fofa API。")
        return
    if len(context.args) != 1:
        await update.message.reply_text("用法: `/host <IP/Domain>`")
        return
    
    target_host = context.args[0]
    api_key = CONFIG['apis'][0]
    msg = await update.message.reply_text(f"ℹ️ 正在查询主机 {target_host} 的详细信息...")

    data, error = fetch_host_details(api_key, target_host)
    if error:
        await msg.edit_text(f"❌ 查询失败: {error}")
        return

    info = (
        f"🎯 *主机情报: `{data.get('host', 'N/A')}`*\n\n"
        f"🗺️ *地理位置*: {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})\n"
        f"🏢 *组织*: {data.get('org', 'N/A')} (ASN: {data.get('asn', 'N/A')})\n"
        f"🕒 *更新时间*: {data.get('update_time', 'N/A')}\n\n"
        f"📡 *开放端口*: `{', '.join(map(str, data.get('ports', [])))}`\n\n"
        f"📦 *识别产品*:\n"
    )
    
    products = data.get('products', [])
    if products:
        for p in products:
            info += f"  - `{p.get('product', '未知产品')}` (分类: {p.get('category', 'N/A')})\n"
    else:
        info += "  - 未识别到任何产品。\n"
    
    await msg.edit_text(info, parse_mode=ParseMode.MARKDOWN)

@restricted
async def settings_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    parts = query.data.split('_')
    menu = parts[1]

    if menu == 'main':
        await query.message.delete()
        await settings_command(update, context)
        return

    if menu == 'api':
        api_message = "当前没有存储任何API密钥。"
        if CONFIG['apis']:
            api_message = "已存储的API Key列表 (为保护隐私，仅显示部分):\n"
            for i, key in enumerate(CONFIG['apis']):
                masked_key = key[:4] + '...' + key[-4:]
                api_message += f"{i+1}. `{masked_key}`\n"
        keyboard = [[InlineKeyboardButton("➕ 添加新API", callback_data='action_api_add')],[InlineKeyboardButton("➖ 删除API", callback_data='action_api_remove_prompt')],[InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')],]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"🔑 *API 管理*\n\n{api_message}", reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

    elif menu == 'proxy':
        proxy_message = f"当前代理: `{CONFIG.get('proxy') or '未设置'}`"
        keyboard = [[InlineKeyboardButton("✏️ 设置/更新代理", callback_data='action_proxy_set')],[InlineKeyboardButton("🗑️ 删除代理", callback_data='action_proxy_delete')],[InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')],]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"🌐 *代理设置*\n\n{proxy_message}", reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

    elif menu == 'dedup':
        current_mode = CONFIG.get('dedup_mode', 'exact')
        mode_text = "智能去重 (忽略协议头)" if current_mode == 'smart' else "精确去重 (完整匹配)"
        keyboard = [[InlineKeyboardButton("🤓 智能去重", callback_data='action_dedup_set_smart')],[InlineKeyboardButton("🎯 精确去重", callback_data='action_dedup_set_exact')],[InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')],]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"🗑️ *去重模式*\n\n当前模式: *{mode_text}*", reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)
    
    elif menu == 'vip':
        admin_list = "\n".join([f"- `{admin_id}`" for admin_id in CONFIG['admins']])
        message = f"🛡️ *权限管理*\n\n当前管理员列表:\n{admin_list}\n\n请直接使用命令 `/vip <add/remove> <用户ID>` 进行操作。"
        keyboard = [[InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(message, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

@restricted
async def settings_action_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """处理设置菜单中的具体操作"""
    query = update.callback_query
    await query.answer()
    action = query.data.replace('action_', '')

    if action == 'api_add':
        await query.message.reply_text("请使用 `/addapi` 命令开始添加流程。")
        await query.message.delete()
    
    elif action == 'api_remove_prompt':
        await query.message.reply_text("请使用 `/settings remove <编号>`。")
        await query.message.delete()

    elif action == 'proxy_set':
        await query.message.reply_text("请使用 `/setproxy` 命令开始设置流程。")
        await query.message.delete()

    elif action == 'proxy_delete':
        CONFIG['proxy'] = ""
        save_config(CONFIG)
        await query.edit_message_text("✅ 代理已成功删除。", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')]]))
    
    elif action.startswith('dedup_set_'):
        new_mode = action.split('_')[-1]
        CONFIG['dedup_mode'] = new_mode
        save_config(CONFIG)
        mode_text = "智能去重 (忽略协议头)" if new_mode == 'smart' else "精确去重 (完整匹配)"
        await query.edit_message_text(f"✅ 去重模式已更新为: *{mode_text}*", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')]]), parse_mode=ParseMode.MARKDOWN)

# --- 终极修正：恢复被错误删除的 manage_vip 函数 ---
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
                await update.message.reply_text(f"✅ 成功添加管理员: {user_id}")
            else: await update.message.reply_text("ℹ️ 该用户已经是管理员。")
        elif action.lower() == 'remove':
            if user_id == CONFIG.get('super_admin'):
                await update.message.reply_text("❌ 不能移除超级管理员！")
                return
            if user_id in CONFIG['admins']:
                CONFIG['admins'].remove(user_id)
                save_config(CONFIG)
                await update.message.reply_text(f"✅ 成功移除管理员: {user_id}")
            else: await update.message.reply_text("🤷‍♀️ 该用户不是管理员。")
        else: await update.message.reply_text("❌ 无效的操作。请使用 `add` 或 `remove`。")
    except ValueError: await update.message.reply_text("❌ 错误: User ID必须是数字。")


# --- 辅助与后台任务 ---
def normalize_for_dedup(result_str: str) -> str:
    """为智能去重模式标准化字符串"""
    if result_str.startswith("http://"): return result_str[7:]
    if result_str.startswith("https://"): return result_str[8:]
    return result_str

async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data
    chat_id, query_text, total_size, api_key = job_data['chat_id'], job_data['base_query'], job_data['total_size'], job_data['api_key']
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"fofa_full_{timestamp}.txt"
    page_size = 10000 
    pages_to_fetch = (total_size + page_size - 1) // page_size
    unique_results = set()
    progress_message = await context.bot.send_message(chat_id, "⏳ 开始全量下载任务...")
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        for page in range(1, pages_to_fetch + 1):
            progress = page / pages_to_fetch
            bar = '█' * int(progress * 15) + '─' * (15 - int(progress * 15))
            try: await progress_message.edit_text(f"下载进度: [{bar}] {page}/{pages_to_fetch} ({progress:.0%})")
            except Exception: pass
            data, error, _ = fetch_fofa_data(api_key, query_text, page=page, page_size=page_size)
            if error:
                await context.bot.send_message(chat_id, f"❌ 下载第 {page} 页时出错: {error}")
                continue
            results = data.get('results', [])
            for res in results:
                key_to_check = normalize_for_dedup(res) if CONFIG['dedup_mode'] == 'smart' else res
                if key_to_check not in unique_results:
                    f.write(f"{res}\n")
                    unique_results.add(key_to_check)
    
    await progress_message.edit_text(f"✅ 全量数据下载完成！\n总计 {total_size} 条，去重后剩余 {len(unique_results)} 条。\n正在发送文件...")
    try:
        with open(output_filename, 'rb') as f:
            await context.bot.send_document(chat_id, document=f)
    except Exception as e: await context.bot.send_message(chat_id, f"❌ 发送文件失败: {e}")
    finally:
        if os.path.exists(output_filename): os.remove(output_filename)

async def run_date_range_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data
    chat_id, base_query, start_date, end_date, api_key = job_data['chat_id'], job_data['base_query'], job_data['start_date'], job_data['end_date'], job_data['api_key']
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"fofa_daily_{timestamp}.txt"
    unique_results = set()
    total_days = (end_date - start_date).days + 1
    current_day_num = 0
    progress_message = await context.bot.send_message(chat_id, "⏳ 开始按天下载任务...")

    with open(output_filename, 'w', encoding='utf-8') as f:
        current_date = start_date
        while current_date <= end_date:
            current_day_num += 1
            date_str = current_date.strftime("%Y-%m-%d")
            progress = current_day_num / total_days
            bar = '█' * int(progress * 15) + '─' * (15 - int(progress * 15))
            try: await progress_message.edit_text(f"下载进度: [{bar}] {current_day_num}/{total_days} ({date_str})")
            except Exception: pass
            daily_query = f'({base_query}) && after="{date_str}" && before="{date_str}"'
            page = 1
            while True:
                data, error, _ = fetch_fofa_data(api_key, daily_query, page=page, page_size=10000)
                if error:
                    await context.bot.send_message(chat_id, f"❌ 下载 `{date_str}` 数据时出错: {error}", parse_mode=ParseMode.MARKDOWN)
                    break 
                results = data.get('results', [])
                if not results: break
                for res in results:
                    key_to_check = normalize_for_dedup(res) if CONFIG['dedup_mode'] == 'smart' else res
                    if key_to_check not in unique_results:
                        f.write(f"{res}\n")
                        unique_results.add(key_to_check)
                if len(results) < 10000: break 
                page += 1
            current_date += timedelta(days=1)
    
    await progress_message.edit_text(f"✅ 所有日期下载完成！\n去重后共找到 {len(unique_results)} 条数据。\n正在发送结果文件...")
    try:
        with open(output_filename, 'rb') as f:
            await context.bot.send_document(chat_id, document=f)
    except Exception as e: await context.bot.send_message(chat_id, f"❌ 发送文件失败: {e}")
    finally:
        if os.path.exists(output_filename): os.remove(output_filename)

async def post_init(application: Application):
    """在Bot启动后设置命令菜单"""
    commands = [
        BotCommand("kkfofa", "🔍 资产搜索"),
        BotCommand("host", "ℹ️ 主机详情"),
        BotCommand("settings", "⚙️ 设置 (管理员)"),
        BotCommand("help", "❓ 获取帮助"),
        BotCommand("cancel", "❌ 取消当前操作"),
    ]
    await application.bot.set_my_commands(commands)
    logger.info("✅ 已成功设置命令菜单！")

def main() -> None:
    """启动Bot"""
    encoded_token = 'ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw=='
    
    if not is_base64(encoded_token):
        logger.error("\n\n" + "="*60 + "\n    !!! 致命安全错误：TELEGRAM_BOT_TOKEN 未使用Base64加密 !!!\n" + "    为了保护您的机器人不被盗用，脚本已停止运行。\n" + "    请对您的Token字符串进行Base64编码后，再填入脚本。\n" + "="*60 + "\n")
        sys.exit(1)

    TELEGRAM_BOT_TOKEN = base64.b64decode(encoded_token).decode('utf-8')
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    add_api_conv = ConversationHandler(
        entry_points=[CommandHandler('addapi', add_api_start), CallbackQueryHandler(add_api_start, pattern='^action_api_add$')],
        states={ GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)] },
        fallbacks=[CommandHandler('cancel', cancel)],
    )
    set_proxy_conv = ConversationHandler(
        entry_points=[CommandHandler('setproxy', set_proxy_start), CallbackQueryHandler(set_proxy_start, pattern='^action_proxy_set$')],
        states={ GET_PROXY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_proxy)] },
        fallbacks=[CommandHandler('cancel', cancel)],
    )
    kkfofa_conv = ConversationHandler(
        entry_points=[CommandHandler('kkfofa', kkfofa_command)],
        states={
            1: [CallbackQueryHandler(query_mode_callback)],
            ASK_DATE_RANGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_date_range_from_message)]
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        allow_reentry=True
    )
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(add_api_conv)
    application.add_handler(set_proxy_conv)
    application.add_handler(CommandHandler("vip", manage_vip))
    application.add_handler(kkfofa_conv)
    application.add_handler(CommandHandler("debug", debug_command))
    application.add_handler(CommandHandler("host", host_command))
    application.add_handler(CommandHandler("settings", settings_command))
    application.add_handler(CommandHandler("root", settings_command))
    application.add_handler(CallbackQueryHandler(settings_callback_query, pattern='^settings_'))
    application.add_handler(CallbackQueryHandler(settings_action_callback_query, pattern='^action_'))

    logger.info("🚀 机器人已启动，开始轮询...")
    application.run_polling()

if __name__ == '__main__':
    main()

