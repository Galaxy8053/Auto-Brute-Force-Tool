import os
import json
import logging
import base64
import requests
import asyncio
from datetime import datetime, timedelta
from functools import wraps
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
logging.getLogger("telegram.ext").addFilter(lambda record: "PTBUserWarning" not in record.getMessage())
logger = logging.getLogger(__name__)

# --- 全局变量和常量 ---
CONFIG_FILE = 'config.json'
(
    STATE_KKFOFA_MODE,
    STATE_KKFOFA_DATE,
    STATE_SETTINGS_MAIN,
    STATE_SETTINGS_ACTION,
    STATE_GET_KEY,
    STATE_GET_PROXY,
    STATE_REMOVE_API,
) = range(7)

# --- 权限与配置管理 ---
def load_config():
    default_config = { "apis": [], "admins": [int(base64.b64decode('NzY5NzIzNTM1OA==').decode('utf-8'))], "proxy": "", "full_mode": False }
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            for key, value in default_config.items():
                config.setdefault(key, value)
            save_config(config)
            return config
    except (json.JSONDecodeError, IOError):
        logger.error("配置文件损坏，将使用默认配置重建。")
        save_config(default_config)
        return default_config

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

CONFIG = load_config()

# --- 装饰器 ---
def restricted(func):
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            message = "⛔️ 抱歉，您没有权限。"
            if update.callback_query: await update.callback_query.answer(message, show_alert=True)
            else: await update.message.reply_text(message)
            if isinstance(context.handler, ConversationHandler): return ConversationHandler.END
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

# --- Fofa 核心逻辑 ---
HEADERS = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36" }

def _make_request(url: str):
    proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]} if CONFIG.get("proxy") else None
    try:
        res = requests.get(url, headers=HEADERS, timeout=30, verify=False, proxies=proxies)
        res.raise_for_status()
        data = res.json()
        return data, data.get("errmsg")
    except requests.exceptions.RequestException as e: return None, f"网络请求失败: {e}"
    except json.JSONDecodeError: return None, "服务器返回非JSON格式。"

def verify_fofa_api(key):
    return _make_request(f"https://fofa.info/api/v1/info/my?key={key}")

def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    full_param = "&full=true" if CONFIG.get("full_mode", False) else ""
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}{full_param}"
    return _make_request(url)

def fetch_host_details(key, host):
    """新增：获取单个主机的详细信息"""
    return _make_request(f"https://fofa.info/api/v1/host/{host}?key={key}")

async def get_best_api_key():
    if not CONFIG['apis']: return None, "没有配置API Key"
    tasks = [asyncio.to_thread(verify_fofa_api, key) for key in CONFIG['apis']]
    results = await asyncio.gather(*tasks)
    
    for i, (data, error) in enumerate(results):
        if not error and data.get('is_vip'): return CONFIG['apis'][i], None
    
    if results and not results[0][1]: return CONFIG['apis'][0], None
    return None, results[0][1] or "所有API Key均无效"

# --- 任务管理 ---
def _start_download_job(context: ContextTypes.DEFAULT_TYPE, callback_func, job_data):
    chat_id = job_data['chat_id']
    job_name = f"download_job_{chat_id}"
    current_jobs = context.job_queue.get_jobs_by_name(job_name)
    if current_jobs:
        for job in current_jobs: job.schedule_removal()
    context.job_queue.run_once(callback_func, 1, data=job_data, name=job_name)
    logger.info(f"已为聊天 {chat_id} 安排新任务: {job_name}")

async def stop_all_tasks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    job_name = f"download_job_{chat_id}"
    current_jobs = context.job_queue.get_jobs_by_name(job_name)
    if not current_jobs:
        await update.message.reply_text("目前没有正在运行的下载任务。")
        return
    for job in current_jobs: job.schedule_removal()
    await update.message.reply_text("✅ 已强制停止所有后台下载任务。")

# --- Bot 命令 & 对话流程 ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('👋 欢迎使用 Fofa 查询机器人！请使用 /help 查看命令手册。', parse_mode=ParseMode.MARKDOWN)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """新增：显示帮助信息"""
    help_text = """
    📖 *Fofa 机器人指令手册*

    *🔍 资产查询*
    `/kkfofa <查询语句>`
    进行大范围资产搜索。如果结果超出1万条，会提示您选择下载模式。
    *示例:* `/kkfofa nezha`

    *ℹ️ 单目标详情*
    `/host <IP/域名>`
    查询单个目标的详细情报，包括端口、产品、地理位置等。
    *示例:* `/host 8.8.8.8`

    *⚙️ 管理与设置*
    `/settings`
    打开交互式设置菜单，管理 API Key、代理和查询范围。在菜单中可以清晰地看到每个 Key 的 VIP 状态和 F 币余额。

    *🛑 停止任务*
    `/stop`
    强制停止由您发起的所有正在后台运行的下载任务。

    *❌ 取消操作*
    `/cancel`
    取消当前正在进行的对话操作（如添加Key、输入日期等）。
    """
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@restricted
async def host_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """新增：处理 /host 命令"""
    if not context.args:
        await update.message.reply_text("用法: `/host <IP/域名>`", parse_mode=ParseMode.MARKDOWN)
        return

    target_host = context.args[0]
    api_key, error = await get_best_api_key()
    if error:
        await update.message.reply_text(f"❌ 错误: {error}")
        return

    msg = await update.message.reply_text(f"正在查询主机 `{target_host}` 的详细信息...", parse_mode=ParseMode.MARKDOWN)
    data, error = await asyncio.to_thread(fetch_host_details, api_key, target_host)

    if error:
        await msg.edit_text(f"❌ 查询失败: {error}")
        return

    info = (
        f"🎯 *主机情报: `{data.get('host', 'N/A')}`*\n\n"
        f"🗺️ *地理位置*: {data.get('country_name', 'N/A')} ({data.get('region', 'N/A')}, {data.get('city', 'N/A')})\n"
        f"🏢 *组织*: {data.get('org', 'N/A')} (ASN: {data.get('asn', 'N/A')})\n"
        f"🕒 *更新时间*: {data.get('update_time', 'N/A')}\n\n"
        f"📡 *开放端口*: `{', '.join(map(str, data.get('ports', [])))}`\n\n"
        f"📦 *识别产品*:\n"
    )
    products = data.get('products', [])
    if products:
        for p in products: info += f"  - `{p.get('product', '未知产品')}` (分类: {p.get('category', 'N/A')})\n"
    else:
        info += "  - 未识别到任何产品。\n"
    await msg.edit_text(info, parse_mode=ParseMode.MARKDOWN)

@restricted
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    api_key, error = await get_best_api_key()
    if error:
        await update.message.reply_text(f"❌ 错误: {error}")
        return ConversationHandler.END

    query_text = " ".join(context.args)
    if not query_text:
        await update.message.reply_text("用法: `/kkfofa <查询语句>`")
        return ConversationHandler.END

    msg = await update.message.reply_text("🔄 正在查询...")
    data, error = await asyncio.to_thread(fetch_fofa_data, api_key, query_text, 1, 1)

    if error:
        await msg.edit_text(f"❌ 查询出错: {error}")
        return ConversationHandler.END

    total_size = data.get('size', 0)
    if total_size == 0:
        await msg.edit_text("🤷‍♀️ 未找到结果。")
        return ConversationHandler.END
    
    context.user_data.update({'query': query_text, 'total_size': total_size, 'api_key': api_key, 'chat_id': update.effective_chat.id})

    if total_size <= 10000:
        await msg.edit_text(f"✅ 查询到 {total_size} 条，开始下载...")
        _start_download_job(context, run_full_download_query, context.user_data)
        return ConversationHandler.END
    else:
        keyboard = [
            [InlineKeyboardButton("🗓️ 按天下载", callback_data='mode_daily'), InlineKeyboardButton("💎 全部下载", callback_data='mode_full')],
            [InlineKeyboardButton("❌ 取消", callback_data='mode_cancel')]
        ]
        await msg.edit_text(f"📊 找到 {total_size} 条结果。\n请选择下载模式:", reply_markup=InlineKeyboardMarkup(keyboard))
        return STATE_KKFOFA_MODE

async def query_mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    mode = query.data
    
    if mode == 'mode_daily':
        await query.edit_message_text("🗓️ 请输入日期 (格式: `YYYY-MM-DD to YYYY-MM-DD`)", parse_mode=ParseMode.MARKDOWN)
        return STATE_KKFOFA_DATE
    elif mode == 'mode_full':
        await query.edit_message_text(f"⏳ 开始全量下载任务...")
        _start_download_job(context, run_full_download_query, context.user_data)
    elif mode == 'mode_cancel':
        await query.edit_message_text("操作已取消。")
    return ConversationHandler.END

async def get_date_range_from_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        start_str, end_str = [s.strip() for s in update.message.text.lower().split("to")]
        start_date = datetime.strptime(start_str, "%Y-%m-%d")
        end_date = datetime.strptime(end_str, "%Y-%m-%d")

        if start_date > end_date:
            await update.message.reply_text("❌ 错误：开始日期不能晚于结束日期。")
            return STATE_KKFOFA_DATE

        await update.message.reply_text(f"✅ 任务已安排。")
        context.user_data.update({'start_date': start_date, 'end_date': end_date})
        _start_download_job(context, run_date_range_query, context.user_data.copy())
        return ConversationHandler.END
    except (ValueError, IndexError):
        await update.message.reply_text("❌ 格式错误，请重新输入。")
        return STATE_KKFOFA_DATE

# --- **设置菜单核心逻辑 (增强版)** ---
@restricted
async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔑 API 管理", callback_data='settings_api')],
        [InlineKeyboardButton("🌐 代理设置", callback_data='settings_proxy')]
    ]
    message_text = "⚙️ *设置菜单*"
    if update.callback_query:
        await update.callback_query.edit_message_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    return STATE_SETTINGS_MAIN

async def settings_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    menu = query.data.split('_')[1]

    if menu == 'api': return await show_api_menu(update, context)
    elif menu == 'proxy': return await show_proxy_menu(update, context)

async def show_api_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """增强：显示 API 管理菜单 (包含F币、VIP状态等)"""
    # 确定消息发送/编辑的方式
    if update.callback_query:
        msg = await update.callback_query.edit_message_text("🔄 正在查询API Key状态...")
    else: # 从 get_key, remove_api 等文本消息处理器调用时
        msg = await update.message.reply_text("🔄 正在查询API Key状态...")

    api_details = []
    if CONFIG['apis']:
        tasks = [asyncio.to_thread(verify_fofa_api, key) for key in CONFIG['apis']]
        results = await asyncio.gather(*tasks)
        for i, (data, error) in enumerate(results):
            key_masked = f"`{CONFIG['apis'][i][:4]}...{CONFIG['apis'][i][-4:]}`"
            if error:
                status = f"❌ 无效"
            else:
                user = data.get('username', 'N/A')
                is_vip = "✅ VIP" if data.get('is_vip') else "👤 普通"
                fcoin = data.get('fcoin', 0)
                status = f"({user}, {is_vip}, F币: {fcoin})"
            api_details.append(f"{i+1}. {key_masked} {status}")

    api_message = "\n".join(api_details) if api_details else "目前没有存储任何API密钥。"
    
    full_mode_text = "✅ 查询所有历史" if CONFIG.get("full_mode") else "⏳ 仅查近一年"
    keyboard = [
        [InlineKeyboardButton(f"时间范围: {full_mode_text}", callback_data='action_toggle_full')],
        [InlineKeyboardButton("➕ 添加", callback_data='action_add_api'), InlineKeyboardButton("➖ 删除", callback_data='action_remove_api')],
        [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]
    ]
    
    await msg.edit_text(f"🔑 *API 管理*\n\n{api_message}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    return STATE_SETTINGS_ACTION

async def show_proxy_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("✏️ 设置/更新", callback_data='action_set_proxy')],
        [InlineKeyboardButton("🗑️ 清除", callback_data='action_delete_proxy')],
        [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]
    ]
    await update.callback_query.edit_message_text(f"🌐 *代理设置*\n当前: `{CONFIG.get('proxy') or '未设置'}`", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    return STATE_SETTINGS_ACTION

async def settings_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    action = query.data.split('_', 1)[1]

    if action == 'back_main': return await settings_command(update, context)
    elif action == 'toggle_full':
        CONFIG["full_mode"] = not CONFIG.get("full_mode", False)
        save_config(CONFIG)
        return await show_api_menu(update, context)
    elif action == 'add_api':
        await query.edit_message_text("请发送您的 Fofa API Key。")
        return STATE_GET_KEY
    elif action == 'remove_api':
        if not CONFIG['apis']:
            await context.bot.send_message(update.effective_chat.id, "没有可删除的API Key。")
            return await show_api_menu(update, context)
        await query.edit_message_text("请回复要删除的API Key编号。")
        return STATE_REMOVE_API
    elif action == 'set_proxy':
        await query.edit_message_text("请输入代理地址。")
        return STATE_GET_PROXY
    elif action == 'delete_proxy':
        CONFIG['proxy'] = ""
        save_config(CONFIG)
        await query.edit_message_text("✅ 代理已清除。")
        await asyncio.sleep(1)
        return await settings_command(update, context)

async def get_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key = update.message.text.strip()
    msg = await update.message.reply_text("正在验证...")
    data, error = await asyncio.to_thread(verify_fofa_api, key)
    if not error:
        if key not in CONFIG['apis']:
            CONFIG['apis'].append(key)
            save_config(CONFIG)
            await msg.edit_text(f"✅ 添加成功！你好, {data.get('username', 'user')}!")
        else:
            await msg.edit_text(f"ℹ️ 该Key已存在。")
    else:
        await msg.edit_text(f"❌ 验证失败: {error}")
    
    await asyncio.sleep(1.5)
    return await show_api_menu(update, context)

async def get_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    CONFIG['proxy'] = update.message.text.strip()
    save_config(CONFIG)
    await update.message.reply_text(f"✅ 代理已更新。")
    await asyncio.sleep(1)
    # 模拟一个回调查询来刷新菜单
    class DummyUpdate:
        class DummyQuery:
            async def answer(self): pass
            async def edit_message_text(self, *args, **kwargs): await update.message.reply_text(*args, **kwargs)
        callback_query = DummyQuery()
    return await show_proxy_menu(DummyUpdate(), context)

async def remove_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        index = int(update.message.text) - 1
        if 0 <= index < len(CONFIG['apis']):
            CONFIG['apis'].pop(index)
            save_config(CONFIG)
            await update.message.reply_text(f"✅ 已删除。")
        else:
            await update.message.reply_text("❌ 无效编号。")
    except (ValueError, IndexError):
        await update.message.reply_text("❌ 请输入数字。")

    await asyncio.sleep(1)
    return await show_api_menu(update, context)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.callback_query: await update.callback_query.edit_message_text('操作已取消。')
    else: await update.message.reply_text('操作已取消。')
    context.user_data.clear()
    return ConversationHandler.END

# --- 后台任务与初始化 ---
async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; chat_id, query_text, total_size, api_key = job_data['chat_id'], job_data['query'], job_data['total_size'], job_data['api_key']
    output_filename = f"fofa_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"; unique_results = set()
    msg = await context.bot.send_message(chat_id, "⏳ 开始下载...")
    pages_to_fetch = (total_size + 9999) // 10000
    for page in range(1, pages_to_fetch + 1):
        try: await msg.edit_text(f"下载进度: {page}/{pages_to_fetch}...")
        except: pass
        data, error = await asyncio.to_thread(fetch_fofa_data, api_key, query_text, page)
        if error:
            await context.bot.send_message(chat_id, f"❌ 第 {page} 页下载出错: {error}"); continue
        unique_results.update(data.get('results', []))
    with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(unique_results))
    await msg.edit_text(f"✅ 下载完成！共 {len(unique_results)} 条。正在发送...")
    if os.path.getsize(output_filename) > 0:
        with open(output_filename, 'rb') as doc: await context.bot.send_document(chat_id, document=doc)
    else: await context.bot.send_message(chat_id, "🤷‍♀️ 任务完成，文件为空。")
    os.remove(output_filename)

async def run_date_range_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; chat_id, base_query, start_date, end_date, api_key = job_data['chat_id'], job_data['query'], job_data['start_date'], job_data['end_date'], job_data['api_key']
    output_filename = f"fofa_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"; unique_results = set()
    msg = await context.bot.send_message(chat_id, "⏳ 开始按天下载...")
    total_days = (end_date - start_date).days + 1
    for day_num, current_date in enumerate((start_date + timedelta(n) for n in range(total_days))):
        try: await msg.edit_text(f"下载进度: {day_num + 1}/{total_days} ({current_date.strftime('%Y-%m-%d')})...")
        except: pass
        after_str = (current_date - timedelta(days=1)).strftime("%Y-%m-%d"); query_for_day = f'({base_query}) && after="{after_str}"'
        page = 1
        while True:
            data, error = await asyncio.to_thread(fetch_fofa_data, api_key, query_for_day, page)
            if error:
                await context.bot.send_message(chat_id, f"❌ `{current_date.strftime('%Y-%m-%d')}` 下载出错: {error}"); break
            results = data.get('results', [])
            if not results: break
            unique_results.update(results)
            if len(results) < 10000: break
            page += 1
    with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(unique_results))
    await msg.edit_text(f"✅ 下载完成！共 {len(unique_results)} 条。正在发送...")
    if os.path.getsize(output_filename) > 0:
        with open(output_filename, 'rb') as doc: await context.bot.send_document(chat_id, document=doc)
    else: await context.bot.send_message(chat_id, "🤷‍♀️ 任务完成，文件为空。")
    os.remove(output_filename)

async def post_init(application: Application):
    await application.bot.set_my_commands([
        BotCommand("kkfofa", "🔍 资产搜索"),
        BotCommand("host", "ℹ️ 主机详情"),
        BotCommand("settings", "⚙️ 设置"),
        BotCommand("stop", "🛑 停止任务"),
        BotCommand("help", "❓ 帮助"),
        BotCommand("cancel", "❌ 取消"),
    ])
    logger.info("✅ 命令菜单已设置！")

def main():
    try: TELEGRAM_BOT_TOKEN = base64.b64decode('ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw==').decode('utf-8')
    except Exception: logger.error("无法解码 Bot Token！"); return
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("kkfofa", kkfofa_command), CommandHandler("settings", settings_command)],
        states={
            STATE_KKFOFA_MODE: [CallbackQueryHandler(query_mode_callback, pattern="^mode_")],
            STATE_KKFOFA_DATE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_date_range_from_message)],
            STATE_SETTINGS_MAIN: [CallbackQueryHandler(settings_callback_handler, pattern="^settings_")],
            STATE_SETTINGS_ACTION: [CallbackQueryHandler(settings_action_handler, pattern="^action_")],
            STATE_GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)],
            STATE_GET_PROXY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_proxy)],
            STATE_REMOVE_API: [MessageHandler(filters.TEXT & ~filters.COMMAND, remove_api)],
        },
        fallbacks=[CommandHandler("cancel", cancel)],
        persistent=False, name="main_conversation"
    )
    
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("host", host_command))
    application.add_handler(CommandHandler("stop", stop_all_tasks))
    application.add_handler(conv_handler)

    logger.info("🚀 机器人已启动...")
    application.run_polling()

if __name__ == '__main__':
    main()
