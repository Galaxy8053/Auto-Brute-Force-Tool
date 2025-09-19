import os
import json
import logging
import base64
import time
import re
import asyncio
from datetime import datetime, timedelta, timezone
from functools import wraps
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- 全局变量和常量 ---
CONFIG_FILE = 'config.json'
HISTORY_FILE = 'history.json'
LOG_FILE = 'fofa_bot.log'
MAX_HISTORY_SIZE = 50
TELEGRAM_DOWNLOAD_LIMIT = 20 * 1024 * 1024 # 20 MB
CACHE_EXPIRATION_SECONDS = 24 * 60 * 60 # 24 hours

# --- 日志配置 ---
if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > (5 * 1024 * 1024): # 5MB
    try:
        os.rename(LOG_FILE, LOG_FILE + '.old')
    except OSError as e:
        print(f"无法轮换日志文件: {e}")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

(
    STATE_KKFOFA_MODE,
    STATE_SETTINGS_MAIN,
    STATE_SETTINGS_ACTION,
    STATE_GET_KEY,
    STATE_GET_PROXY,
    STATE_REMOVE_API,
    STATE_CACHE_CHOICE,
) = range(7)

# --- 配置与历史记录管理 ---
def load_json_file(filename, default_content):
    if not os.path.exists(filename):
        with open(filename, 'w', encoding='utf-8') as f: json.dump(default_content, f, indent=4)
        return default_content
    try:
        with open(filename, 'r', encoding='utf-8') as f: return json.load(f)
    except (json.JSONDecodeError, IOError):
        logger.error(f"{filename} 损坏，将使用默认配置重建。")
        with open(filename, 'w', encoding='utf-8') as f: json.dump(default_content, f, indent=4)
        return default_content

def save_json_file(filename, data):
    with open(filename, 'w', encoding='utf-8') as f: json.dump(data, f, indent=4)

default_admin_id = int(base64.b64decode('NzY5NzIzNTM1OA==').decode('utf-8'))
CONFIG = load_json_file(CONFIG_FILE, {"apis": [], "admins": [default_admin_id], "proxy": "", "full_mode": False})
HISTORY = load_json_file(HISTORY_FILE, {"queries": []})

def save_config(): save_json_file(CONFIG_FILE, CONFIG)
def save_history(): save_json_file(HISTORY_FILE, HISTORY)

def add_or_update_query(query_text, cache_data=None):
    existing_query = next((q for q in HISTORY['queries'] if q['query_text'] == query_text), None)
    if existing_query:
        HISTORY['queries'].remove(existing_query)
        existing_query['timestamp'] = datetime.now(timezone.utc).isoformat()
        if cache_data: existing_query['cache'] = cache_data
        HISTORY['queries'].insert(0, existing_query)
    else:
        new_query = {"query_text": query_text, "timestamp": datetime.now(timezone.utc).isoformat(), "cache": cache_data}
        HISTORY['queries'].insert(0, new_query)
    while len(HISTORY['queries']) > MAX_HISTORY_SIZE: HISTORY['queries'].pop()
    save_history()

def find_cached_query(query_text):
    query = next((q for q in HISTORY['queries'] if q['query_text'] == query_text), None)
    if query and query.get('cache'): return query
    return None

# --- 辅助函数与装饰器 ---
def escape_markdown(text: str) -> str:
    escape_chars = '_*`[]()~>#+-=|{}.!'; return "".join(['\\' + char if char in escape_chars else char for char in text])

def restricted(func):
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            if update.message: await update.message.reply_text("⛔️ 抱歉，您没有权限。")
            return None
        return await func(update, context, *args, **kwargs)
    return wrapped

# --- FOFA API 核心逻辑 (保持不变) ---
async def _make_request_async(url: str):
    proxy_str = ""
    if CONFIG.get("proxy"): proxy_str = f'--proxy "{CONFIG["proxy"]}"'
    command = f'curl -s -L -k {proxy_str} "{url}"'
    try:
        proc = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0: return None, f"网络请求失败 (curl): {stderr.decode().strip()}"
        response_text = stdout.decode()
        if not response_text: return None, "API 返回了空响应。"
        data = json.loads(response_text)
        if data.get("error"): return None, data.get("errmsg", "未知的FOFA错误")
        return data, None
    except json.JSONDecodeError: return None, f"解析JSON响应失败: {response_text[:200]}"
    except Exception as e: return None, f"执行curl时发生意外错误: {e}"

async def verify_fofa_api(key):
    url = f"https://fofa.info/api/v1/info/my?key={key}"; return await _make_request_async(url)

async def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    full_param = "&full=true" if CONFIG.get("full_mode", False) else ""
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}{full_param}"
    return await _make_request_async(url)

async def execute_query_with_fallback(query_func, preferred_key_index=None):
    if not CONFIG['apis']: return None, None, "没有配置任何API Key。"
    tasks = [verify_fofa_api(key) for key in CONFIG['apis']]
    results = await asyncio.gather(*tasks)
    valid_keys = [{'key': CONFIG['apis'][i], 'index': i + 1, 'is_vip': data.get('is_vip', False)} for i, (data, error) in enumerate(results) if not error and data]
    if not valid_keys: return None, None, "所有API Key均无效或验证失败。"
    prioritized_keys = sorted(valid_keys, key=lambda x: x['is_vip'], reverse=True)
    keys_to_try = prioritized_keys
    if preferred_key_index is not None:
        start_index = next((i for i, k in enumerate(prioritized_keys) if k['index'] == preferred_key_index), -1)
        if start_index != -1: keys_to_try = prioritized_keys[start_index:] + prioritized_keys[:start_index]
    last_error = "没有可用的API Key。"
    for key_info in keys_to_try:
        data, error = await query_func(key_info['key'])
        if not error: return data, key_info['index'], None
        last_error = error
        if "[820031]" in str(error): logger.warning(f"Key [#{key_info['index']}] F点余额不足，尝试下一个..."); continue
        return None, key_info['index'], error
    return None, None, f"所有Key均尝试失败，最后错误: {last_error}"

# --- 管理员命令 ---
@restricted
async def get_log_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(LOG_FILE):
        await update.message.reply_document(document=open(LOG_FILE, 'rb'), caption="这是当前的机器人运行日志。")
    else:
        await update.message.reply_text("❌ 未找到日志文件。")

@restricted
async def shutdown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("✅ **收到指令！**\n机器人正在安全关闭...", parse_mode=ParseMode.MARKDOWN)
    logger.info(f"接收到来自用户 {update.effective_user.id} 的关闭指令。")
    shutdown_event = context.bot_data.get('shutdown_event')
    if shutdown_event:
        shutdown_event.set()
    else:
        logger.error("无法找到 shutdown_event, 无法正常关闭。")
        await update.message.reply_text("❌ 内部错误：无法触发关闭事件。")


# --- 智能导入与缓存刷新 ---
@restricted
async def import_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.reply_to_message or not update.message.reply_to_message.document:
        await update.message.reply_text("❌ **使用方法错误**\n请**回复 (Reply)** 一个您想导入的 `.txt` 文件，然后再输入此命令。"); return
    if not context.args:
        await update.message.reply_text("❌ **缺少参数**\n请在命令后附上查询语句和可选的结果数量。\n\n*用法:*\n`/import <查询语句> [可选数量]`"); return
    
    doc = update.message.reply_to_message.document; args = context.args; query_text = ""; provided_count = None
    if args[-1].isdigit():
        try: provided_count = int(args[-1]); query_text = " ".join(args[:-1])
        except (ValueError, IndexError): query_text = " ".join(args)
    else: query_text = " ".join(args)
    if not query_text: await update.message.reply_text("❌ **查询语句不能为空**。"); return

    if doc.file_size and doc.file_size > TELEGRAM_DOWNLOAD_LIMIT:
        msg = await update.message.reply_text(f"⚠️ **检测到大文件 (>20MB)**\n将跳过下载，直接关联缓存...")
        result_count = provided_count if provided_count is not None else -1
        cache_data = {'file_id': doc.file_id, 'file_unique_id': doc.file_unique_id, 'file_name': doc.file_name, 'result_count': result_count}
        add_or_update_query(query_text, cache_data)
        count_str = str(result_count) if result_count != -1 else "未知"
        reply_text = f"✅ **导入成功 (大文件模式)！**\n\n查询 `{escape_markdown(query_text)}` 已成功关联缓存。\n结果数量: *{count_str}*\n\n"
        original_message_date = update.message.reply_to_message.date
        if (datetime.now(timezone.utc) - original_message_date).total_seconds() > CACHE_EXPIRATION_SECONDS:
            reply_text += "⚠️ **警告**: 此文件发送于24小时前，其缓存**无法用于增量更新**。您可以手动下载并重新发送此文件给我来刷新时效。"
        else: reply_text += "下次使用此查询时即可进行增量更新。"
        await msg.edit_text(reply_text, parse_mode=ParseMode.MARKDOWN)
    else:
        msg = await update.message.reply_text("正在下载文件并统计精确行数...")
        temp_path = f"import_{doc.file_name}"
        try:
            file = await doc.get_file(); await file.download_to_drive(temp_path)
            with open(temp_path, 'r', encoding='utf-8') as f: counted_lines = sum(1 for line in f if line.strip())
            cache_data = {'file_id': doc.file_id, 'file_unique_id': doc.file_unique_id, 'file_name': doc.file_name, 'result_count': counted_lines}
            add_or_update_query(query_text, cache_data)
            await msg.edit_text(f"✅ **导入成功！**\n\n查询 `{escape_markdown(query_text)}` 已成功关联 {counted_lines} 条结果的缓存。\n下次使用此查询时即可进行增量更新。", parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            logger.error(f"导入小文件时出错: {e}"); await msg.edit_text(f"❌ 导入失败: {e}")
        finally:
            if os.path.exists(temp_path): os.remove(temp_path)

@restricted
async def refresh_cache_from_reply(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.reply_to_message or not update.message.reply_to_message.text: return
    original_text = update.message.reply_to_message.text
    match = re.search(r"查询: `(.+?)`", original_text)
    if not match: return
    query_text = match.group(1).replace('\\', '')
    cached_item = find_cached_query(query_text)
    if not cached_item:
        await update.message.reply_text("🤔 看起来这条消息对应的缓存记录不存在，请尝试使用 `/import` 命令手动导入。"); return
    doc = update.message.document
    new_cache_data = {'file_id': doc.file_id, 'file_unique_id': doc.file_unique_id, 'file_name': doc.file_name, 'result_count': cached_item['cache']['result_count']}
    add_or_update_query(query_text, new_cache_data)
    await update.message.reply_text(f"✅ **缓存已刷新！**\n\n查询 `{escape_markdown(query_text)}` 的缓存时效已更新。\n现在可以对此查询进行增量更新了。", parse_mode=ParseMode.MARKDOWN)

# --- 其他命令 ---
# ... (backup, restore, history, settings, etc.) ...
@restricted
async def backup_config_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if os.path.exists(CONFIG_FILE): await chat.send_document(document=open(CONFIG_FILE, 'rb'), caption="这是您当前的配置文件备份。")
    else: await chat.send_message("❌ 找不到配置文件。")

@restricted
async def restore_config_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📥 要恢复配置，请直接将您的 `config.json` 备份文件作为文档发送给我。")

@restricted
async def receive_config_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global CONFIG
    document = update.message.document
    if document.file_name != CONFIG_FILE: await update.message.reply_text(f"❌ 文件名错误，请确保上传的文件名为 `{CONFIG_FILE}`。"); return
    try:
        file = await document.get_file(); temp_file_path = f"{CONFIG_FILE}.tmp"; await file.download_to_drive(temp_file_path)
        with open(temp_file_path, 'r', encoding='utf-8') as f: json.load(f)
        os.replace(temp_file_path, CONFIG_FILE)
        CONFIG = load_json_file(CONFIG_FILE, {})
        await update.message.reply_text("✅ 配置已成功恢复！")
    except Exception as e:
        logger.error(f"恢复配置文件时出错: {e}"); await update.message.reply_text(f"❌ 恢复配置时发生意外错误: {e}")
        if os.path.exists(temp_file_path): os.remove(temp_file_path)

@restricted
async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not HISTORY['queries']: await update.message.reply_text("🕰️ 暂无历史记录。"); return
    message_text = "🕰️ *最近10条查询记录:*\n\n"
    for i, query in enumerate(HISTORY['queries'][:10]):
        dt_utc = datetime.fromisoformat(query['timestamp']); dt_local = dt_utc.astimezone(); time_str = dt_local.strftime('%Y-%m-%d %H:%M')
        cache_icon = "✅" if query.get('cache') else "❌"
        message_text += f"`{i+1}.` {escape_markdown(query['query_text'])} \n_{time_str}_  (缓存: {cache_icon})\n\n"
    await update.message.reply_text(message_text, parse_mode=ParseMode.MARKDOWN)

async def start_new_search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query_text = context.user_data['query']; key_index = context.user_data.get('key_index')
    add_or_update_query(query_text)
    message_able = update.callback_query.message if update.callback_query else update.message
    edit_func = message_able.edit_text if update.callback_query else message_able.reply_text
    msg = await edit_func("🔄 正在执行全新查询...")
    data, used_key_index, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, query_text, 1, 1, "host"), key_index)
    if error: await msg.edit_text(f"❌ 查询出错: {error}"); return ConversationHandler.END
    total_size = data.get('size', 0)
    if total_size == 0: await msg.edit_text("🤷‍♀️ 未找到结果。"); return ConversationHandler.END
    context.user_data.update({'total_size': total_size, 'chat_id': update.effective_chat.id})
    success_message = f"✅ 使用 Key [#{used_key_index}] 找到 {total_size} 条结果。"
    if total_size <= 10000:
        await msg.edit_text(f"{success_message}\n开始下载..."); await start_download_job(context, run_full_download_query, context.user_data)
        return ConversationHandler.END
    else:
        keyboard = [[InlineKeyboardButton("💎 全部下载", callback_data='mode_full'), InlineKeyboardButton("🌀 深度追溯下载", callback_data='mode_traceback')], [InlineKeyboardButton("❌ 取消", callback_data='mode_cancel')]]
        await msg.edit_text(f"{success_message}\n请选择下载模式:", reply_markup=InlineKeyboardMarkup(keyboard))
        return STATE_KKFOFA_MODE

def get_user_data(update: Update, context: ContextTypes.DEFAULT_TYPE) -> dict:
    chat_id = update.effective_chat.id
    if not context.user_data:
        persistent_data_key = f"persistent_user_data_{chat_id}"
        if persistent_data_key in context.bot_data:
            context.user_data.update(context.bot_data[persistent_data_key])
            logger.info(f"为 chat_id {chat_id} 恢复了 user_data。")
    return context.user_data

@restricted
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args: await update.message.reply_text("用法: `/kkfofa [key编号] <查询语句>`"); return ConversationHandler.END
    key_index, query_text = None, " ".join(args)
    try:
        key_index = int(args[0])
        if not (1 <= key_index <= len(CONFIG['apis'])): await update.message.reply_text(f"❌ Key编号无效。"); return ConversationHandler.END
        query_text = " ".join(args[1:])
    except (ValueError, IndexError): pass
    
    user_data = get_user_data(update, context)
    user_data.update({'query': query_text, 'key_index': key_index, 'chat_id': update.effective_chat.id})
    context.bot_data[f"persistent_user_data_{update.effective_chat.id}"] = user_data.copy()

    cached_item = find_cached_query(query_text)
    if cached_item:
        dt_utc = datetime.fromisoformat(cached_item['timestamp']); dt_local = dt_utc.astimezone(); time_str = dt_local.strftime('%Y-%m-%d %H:%M')
        result_count = cached_item['cache']['result_count']
        count_str = str(result_count) if result_count != -1 else "未知 (大文件)"
        
        is_expired = (datetime.now(timezone.utc) - dt_utc).total_seconds() > CACHE_EXPIRATION_SECONDS
        
        message_text = (f"✅ **发现缓存**\n\n查询: `{escape_markdown(query_text)}`\n缓存于: *{time_str}* (含 *{count_str}* 条结果)\n\n")
        
        keyboard = []
        if is_expired:
            message_text += "⚠️ **此缓存已超过24小时，无法增量更新。**\n您可以手动下载此文件，然后**回复本消息**并重新上传，以刷新缓存时效。"
            keyboard.append([InlineKeyboardButton("⬇️ 下载旧缓存", callback_data='cache_download'), InlineKeyboardButton("🔍 全新搜索", callback_data='cache_newsearch')])
        else:
            message_text += "请选择操作："
            keyboard.append([InlineKeyboardButton("🔄 增量更新", callback_data='cache_incremental')])
            keyboard.append([InlineKeyboardButton("⬇️ 下载缓存", callback_data='cache_download'), InlineKeyboardButton("🔍 全新搜索", callback_data='cache_newsearch')])
        
        keyboard.append([InlineKeyboardButton("❌ 取消", callback_data='cache_cancel')])
        
        await update.message.reply_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
        return STATE_CACHE_CHOICE
        
    return await start_new_search(update, context)

async def cache_choice_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    user_data = get_user_data(update, context)
    if not user_data:
        await query.edit_message_text("❌ 会话已过期，请重新发起 /kkfofa 查询。"); return ConversationHandler.END

    choice = query.data.split('_')[1]
    if choice == 'download':
        cached_item = find_cached_query(user_data['query'])
        if cached_item:
            await query.edit_message_text("⬇️ 正在从缓存发送文件...")
            try:
                await context.bot.send_document(chat_id=update.effective_chat.id, document=cached_item['cache']['file_id'], caption=f"来自 {cached_item['timestamp'].split('T')[0]} 的缓存结果。")
                await query.delete_message()
            except BadRequest as e:
                logger.error(f"发送缓存文件失败: {e}")
                await query.edit_message_text(f"❌ 发送缓存失败: {e}\n可能是文件已从Telegram服务器过期。")
        else: await query.edit_message_text("❌ 找不到缓存记录，请重新搜索。")
        return ConversationHandler.END
    elif choice == 'newsearch': return await start_new_search(update, context)
    elif choice == 'incremental':
        await query.edit_message_text("⏳ 准备增量更新...")
        await start_download_job(context, run_incremental_update_query, user_data)
        return ConversationHandler.END
    elif choice == 'cancel': await query.edit_message_text("操作已取消。"); return ConversationHandler.END

async def start_download_job(context: ContextTypes.DEFAULT_TYPE, callback_func, job_data):
    chat_id = job_data.get('chat_id')
    if not chat_id:
        logger.error("start_download_job 失败: job_data 中缺少 'chat_id'。")
        if hasattr(context.job, 'chat_id') and context.job.chat_id:
             await context.bot.send_message(context.job.chat_id, "❌ 内部错误：无法启动下载任务，会话信息丢失。")
        return

    job_name = f"download_job_{chat_id}"
    for job in context.job_queue.get_jobs_by_name(job_name): job.schedule_removal()
    context.bot_data.pop(f'stop_job_{chat_id}', None)
    context.job_queue.run_once(callback_func, 1, data=job_data, name=job_name, chat_id=chat_id)
    
async def stop_all_tasks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.bot_data[f'stop_job_{update.effective_chat.id}'] = True
    await update.message.reply_text("✅ 已发送停止信号。")

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('👋 欢迎使用 Fofa 查询机器人！请使用 /help 查看命令手册。')
    if update.effective_user.id not in CONFIG.get('admins', []):
        CONFIG.setdefault('admins', []).append(update.effective_user.id); save_config()
        await update.message.reply_text("ℹ️ 已自动将您添加为管理员。")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = ( "📖 *Fofa 机器人指令手册*\n\n" 
                  "*🔍 资产查询*\n`/kkfofa [key编号] <查询语句>`\n\n" 
                  "*⚙️ 管理与设置*\n`/settings` - 进入交互式设置菜单\n\n" 
                  "*💾 高级功能*\n"
                  "`/backup` - 备份当前配置\n"
                  "`/restore` - 恢复配置\n"
                  "`/history` - 查看查询历史\n"
                  "`/import` - 导入旧结果作为缓存\n"
                  "  用法: **回复**一个文件, 然后输入:\n"
                  "  `/import <查询语句> [可选数量]`\n\n"
                  "*💻 系统管理 (仅管理员)*\n"
                  "`/getlog` - 获取机器人运行日志\n"
                  "`/shutdown` - 安全关闭机器人\n\n"
                  "*🛑 任务控制*\n`/stop` - 紧急停止当前下载任务\n`/cancel` - 取消当前操作" )
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

async def query_mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer()
    user_data = get_user_data(update, context)
    if not user_data:
        await query.edit_message_text("❌ 会话已过期，请重新发起 /kkfofa 查询。"); return ConversationHandler.END

    mode = query.data.split('_')[1]
    if mode == 'full': await query.edit_message_text(f"⏳ 开始全量下载任务..."); await start_download_job(context, run_full_download_query, user_data)
    elif mode == 'traceback': await query.edit_message_text(f"⏳ 开始深度追溯下载任务..."); await start_download_job(context, run_traceback_download_query, user_data)
    elif mode == 'cancel': await query.edit_message_text("操作已取消。")
    return ConversationHandler.END

@restricted
async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("🔑 API 管理", callback_data='settings_api')], [InlineKeyboardButton("🌐 代理设置", callback_data='settings_proxy')], [InlineKeyboardButton("💾 备份与恢复", callback_data='settings_backup')], [InlineKeyboardButton("🕰️ 查询历史", callback_data='settings_history')]]
    message_text = "⚙️ *设置菜单*"
    if update.callback_query: await update.callback_query.edit_message_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    else: await update.message.reply_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    return STATE_SETTINGS_MAIN

# ... (所有 settings, 下载任务, main 函数与上一版完全一致) ...
async def settings_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer(); menu = query.data.split('_', 1)[1]
    if menu == 'api': await show_api_menu(update, context); return STATE_SETTINGS_ACTION
    elif menu == 'proxy': await show_proxy_menu(update, context); return STATE_SETTINGS_ACTION
    elif menu == 'backup': await show_backup_restore_menu(update, context); return STATE_SETTINGS_ACTION
    elif menu == 'history': await history_command(update, context); await query.message.reply_text("返回设置主菜单:", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 返回", callback_data='settings_back_main')]])); return STATE_SETTINGS_MAIN

async def show_api_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = await (update.callback_query.edit_message_text if update.callback_query else update.message.reply_text)("🔄 正在查询API Key状态...")
    tasks = [verify_fofa_api(key) for key in CONFIG['apis']]; results = await asyncio.gather(*tasks); api_details = []
    for i, (data, error) in enumerate(results):
        key_masked = f"`{CONFIG['apis'][i][:4]}...{CONFIG['apis'][i][-4:]}`"; status = f"❌ 无效或出错: {error}"
        if not error and data: status = f"({escape_markdown(data.get('username', 'N/A'))}, {'✅ VIP' if data.get('is_vip') else '👤 普通'}, F币: {data.get('fcoin', 0)})"
        api_details.append(f"{i+1}. {key_masked} {status}")
    api_message = "\n".join(api_details) if api_details else "目前没有存储任何API密钥。"
    keyboard = [[InlineKeyboardButton(f"时间范围: {'✅ 查询所有历史' if CONFIG.get('full_mode') else '⏳ 仅查近一年'}", callback_data='action_toggle_full')], [InlineKeyboardButton("➕ 添加Key", callback_data='action_add_api'), InlineKeyboardButton("➖ 删除Key", callback_data='action_remove_api')], [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]]
    await msg.edit_text(f"🔑 *API 管理*\n\n{api_message}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)

async def show_proxy_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("✏️ 设置/更新", callback_data='action_set_proxy')], [InlineKeyboardButton("🗑️ 清除", callback_data='action_delete_proxy')], [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]]
    await update.callback_query.edit_message_text(f"🌐 *代理设置*\n当前: `{CONFIG.get('proxy') or '未设置'}`", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)

async def show_backup_restore_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message_text = ("💾 *备份与恢复*\n\n📤 *备份*\n点击下方按钮，或使用 /backup 命令。\n\n📥 *恢复*\n直接向机器人**发送** `config.json` 文件即可。")
    keyboard = [[InlineKeyboardButton("📤 立即备份", callback_data='action_backup_now')], [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]]
    await update.callback_query.edit_message_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)

async def settings_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer(); action = query.data.split('_', 1)[1]
    if action == 'back_main': return await settings_command(update, context)
    elif action == 'toggle_full': CONFIG["full_mode"] = not CONFIG.get("full_mode", False); save_config(); await show_api_menu(update, context); return STATE_SETTINGS_ACTION
    elif action == 'add_api': await query.edit_message_text("请发送您的 Fofa API Key。"); return STATE_GET_KEY
    elif action == 'remove_api':
        if not CONFIG['apis']: await query.message.reply_text("没有可删除的API Key。"); await show_api_menu(update, context); return STATE_SETTINGS_ACTION
        await query.edit_message_text("请回复要删除的API Key编号。"); return STATE_REMOVE_API
    elif action == 'set_proxy': await query.edit_message_text("请输入代理地址。"); return STATE_GET_PROXY
    elif action == 'delete_proxy': CONFIG['proxy'] = ""; save_config(); await query.edit_message_text("✅ 代理已清除。"); await asyncio.sleep(1); return await settings_command(update, context)
    elif action == 'backup_now': await backup_config_command(update, context); return STATE_SETTINGS_ACTION

async def get_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key = update.message.text.strip(); msg = await update.message.reply_text("正在验证...")
    data, error = await verify_fofa_api(key)
    if not error and data:
        if key not in CONFIG['apis']: CONFIG['apis'].append(key); save_config(); await msg.edit_text(f"✅ 添加成功！你好, {escape_markdown(data.get('username', 'user'))}!", parse_mode=ParseMode.MARKDOWN)
        else: await msg.edit_text(f"ℹ️ 该Key已存在。")
    else: await msg.edit_text(f"❌ 验证失败: {error}")
    await asyncio.sleep(2); await msg.delete(); await show_api_menu(update, context); return STATE_SETTINGS_ACTION

async def get_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    CONFIG['proxy'] = update.message.text.strip(); save_config()
    await update.message.reply_text(f"✅ 代理已更新。"); await asyncio.sleep(1)
    await update.message.reply_text("请重新输入 /settings 进入设置菜单。"); return ConversationHandler.END

async def remove_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        index = int(update.message.text) - 1
        if 0 <= index < len(CONFIG['apis']): CONFIG['apis'].pop(index); save_config(); await update.message.reply_text(f"✅ 已删除。")
        else: await update.message.reply_text("❌ 无效编号。")
    except (ValueError, IndexError): await update.message.reply_text("❌ 请输入数字。")
    await asyncio.sleep(1); await show_api_menu(update, context); return STATE_SETTINGS_ACTION

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('操作已取消。'); context.user_data.clear(); return ConversationHandler.END

async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; bot = context.bot; chat_id, query_text, total_size = job_data['chat_id'], job_data['query'], job_data['total_size']
    output_filename = f"fofa_full_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results = set(); msg = await bot.send_message(chat_id, "⏳ 开始全量下载任务...")
    pages_to_fetch = (total_size + 9999) // 10000; stop_flag = f'stop_job_{chat_id}'
    for page in range(1, pages_to_fetch + 1):
        if context.bot_data.get(stop_flag): await msg.edit_text("🌀 下载任务已手动停止."); break
        try: await msg.edit_text(f"下载进度: {len(unique_results)}/{total_size} (Page {page}/{pages_to_fetch})...")
        except Exception: pass
        data, _, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, query_text, page, 10000, "host"))
        if error: await msg.edit_text(f"❌ 第 {page} 页下载出错: {error}"); break
        if not data.get('results'): break
        unique_results.update(data.get('results', []))
    if unique_results:
        with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(unique_results))
        await msg.edit_text(f"✅ 下载完成！共 {len(unique_results)} 条。正在发送...")
        with open(output_filename, 'rb') as doc: sent_message = await bot.send_document(chat_id, document=doc, filename=output_filename)
        os.remove(output_filename)
        cache_data = {'file_id': sent_message.document.file_id, 'file_unique_id': sent_message.document.file_unique_id, 'file_name': output_filename, 'result_count': len(unique_results)}
        add_or_update_query(query_text, cache_data)
    elif not context.bot_data.get(stop_flag): await msg.edit_text("🤷‍♀️ 任务完成，但未能下载到任何数据。")
    context.bot_data.pop(stop_flag, None)

async def run_traceback_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; bot = context.bot; chat_id, base_query = job_data['chat_id'], job_data['query']
    output_filename = f"fofa_traceback_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results, page_count, last_page_date, termination_reason = set(), 0, None, ""
    msg = await bot.send_message(chat_id, "⏳ 开始深度追溯下载...")
    current_query = base_query; stop_flag = f'stop_job_{chat_id}'
    while True:
        page_count += 1
        if context.bot_data.get(stop_flag): termination_reason = "\n\n🌀 任务已手动停止."; break
        data, _, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, current_query, 1, 10000, "host,lastupdatetime"))
        if error: termination_reason = f"\n\n❌ 第 {page_count} 轮出错: {error}"; break
        results = data.get('results', []);
        if not results: termination_reason = f"\n\nℹ️ 已获取所有查询结果."; break
        original_count = len(unique_results); unique_results.update([r[0] for r in results if r and r[0]]); newly_added_count = len(unique_results) - original_count
        try: await msg.edit_text(f"⏳ 已找到 {len(unique_results)} 条... (第 {page_count} 轮, 新增 {newly_added_count})")
        except Exception: pass
        valid_anchor_found = False; outer_loop_break = False
        for i in range(len(results) - 1, -1, -1):
            if not results[i] or not results[i][0]: continue
            potential_anchor_host = results[i][0]
            anchor_host_data, _, _ = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, f'host="{potential_anchor_host}"', 1, 1, "lastupdatetime"))
            try:
                timestamp_str = ""; results_list = anchor_host_data.get('results', [])
                if not results_list: raise ValueError("锚点主机未返回任何结果。")
                first_item = results_list[0]
                if isinstance(first_item, list): timestamp_str = first_item[0]
                else: timestamp_str = first_item
                if not isinstance(timestamp_str, str) or not timestamp_str: raise ValueError(f"从结果中未能提取有效的时间戳字符串。")
                current_date_obj = datetime.strptime(timestamp_str.split(' ')[0], '%Y-%m-%d')
                if last_page_date and current_date_obj.date() >= last_page_date: logger.warning(f"检测到时间回溯或停滞！跳过锚点 {potential_anchor_host}。"); continue
                logger.info(f"锚点 {potential_anchor_host} 的有效时间戳: {timestamp_str}")
                next_page_date_obj = current_date_obj
                if last_page_date and current_date_obj.date() == last_page_date: next_page_date_obj -= timedelta(days=1)
                next_page_date_str = next_page_date_obj.strftime('%Y-%m-%d')
                if last_page_date and next_page_date_str == last_page_date.strftime('%Y-%m-%d') and newly_added_count == 0: termination_reason = "\n\n⚠️ 日期未推进且无新数据，已达查询边界."; outer_loop_break = True; break
                last_page_date = current_date_obj.date(); current_query = f'({base_query}) && before="{next_page_date_str}"'; valid_anchor_found = True; break
            except (IndexError, TypeError, ValueError, AttributeError) as e: logger.warning(f"主机 {potential_anchor_host} 作为锚点无效: {e}。尝试下一个..."); continue
        if outer_loop_break: break
        if not valid_anchor_found: termination_reason = "\n\n❌ 错误：无法找到有效的时间锚点以继续。"; logger.error(f"第 {page_count} 轮中所有结果均无法作为锚点。"); break
    if unique_results:
        with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(unique_results))))
        await msg.edit_text(f"✅ 深度追溯完成！共 {len(unique_results)} 条。{termination_reason}\n正在发送文件...")
        with open(output_filename, 'rb') as doc: sent_message = await bot.send_document(chat_id, document=doc, filename=output_filename)
        os.remove(output_filename)
        cache_data = {'file_id': sent_message.document.file_id, 'file_unique_id': sent_message.document.file_unique_id, 'file_name': output_filename, 'result_count': len(unique_results)}
        add_or_update_query(base_query, cache_data)
    else: await msg.edit_text(f"🤷‍♀️ 任务完成，但未能下载到任何数据。{termination_reason}")
    context.bot_data.pop(stop_flag, None)

async def run_incremental_update_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; bot = context.bot
    chat_id, base_query = job_data['chat_id'], job_data['query']
    msg = await bot.send_message(chat_id, "--- 增量更新启动 ---")
    
    await msg.edit_text("1/5: 正在获取旧缓存...")
    cached_item = find_cached_query(base_query)
    if not cached_item: await msg.edit_text("❌ 错误：找不到缓存项。"); return
    
    old_file_path = f"old_{cached_item['cache']['file_name']}"; old_results = set()
    try:
        file = await bot.get_file(cached_item['cache']['file_id']); await file.download_to_drive(old_file_path)
        with open(old_file_path, 'r', encoding='utf-8') as f: old_results = set(line.strip() for line in f if line.strip())
        if not old_results: raise ValueError("缓存文件为空。")
    except BadRequest:
        await msg.edit_text("❌ **错误：缓存文件已无法下载**\n\n由于Telegram的限制，机器人无法下载超过24小时的文件。\n\n请返回并选择 **🔍 全新搜索** 来获取最新数据。");
        return
    except Exception as e: await msg.edit_text(f"❌ 读取缓存文件失败: {e}"); return
    
    await msg.edit_text("2/5: 正在确定更新起始点...")
    sorted_old_results = sorted(list(old_results), reverse=True)
    if not sorted_old_results: await msg.edit_text(f"❌ 缓存文件为空，无法确定起始点"); os.remove(old_file_path); return
    first_line = sorted_old_results[0]
    
    data, _, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, f'host="{first_line}"', fields="lastupdatetime"))
    if error or not data.get('results'):
        await msg.edit_text(f"❌ 无法获取最新记录时间戳: {error or '无结果'}"); os.remove(old_file_path); return

    ts_str = data['results'][0] if not isinstance(data['results'][0], list) else data['results'][0][0]
    cutoff_date = ts_str.split(' ')[0]
    incremental_query = f'({base_query}) && after="{cutoff_date}"'
    
    await msg.edit_text(f"3/5: 正在侦察自 {cutoff_date} 以来的新数据...")
    data, _, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, incremental_query, size=1))
    if error: await msg.edit_text(f"❌ 侦察查询失败: {error}"); os.remove(old_file_path); return

    total_new_size = data.get('size', 0)
    if total_new_size == 0: await msg.edit_text("✅ 未发现新数据。缓存已是最新。"); os.remove(old_file_path); return
    
    new_results = set(); stop_flag = f'stop_job_{chat_id}'
    pages_to_fetch = (total_new_size + 9999) // 10000
    for page in range(1, pages_to_fetch + 1):
        if context.bot_data.get(stop_flag): await msg.edit_text("🌀 增量更新已手动停止。"); os.remove(old_file_path); return
        await msg.edit_text(f"3/5: 正在下载新数据... ( Page {page}/{pages_to_fetch} )")
        data, _, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, incremental_query, page=page, page_size=10000))
        if error: await msg.edit_text(f"❌ 下载新数据失败: {error}"); os.remove(old_file_path); return
        if data.get('results'): new_results.update(data.get('results', []))

    await msg.edit_text(f"4/5: 正在合并数据... (发现 {len(new_results)} 条新数据)")
    combined_results = sorted(list(new_results.union(old_results)), reverse=True)
    
    output_filename = f"fofa_updated_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(combined_results))
    await msg.edit_text(f"5/5: 发送更新后的文件... (共 {len(combined_results)} 条)")
    with open(output_filename, 'rb') as doc: sent_message = await bot.send_document(chat_id, document=doc, filename=output_filename)
    
    cache_data = {'file_id': sent_message.document.file_id, 'file_unique_id': sent_message.document.file_unique_id, 'file_name': output_filename, 'result_count': len(combined_results)}
    add_or_update_query(base_query, cache_data)
    
    os.remove(old_file_path); os.remove(output_filename)
    await msg.delete()
    await bot.send_message(chat_id, f"✅ 增量更新完成！")


async def main() -> None:
    try:
        encoded_token = 'ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw=='
        TELEGRAM_BOT_TOKEN = base64.b64decode(encoded_token).decode('utf-8')
    except Exception as e: logger.error(f"无法解码 Bot Token！错误: {e}"); return
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    
    shutdown_event = asyncio.Event()
    application.bot_data['shutdown_event'] = shutdown_event

    settings_conv = ConversationHandler(entry_points=[CommandHandler("settings", settings_command)], states={ STATE_SETTINGS_MAIN: [CallbackQueryHandler(settings_callback_handler, pattern=r"^settings_")], STATE_SETTINGS_ACTION: [CallbackQueryHandler(settings_action_handler, pattern=r"^action_")], STATE_GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)], STATE_GET_PROXY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_proxy)], STATE_REMOVE_API: [MessageHandler(filters.TEXT & ~filters.COMMAND, remove_api)], }, fallbacks=[CommandHandler("cancel", cancel), CallbackQueryHandler(settings_command, pattern=r"^settings_back_main$")])
    kkfofa_conv = ConversationHandler(entry_points=[CommandHandler("kkfofa", kkfofa_command)], states={ STATE_CACHE_CHOICE: [CallbackQueryHandler(cache_choice_callback, pattern=r"^cache_")], STATE_KKFOFA_MODE: [CallbackQueryHandler(query_mode_callback, pattern=r"^mode_")], }, fallbacks=[CommandHandler("cancel", cancel)])
    
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("stop", stop_all_tasks))
    application.add_handler(CommandHandler("backup", backup_config_command))
    application.add_handler(CommandHandler("restore", restore_config_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("import", import_command))
    application.add_handler(CommandHandler("getlog", get_log_command))
    application.add_handler(CommandHandler("shutdown", shutdown_command))
    application.add_handler(settings_conv)
    application.add_handler(kkfofa_conv)
    application.add_handler(MessageHandler(filters.REPLY & filters.Document.FileExtension("txt"), refresh_cache_from_reply))
    application.add_handler(MessageHandler(filters.Document.FileExtension("json"), receive_config_file))
    
    async with application:
        await application.bot.set_my_commands([ 
            BotCommand("start", "🚀 启动机器人"), BotCommand("kkfofa", "🔍 资产搜索"), 
            BotCommand("settings", "⚙️ 设置"), BotCommand("history", "🕰️ 查询历史"), 
            BotCommand("import", "🖇️ 导入旧缓存"), BotCommand("backup", "📤 备份配置"), 
            BotCommand("restore", "📥 恢复配置"), BotCommand("getlog", "📄 获取日志"),
            BotCommand("shutdown", "🔌 关闭机器人"), BotCommand("stop", "🛑 停止任务"), 
            BotCommand("help", "❓ 帮助"), BotCommand("cancel", "❌ 取消操作")])
        
        logger.info("🚀 机器人已启动...")
        await application.start()
        await application.updater.start_polling()
        
        await shutdown_event.wait()
        
        logger.info("正在停止 Updater...")
        await application.updater.stop()
        logger.info("正在停止 Application...")
        await application.stop()

    logger.info("机器人已安全关闭。")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("程序被强制退出。")

