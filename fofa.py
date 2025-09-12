import os
import json
import logging
import base64
import requests
import asyncio
from datetime import datetime
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
    filters,
    JobQueue
)
from pytz import timezone
import tzlocal

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logging.getLogger("telegram.ext").addFilter(lambda record: "PTBUserWarning" not in record.getMessage())
logger = logging.getLogger(__name__)

CONFIG_FILE = 'config.json'
(
    STATE_KKFOFA_MODE,
    STATE_SETTINGS_MAIN,
    STATE_SETTINGS_ACTION,
    STATE_GET_KEY,
    STATE_GET_PROXY,
    STATE_REMOVE_API,
) = range(6)

def load_config():
    default_admin_id = int(base64.b64decode('NzY5NzIzNTM1OA==').decode('utf-8'))
    default_config = { "apis": []， "admins": [default_admin_id]， "proxy": "", "full_mode": False }
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config); return default_config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            for key, value 在 default_config.items(): config.setdefault(key, value)
            save_config(config); return config
    except (json.JSONDecodeError, IOError):
        logger.error("配置文件损坏，将使用默认配置重建。")
        save_config(default_config); return default_config

def save_config(config):
    with open(CONFIG_FILE, 'w') as f: json.dump(config, f, indent=4)

CONFIG = load_config()

def escape_markdown(text: str) -> str:
    escape_chars = '_*`['
    return ""。join(['\\' + char if char in escape_chars else char for char in text])

def get_system_timezone_name():
    try:
        tz_name = tzlocal.get_localzone_name()
        timezone(tz_name)
        return tz_name
    except Exception as e:
        logger.warning(f"无法自动检测时区: {e}。将默认使用 UTC。")
        return 'UTC'

def restricted(func):
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not 在 CONFIG.get('admins'， []):
            message = "⛔️ 抱歉，您没有权限。"
            if update.callback_query: await update.callback_query.answer(message, show_alert=True)
            else: await update.message.reply_text(message)
            return ConversationHandler.END if isinstance(context.handler, ConversationHandler) else None
        return await func(update, context, *args, **kwargs)
    return wrapped

HEADERS = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36" }

def _make_request(url: str):
    proxies = {"http": CONFIG["proxy"]， "https": CONFIG["proxy"]} if CONFIG.get("proxy") else None
    try:
        res = requests.get(url, headers=HEADERS, timeout=30, verify=False, proxies=proxies)
        res.raise_for_status()
        data = res.json()
        if data.get("error"): return 无, data.get("errmsg", "未知错误")
        return data, 无
    except requests.exceptions.RequestException as e: return 无， f"网络请求失败: {e}"
    except json.JSONDecodeError: return 无, "服务器返回非JSON格式。"

def verify_fofa_api(key):
    return _make_request(f"https://fofa.info/api/v1/info/my?key={key}")

def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    b64_query = base64.b64encode(query.encode('utf-8'))。decode('utf-8')
    full_param = "&full=true" if CONFIG.get("full_mode", False) else ""
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}{full_param}"
    return _make_request(url)

async def execute_query_with_fallback(query_func, preferred_key_index=无):
    if not CONFIG['apis']: return 无, 无, "没有配置任何API Key。"
    tasks = [asyncio.to_thread(verify_fofa_api, key) for key 在 CONFIG['apis']]
    results = await asyncio.gather(*tasks)
    valid_keys = []
    for i, (data, error) in enumerate(results):
        if not error and data: valid_keys.append({'key': CONFIG['apis'][i], 'index': i + 1, 'is_vip': data.get('is_vip', False)})
    if not valid_keys: return None, None, "所有API Key均无效或验证失败"
    prioritized_keys = sorted(valid_keys, key=lambda x: x['is_vip'], reverse=True)
    keys_to_try = prioritized_keys
    if preferred_key_index is not None:
        start_index = next((i for i, k in enumerate(prioritized_keys) if k['index'] == preferred_key_index), -1)
        if start_index != -1: keys_to_try = prioritized_keys[start_index:] + prioritized_keys[:start_index]
    last_error = "没有可用的API Key。"
    for key_info in keys_to_try:
        data, error = await asyncio.to_thread(query_func, key_info['key'])
        if not error: return data, key_info['index'], None
        last_error = error
        if "[820031]" in str(error):
            logger.warning(f"Key [#{key_info['index']}] F点不足，尝试下一个...")
            continue
        return None, key_info['index'], error
    return None, None, f"所有Key均尝试失败，最后错误: {last_error}"

def get_stop_flag_name(chat_id):
    return f'stop_job_{chat_id}'

async def stop_all_tasks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    stop_flag = get_stop_flag_name(chat_id)
    context.bot_data[stop_flag] = True
    await update.message.reply_text("✅ 已发送停止信号。后台任务将在当前循环结束后停止。")

async def start_download_job(context: ContextTypes.DEFAULT_TYPE, callback_func, job_data):
    chat_id = job_data['chat_id']
    job_name = f"download_job_{chat_id}"
    current_jobs = context.job_queue.get_jobs_by_name(job_name)
    for job in current_jobs: job.schedule_removal()
    stop_flag = get_stop_flag_name(chat_id)
    context.bot_data.pop(stop_flag, None)
    context.job_queue.run_once(callback_func, 1, data=job_data, name=job_name)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('👋 欢迎使用 Fofa 查询机器人！请使用 /help 查看命令手册。')
    if not CONFIG.get('admins'): CONFIG['admins'] = []
    if update.effective_user.id not in CONFIG['admins']:
        CONFIG['admins'].append(update.effective_user.id)
        save_config(CONFIG)
        await update.message.reply_text("ℹ️ 已自动将您添加为管理员。")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = "📖 *Fofa 机器人指令手册*\n\n*🔍 资产查询*\n`/kkfofa [key编号] <查询语句>`\n\n*⚙️ 管理与设置*\n`/settings`\n\n*🛑 停止任务*\n`/stop`\n\n*❌ 取消操作*\n`/cancel`"
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@restricted
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if not args: await update.message.reply_text("用法: `/kkfofa [key编号] <查询语句>`"); return ConversationHandler.END
    key_index, query_text = None, ""
    try:
        key_index = int(args[0]);
        if not (1 <= key_index <= len(CONFIG['apis'])) or len(args) < 2: await update.message.reply_text(f"❌ Key编号无效或缺少查询语句。"); return ConversationHandler.END
        query_text = " ".join(args[1:])
    except (ValueError, IndexError): query_text = " ".join(args)
    msg = await update.message.reply_text("🔄 正在查询...")
    query_func = lambda key: fetch_fofa_data(key, query_text, 1, 1, "host")
    data, used_key_index, error = await execute_query_with_fallback(query_func, key_index)
    if error: await msg.edit_text(f"❌ 查询出错: {error}"); return ConversationHandler.END
    total_size = data.get('size', 0)
    if total_size == 0: await msg.edit_text("🤷‍♀️ 未找到结果。"); return ConversationHandler.END
    context.user_data.update({'query': query_text, 'total_size': total_size, 'chat_id': update.effective_chat.id})
    success_message = f"✅ 使用 Key [#{used_key_index}] 找到 {total_size} 条结果。"
    if total_size <= 10000:
        await msg.edit_text(f"{success_message}\n开始下载..."); await start_download_job(context, run_full_download_query, context.user_data); return ConversationHandler.END
    else:
        # **修复：确保 callback_data 格式一致**
        keyboard = [[InlineKeyboardButton("💎 全部下载", callback_data='mode_full'), InlineKeyboardButton("🌀 深度追溯下载", callback_data='mode_traceback')], [InlineKeyboardButton("❌ 取消", callback_data='mode_cancel')]]
        await msg.edit_text(f"{success_message}\n请选择下载模式:", reply_markup=InlineKeyboardMarkup(keyboard)); return STATE_KKFOFA_MODE

# **修复：修正 split 的索引**
async def query_mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer(); mode = query.data.split('_')[1] # 使用索引 1
    if mode == 'full': await query.edit_message_text(f"⏳ 开始全量下载任务..."); await start_download_job(context, run_full_download_query, context.user_data)
    elif mode == 'traceback': await query.edit_message_text(f"⏳ 开始深度追溯下载任务..."); await start_download_job(context, run_traceback_download_query, context.user_data)
    elif mode == 'cancel': await query.edit_message_text("操作已取消。")
    return ConversationHandler.END

@restricted
async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("🔑 API 管理", callback_data='settings_api')], [InlineKeyboardButton("🌐 代理设置", callback_data='settings_proxy')]]
    message_text = "⚙️ *设置菜单*";
    if update.callback_query: await update.callback_query.edit_message_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    else: await update.message.reply_text(message_text, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    return STATE_SETTINGS_MAIN

# ... (settings functions remain the same)
async def settings_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer(); menu = query.data.split('_')[1]
    if menu == 'api': return await show_api_menu(update, context)
    elif menu == 'proxy': return await show_proxy_menu(update, context)
async def show_api_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        msg = await (update.callback_query.edit_message_text if update.callback_query else update.message.reply_text)("🔄 正在查询API Key状态...")
        api_details = []
        if CONFIG['apis']:
            tasks = [asyncio.to_thread(verify_fofa_api, key) for key in CONFIG['apis']]; results = await asyncio.gather(*tasks)
            for i, (data, error) in enumerate(results):
                key_masked = f"`{CONFIG['apis'][i][:4]}...{CONFIG['apis'][i][-4:]}`"; status = f"❌ 无效或出错: {error}"
                if not error and data:
                    user = escape_markdown(data.get('username', 'N/A')); is_vip = "✅ VIP" if data.get('is_vip') else "👤 普通"; fcoin = data.get('fcoin', 0)
                    status = f"({user}, {is_vip}, F币: {fcoin})"
                api_details.append(f"{i+1}. {key_masked} {status}")
        api_message = "\n".join(api_details) if api_details else "目前没有存储任何API密钥。"
        full_mode_text = "✅ 查询所有历史" if CONFIG.get("full_mode") else "⏳ 仅查近一年"
        keyboard = [[InlineKeyboardButton(f"时间范围: {full_mode_text}", callback_data='action_toggle_full')], [InlineKeyboardButton("➕ 添加", callback_data='action_add_api'), InlineKeyboardButton("➖ 删除", callback_data='action_remove_api')], [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]]
        await msg.edit_text(f"🔑 *API 管理*\n\n{api_message}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
        return STATE_SETTINGS_ACTION
    except Exception as e:
        logger.error(f"显示 API 菜单时出错: {e}", exc_info=True); await context.bot.send_message(update.effective_chat.id, "显示菜单时发生内部错误。"); return ConversationHandler.END
async def show_proxy_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[InlineKeyboardButton("✏️ 设置/更新", callback_data='action_set_proxy')], [InlineKeyboardButton("🗑️ 清除", callback_data='action_delete_proxy')], [InlineKeyboardButton("🔙 返回主菜单", callback_data='action_back_main')]]
    await update.callback_query.edit_message_text(f"🌐 *代理设置*\n当前: `{CONFIG.get('proxy') or '未设置'}`", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN); return STATE_SETTINGS_ACTION
async def settings_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query; await query.answer(); action = query.data.split('_', 1)[1]
    if action == 'back_main': return await settings_command(update, context)
    elif action == 'toggle_full': CONFIG["full_mode"] = not CONFIG.get("full_mode", False); save_config(CONFIG); return await show_api_menu(update, context)
    elif action == 'add_api': await query.edit_message_text("请发送您的 Fofa API Key。"); return STATE_GET_KEY
    elif action == 'remove_api':
        if not CONFIG['apis']: await query.message.reply_text("没有可删除的API Key。"); return await show_api_menu(update, context)
        await query.edit_message_text("请回复要删除的API Key编号。"); return STATE_REMOVE_API
    elif action == 'set_proxy': await query.edit_message_text("请输入代理地址。"); return STATE_GET_PROXY
    elif action == 'delete_proxy': CONFIG['proxy'] = ""; save_config(CONFIG); await query.edit_message_text("✅ 代理已清除。"); await asyncio.sleep(1); return await settings_command(update, context)
async def get_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key = update.message.text.strip(); msg = await update.message.reply_text("正在验证...")
    data, error = await asyncio.to_thread(verify_fofa_api, key)
    if not error and data:
        if key not in CONFIG['apis']: CONFIG['apis'].append(key); save_config(CONFIG); await msg.edit_text(f"✅ 添加成功！你好, {escape_markdown(data.get('username', 'user'))}!", parse_mode=ParseMode.MARKDOWN)
        else: await msg.edit_text(f"ℹ️ 该Key已存在。")
    else: await msg.edit_text(f"❌ 验证失败: {error}")
    await asyncio.sleep(2); await msg.delete(); return await show_api_menu(update, context)
async def get_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    CONFIG['proxy'] = update.message.text.strip(); save_config(CONFIG); await update.message.reply_text(f"✅ 代理已更新。"); await asyncio.sleep(1)
    class DummyUpdate: callback_query = type('Q',(),{'answer':(lambda:None),'edit_message_text':(lambda*a,**kw:update.message.reply_text(*a,**kw))})()
    return await show_proxy_menu(DummyUpdate(), context)
async def remove_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        index = int(update.message.text) - 1
        if 0 <= index < len(CONFIG['apis']): CONFIG['apis'].pop(index); save_config(CONFIG); await update.message.reply_text(f"✅ 已删除。")
        else: await update.message.reply_text("❌ 无效编号。")
    except (ValueError, IndexError): await update.message.reply_text("❌ 请输入数字。")
    await asyncio.sleep(1); return await show_api_menu(update, context)

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.callback_query: await update.callback_query.edit_message_text('操作已取消。')
    else: await update.message.reply_text('操作已取消。')
    context.user_data.clear(); return ConversationHandler.END

async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; chat_id, query_text, total_size = job_data['chat_id'], job_data['query'], job_data['total_size']
    output_filename = f"fofa_full_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"; unique_results = set()
    msg = await context.bot.send_message(chat_id, "⏳ 开始全量下载任务..."); pages_to_fetch = (total_size + 9999) // 10000
    stop_flag = get_stop_flag_name(chat_id)
    for page in range(1, pages_to_fetch + 1):
        if context.bot_data.get(stop_flag): await msg.edit_text("🌀 下载任务已手动停止."); break
        try: await msg.edit_text(f"下载进度: {len(unique_results)}/{total_size} (Page {page}/{pages_to_fetch})...")
        except: pass
        data, _, error = await execute_query_with_fallback(lambda key: fetch_fofa_data(key, query_text, page, 10000, "host"))
        if error:
            await msg.edit_text(f"❌ 第 {page} 页下载出错: {error}" + ("\n\n任务已因F点不足而终止。" if "[820031]" in str(error) else "")); break
        if not data.get('results'): break
        unique_results.update(data.get('results', []))
    if unique_results:
        with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(unique_results))
        await msg.edit_text(f"✅ 下载完成！共 {len(unique_results)} 条。正在发送...")
        with open(output_filename, 'rb') as doc: await context.bot.send_document(chat_id, document=doc)
        os.remove(output_filename)
    elif not context.bot_data.get(stop_flag): await msg.edit_text("🤷‍♀️ 任务完成，但未能下载到任何数据。")
    context.bot_data.pop(stop_flag, None)

async def run_traceback_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data; chat_id, base_query = job_data['chat_id'], job_data['query']
    output_filename = f"fofa_traceback_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results, page_count, last_page_timestamp, termination_reason = set(), 0, None, ""
    msg = await context.bot.send_message(chat_id, "⏳ 开始深度追溯下载...")
    current_query = base_query
    stop_flag = get_stop_flag_name(chat_id)
    while True:
        page_count += 1
        if context.bot_data.get(stop_flag): termination_reason = "\n\n🌀 任务已手动停止。"; break
        query_func = lambda key: fetch_fofa_data(key, current_query, 1, 10000, "host,mtime")
        data, _, error = await execute_query_with_fallback(query_func)
        if error:
            termination_reason = f"\n\n❌ 在第 {page_count} 轮追溯时出错: {error}" + (" (F点不足)" if "[820031]" in str(error) else "")
            break
        results = data.get('results', [])
        if not results:
            termination_reason = "\n\nℹ️ 已获取所有查询结果。"
            break
        unique_results.update([r[0] for r in results])
        try: await msg.edit_text(f"⏳ 已找到 {len(unique_results)} 条独立结果... (第 {page_count} 轮)")
        except: pass
        next_page_timestamp = results[-1][1]
        if next_page_timestamp == last_page_timestamp:
            termination_reason = "\n\n⚠️ 任务因后续结果时间戳完全相同而终止，已达数据查询边界。"
            logger.warning("追溯时间戳未变，终止任务。")
            break
        last_page_timestamp = next_page_timestamp
        current_query = f'({base_query}) && before="{next_page_timestamp}"'
    if unique_results:
        with open(output_filename, 'w', encoding='utf-8') as f: f.write("\n".join(sorted(list(unique_results))))
        final_message = f"✅ 深度追溯完成！共 {len(unique_results)} 条。{termination_reason}\n正在发送文件..."
        await msg.edit_text(final_message)
        with open(output_filename, 'rb') as doc: await context.bot.send_document(chat_id, document=doc)
        os.remove(output_filename)
    else:
        await msg.edit_text(f"🤷‍♀️ 任务完成，但未能下载到任何数据。{termination_reason}")
    context.bot_data.pop(stop_flag, None)

async def post_init(application: Application):
    await application.bot.set_my_commands([BotCommand("kkfofa", "🔍 资产搜索"), BotCommand("settings", "⚙️ 设置"), BotCommand("stop", "🛑 停止任务"), BotCommand("help", "❓ 帮助"), BotCommand("cancel", "❌ 取消")])
    logger.info("✅ 命令菜单已设置！")

def main():
    try:
        encoded_token = 'ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw=='
        TELEGRAM_BOT_TOKEN = base64.b64decode(encoded_token).decode('utf-8')
    except Exception as e:
        logger.error(f"无法解码 Bot Token！请检查Base64编码是否正确。错误: {e}")
        return
    application_builder = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init)
    system_timezone_str = get_system_timezone_name()
    logger.info(f"检测到系统时区: {system_timezone_str}")
    job_queue = JobQueue()
    job_queue.scheduler.configure(timezone=timezone(system_timezone_str))
    application = application_builder.job_queue(job_queue).build()
    conv_handler = ConversationHandler(
        # **修复：修正 pattern**
        entry_points=[CommandHandler("kkfofa", kkfofa_command), CommandHandler("settings", settings_command)],
        states={
            STATE_KKFOFA_MODE: [CallbackQueryHandler(query_mode_callback, pattern=r"^mode_")],
            STATE_SETTINGS_MAIN: [CallbackQueryHandler(settings_callback_handler, pattern=r"^settings_")],
            STATE_SETTINGS_ACTION: [CallbackQueryHandler(settings_action_handler, pattern=r"^action_")],
            STATE_GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)],
            STATE_GET_PROXY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_proxy)],
            STATE_REMOVE_API: [MessageHandler(filters.TEXT & ~filters.COMMAND, remove_api)],
        },
        fallbacks=[CommandHandler("cancel", cancel)], persistent=False, name="main_conversation"
    )
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("stop", stop_all_tasks))
    application.add_handler(conv_handler)
    logger.info("🚀 机器人已启动..."); application.run_polling()

if __name__ == '__main__':
    main()
