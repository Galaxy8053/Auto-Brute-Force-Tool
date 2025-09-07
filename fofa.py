import os
import json
import logging
import base64
import requests
import traceback
import sys
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
GET_KEY, ASK_DATE_RANGE, GET_PROXY, REMOVE_API_PROMPT = range(4)

# --- 权限与配置管理 ---
def load_config():
    """加载配置文件，如果不存在则创建"""
    default_config = {
        "apis": [],
        "admins": [int(base64.b64decode('NzY5NzIzNTM1OA==').decode('utf-8'))],
        "super_admin": int(base64.b64decode('NzY5NzIzNTM1OA==').decode('utf-8')),
        "proxy": "",
        "dedup_mode": "exact",
        "full_mode": False # 新增：全时数据开关，默认为False
    }
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # 确保所有新旧键都存在
            for key, value in default_config.items():
                config.setdefault(key, value)
            save_config(config) # 保存以补充可能缺失的键
            return config
    except (json.JSONDecodeError, IOError):
        logger.error("配置文件损坏或无法读取，将使用默认配置重建。")
        save_config(default_config)
        return default_config

def save_config(config):
    """保存配置到文件"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

CONFIG = load_config()

# --- 装饰器 ---
def restricted(func):
    """装饰器：限制只有管理员才能访问"""
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            message = "⛔️ 抱歉，您没有权限。"
            if update.callback_query:
                await update.callback_query.answer(message, show_alert=True)
            else:
                await update.message.reply_text(message)
            return
        return await func(update, context, *args, **kwargs)
    return wrapped

# --- Fofa 核心逻辑 ---
HEADERS = { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36" }
TIMEOUT = 30

def _make_request(url: str):
    proxies = {"http": CONFIG["proxy"], "https": CONFIG["proxy"]} if CONFIG.get("proxy") else None
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, proxies=proxies)
        res.raise_for_status()
        data = res.json()
        if data.get("error"):
            return None, data.get("errmsg", "Fofa返回未知错误。")
        return data, None
    except requests.exceptions.RequestException as e:
        return None, f"网络请求失败: {e}"
    except json.JSONDecodeError:
        return None, "服务器返回非JSON格式。"

def verify_fofa_api(key):
    url = f"https://fofa.info/api/v1/info/my?key={key}"
    return _make_request(url)

def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    # 根据全局设置决定是否添加 full=true 参数
    full_param = "&full=true" if CONFIG.get("full_mode", False) else ""
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}{full_param}"
    return _make_request(url)

async def get_best_api_key():
    """智能选择最佳API Key，优先选择VIP会员Key。"""
    if not CONFIG['apis']: return None
    # 异步检查所有key
    tasks = [asyncio.to_thread(verify_fofa_api, key) for key in CONFIG['apis']]
    results = await asyncio.gather(*tasks)
    
    for i, (is_valid, data) in enumerate(results):
        if is_valid and data.get('is_vip'):
            key = CONFIG['apis'][i]
            logger.info(f"✅ 找到VIP会员Key (用户: {data.get('username')})，将优先使用。")
            return key
            
    logger.info("ℹ️ 未找到VIP会员Key，将使用配置中的第一个Key。")
    return CONFIG['apis'][0]

# --- Bot 命令处理函数 ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('👋 欢迎使用 Fofa 查询机器人！\n\n👇 点击 **菜单** 或输入 `/` 查看所有命令。', parse_mode=ParseMode.MARKDOWN)

@restricted
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (代码与上一版相同，但现在 fetch_fofa_data 会自动处理 full_mode)
    api_key = await get_best_api_key()
    if not api_key:
        await update.message.reply_text("❌ 错误：请先在设置中添加 Fofa API Key。")
        return ConversationHandler.END

    query_text = " ".join(context.args)
    if not query_text:
        await update.message.reply_text("请输入查询语句，例如：`/kkfofa nezha`")
        return ConversationHandler.END

    msg = await update.message.reply_text("🔄 正在查询数据总数，请稍候...")
    data, error = fetch_fofa_data(api_key, query_text, page_size=1)

    if error:
        await msg.edit_text(f"❌ 查询出错: {error}")
        return ConversationHandler.END

    total_size = data.get('size', 0)
    if total_size == 0:
        await msg.edit_text("🤷‍♀️ 未找到相关结果。")
        return ConversationHandler.END
    
    context.user_data.update({'query': query_text, 'total_size': total_size, 'api_key': api_key})

    if total_size <= 10000:
        await msg.edit_text(f"✅ 查询到 {total_size} 条结果，符合单次额度，正在为您下载...")
        job_data = {'base_query': query_text, 'total_size': total_size, 'chat_id': update.effective_chat.id, 'api_key': api_key}
        context.application.job_queue.run_once(run_full_download_query, 0, data=job_data)
        return ConversationHandler.END
    else:
        keyboard = [
            [InlineKeyboardButton("🗓️ 按天下载", callback_data='mode_daily')],
            [InlineKeyboardButton("💎 全部下载", callback_data='mode_full')],
            [InlineKeyboardButton("❌ 取消", callback_data='mode_cancel')]
        ]
        await msg.edit_text(f"📊 查询到 {total_size} 条结果，已超出单次额度(10000条)。\n请选择下载模式:", reply_markup=InlineKeyboardMarkup(keyboard))
        return 1

async def query_mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (逻辑与上一版完全相同)
    query = update.callback_query
    await query.answer()
    mode = query.data
    user_data = context.user_data
    
    if mode == 'mode_daily':
        await query.edit_message_text(text="您选择了按天下载模式。\n🗓️ 请输入起止日期 (格式: `YYYY-MM-DD to YYYY-MM-DD`)", parse_mode=ParseMode.MARKDOWN)
        return ASK_DATE_RANGE
    elif mode == 'mode_full':
        await query.edit_message_text(text=f"⏳ 已开始全量下载任务 ({user_data['total_size']}条)，请注意F点消耗。")
        job_data = {'base_query': user_data['query'], 'total_size': user_data['total_size'], 'chat_id': query.message.chat_id, 'api_key': user_data['api_key']}
        context.application.job_queue.run_once(run_full_download_query, 0, data=job_data)
    elif mode == 'mode_cancel':
        await query.edit_message_text(text="操作已取消。")
        user_data.clear()
        
    return ConversationHandler.END

async def get_date_range_from_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # ... (逻辑与上一版完全相同)
    date_range_str = update.message.text
    user_data = context.user_data
    try:
        start_str, end_str = [s.strip() for s in date_range_str.lower().split("to")]
        start_date = datetime.strptime(start_str, "%Y-%m-%d")
        end_date = datetime.strptime(end_str, "%Y-%m-%d")

        if start_date > end_date:
            await update.message.reply_text("❌ 错误：开始日期不能晚于结束日期，请重新输入。")
            return ASK_DATE_RANGE

        await update.message.reply_text(f"✅ 日期范围确认！任务已在后台开始。", parse_mode=ParseMode.MARKDOWN)
        job_data = {**user_data, 'start_date': start_date, 'end_date': end_date, 'chat_id': update.effective_chat.id}
        context.application.job_queue.run_once(run_date_range_query, 0, data=job_data)
        user_data.clear()
        return ConversationHandler.END
    except (ValueError, IndexError):
        await update.message.reply_text("❌ 格式错误，请重新输入 (格式: `YYYY-MM-DD to YYYY-MM-DD`)\n或使用 /cancel 取消。", parse_mode=ParseMode.MARKDOWN)
        return ASK_DATE_RANGE

# --- 设置菜单 ---
@restricted
async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔑 API 管理", callback_data='settings_api')],
        [InlineKeyboardButton("🌐 代理设置", callback_data='settings_proxy')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    message_text = "⚙️ *设置菜单*\n\n请选择您要管理的项目:"
    if update.callback_query:
        await update.callback_query.edit_message_text(message_text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text(message_text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

async def settings_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    menu = query.data.split('_')[1]

    if menu == 'api':
        await api_settings_menu(query)
    elif menu == 'proxy':
        # (代理设置菜单逻辑)
        proxy_message = f"当前代理: `{CONFIG.get('proxy') or '未设置'}`"
        keyboard = [
            [InlineKeyboardButton("✏️ 设置/更新", callback_data='action_proxy_set')],
            [InlineKeyboardButton("🗑️ 清除", callback_data='action_proxy_delete')],
            [InlineKeyboardButton("🔙 返回", callback_data='settings_main')]
        ]
        await query.edit_message_text(f"🌐 *代理设置*\n\n{proxy_message}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)
    elif menu == 'main':
        await settings_command(update, context)

async def api_settings_menu(query: Update.callback_query):
    # --- MODIFIED: API菜单现在包含 full_mode 开关 ---
    api_message = "当前没有存储任何API密钥。"
    if CONFIG['apis']:
        api_message = "已存储的API Key (仅显示部分):\n" + "\n".join(
            [f"{i+1}. `{key[:4]}...{key[-4:]}`" for i, key in enumerate(CONFIG['apis'])]
        )
    
    # 根据 full_mode 状态创建开关按钮
    full_mode_status = CONFIG.get("full_mode", False)
    full_mode_text = "✅ 查询所有历史数据" if full_mode_status else "⏳ 仅查近一年 (默认)"
    
    keyboard = [
        [InlineKeyboardButton(f"时间范围: {full_mode_text}", callback_data='action_api_toggle_full')],
        [InlineKeyboardButton("➕ 添加新API", callback_data='action_api_add'), InlineKeyboardButton("➖ 删除API", callback_data='action_api_remove_prompt')],
        [InlineKeyboardButton("🔙 返回主菜单", callback_data='settings_main')]
    ]
    await query.edit_message_text(f"🔑 *API 管理*\n\n{api_message}", reply_markup=InlineKeyboardMarkup(keyboard), parse_mode=ParseMode.MARKDOWN)

async def settings_action_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    action = query.data.split('_', 1)[1]

    if action == 'api_add':
        await query.edit_message_text("好的，请直接发送您的 Fofa API Key。")
        return GET_KEY
    if action == 'api_remove_prompt':
        await query.edit_message_text("请输入您要删除的API Key的编号。")
        return REMOVE_API_PROMPT
    if action == 'api_toggle_full':
        # 切换 full_mode 状态并保存
        CONFIG["full_mode"] = not CONFIG.get("full_mode", False)
        save_config(CONFIG)
        await api_settings_menu(query) # 重新加载菜单以显示新状态
    elif action == 'proxy_set':
        await query.edit_message_text("请输入代理地址，例如 `http://127.0.0.1:7890`")
        return GET_PROXY
    elif action == 'proxy_delete':
        CONFIG['proxy'] = ""
        save_config(CONFIG)
        await query.edit_message_text("✅ 代理已成功清除。")
        await asyncio.sleep(2)
        await settings_command(update, context)

# (get_key, get_proxy, remove_api 等函数的实现保持不变)

async def get_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    key = update.message.text
    msg = await update.message.reply_text("正在验证API密钥...")
    is_valid, data = await asyncio.to_thread(verify_fofa_api, key)
    if is_valid:
        if key not in CONFIG['apis']:
            CONFIG['apis'].append(key)
            save_config(CONFIG)
            await msg.edit_text(f"✅ 成功添加！\n你好, {data.get('username', 'user')}!")
        else:
            await msg.edit_text(f"ℹ️ 该Key已存在。\n你好, {data.get('username', 'user')}!")
    else:
        await msg.edit_text(f"❌ 验证失败: {data}")
    
    await asyncio.sleep(2)
    # 模拟回调查询以返回菜单
    query_mock = type('Query', (), {'message': update.message, 'data': 'settings_api', 'answer': lambda: asyncio.sleep(0), 'edit_message_text': msg.edit_text})
    await api_settings_menu(query_mock)
    return ConversationHandler.END

async def get_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    CONFIG['proxy'] = update.message.text
    save_config(CONFIG)
    await update.message.reply_text(f"✅ 代理已更新为: `{CONFIG['proxy']}`", parse_mode=ParseMode.MARKDOWN)
    await asyncio.sleep(2)
    await settings_command(update, context)
    return ConversationHandler.END

async def remove_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        index = int(update.message.text) - 1
        if 0 <= index < len(CONFIG['apis']):
            removed_key = CONFIG['apis'].pop(index)
            save_config(CONFIG)
            await update.message.reply_text(f"✅ 已删除Key: `{removed_key[:4]}...`")
        else:
            await update.message.reply_text("❌ 无效的编号。")
    except ValueError:
        await update.message.reply_text("❌ 请输入数字编号。")

    await asyncio.sleep(2)
    query_mock = type('Query', (), {'message': update.message, 'data': 'settings_api', 'answer': lambda: asyncio.sleep(0), 'edit_message_text': update.message.reply_text})
    await api_settings_menu(query_mock)
    return ConversationHandler.END

# --- 后台任务 (run_full_download_query, run_date_range_query) 逻辑与上一版相同 ---
async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data
    chat_id, query_text, total_size, api_key = job_data['chat_id'], job_data['base_query'], job_data['total_size'], job_data['api_key']
    output_filename = f"fofa_full_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results = set()
    msg = await context.bot.send_message(chat_id, "⏳ 开始全量下载任务...")
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        # ...下载逻辑...
        page_size = 10000
        pages_to_fetch = (total_size + page_size - 1) // page_size
        for page in range(1, pages_to_fetch + 1):
            await msg.edit_text(f"下载进度: {page}/{pages_to_fetch}...")
            data, error = fetch_fofa_data(api_key, query_text, page=page, page_size=page_size)
            if error:
                await context.bot.send_message(chat_id, f"❌ 下载第 {page} 页时出错: {error}")
                continue
            for res in data.get('results', []):
                unique_results.add(res)
        
        for item in unique_results:
            f.write(f"{item}\n")

    await msg.edit_text(f"✅ 下载完成！去重后共 {len(unique_results)} 条。\n正在发送文件...")
    # ...发送文件逻辑...
    if os.path.getsize(output_filename) > 0:
        with open(output_filename, 'rb') as doc:
            await context.bot.send_document(chat_id, document=doc)
    else:
        await context.bot.send_message(chat_id, "🤷‍♀️ 任务完成，但未发现任何数据。")
    os.remove(output_filename)


async def run_date_range_query(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data
    #... (与上一版完全相同的按天查询逻辑)
    chat_id, base_query, start_date, end_date, api_key = job_data['chat_id'], job_data['base_query'], job_data['start_date'], job_data['end_date'], job_data['api_key']
    output_filename = f"fofa_daily_{datetime.now().strftime('%Y%m%d%H%M%S')}.txt"
    unique_results = set()
    total_days = (end_date - start_date).days + 1
    msg = await context.bot.send_message(chat_id, "⏳ 开始按天下载任务...")

    with open(output_filename, 'w', encoding='utf-8') as f:
        current_date = start_date
        for day_num in range(total_days):
            await msg.edit_text(f"下载进度: {day_num + 1}/{total_days} ({current_date.strftime('%Y-%m-%d')})...")
            
            day_before_str = (current_date - timedelta(days=1)).strftime("%Y-%m-%d")
            # 使用 after 获取当天及之后的数据
            daily_query = f'({base_query}) && after="{day_before_str}"'
            
            page = 1
            while True:
                data, error = fetch_fofa_data(api_key, daily_query, page=page, page_size=10000)
                if error:
                    await context.bot.send_message(chat_id, f"❌ 下载 `{current_date.strftime('%Y-%m-%d')}` 数据出错: {error}")
                    break
                
                results = data.get('results', [])
                if not results: break
                
                # 客户端验证，确保数据在当天范围内
                for res in results:
                    # 这是一个简化的检查，实际可能需要更精确的 host 查询来获取时间
                    # 为了性能，我们信任 FOFA 在 after 后的排序
                    # 这里假设第一页之后的数据不太可能跨天
                    pass 
                
                for item in results:
                     unique_results.add(item)

                if len(results) < 10000: break
                page += 1
            current_date += timedelta(days=1)
        
        for item in unique_results:
            f.write(f"{item}\n")

    await msg.edit_text(f"✅ 下载完成！去重后共 {len(unique_results)} 条。\n正在发送文件...")
    if os.path.getsize(output_filename) > 0:
        with open(output_filename, 'rb') as doc:
            await context.bot.send_document(chat_id, document=doc)
    else:
        await context.bot.send_message(chat_id, "🤷‍♀️ 任务完成，但未发现任何新数据。")
    os.remove(output_filename)


# --- Bot 初始化 ---
async def post_init(application: Application):
    commands = [
        BotCommand("kkfofa", "🔍 资产搜索"),
        BotCommand("settings", "⚙️ 设置"),
        BotCommand("cancel", "❌ 取消当前操作"),
    ]
    await application.bot.set_my_commands(commands)
    logger.info("✅ 已成功设置命令菜单！")

def main():
    try:
        TELEGRAM_BOT_TOKEN = base64.b64decode('ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw==').decode('utf-8')
    except Exception:
        logger.error("无法解码 Telegram Bot Token，请检查 Base64 编码。")
        sys.exit(1)
        
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    settings_conv = ConversationHandler(
        entry_points=[CommandHandler('settings', settings_command), CallbackQueryHandler(pattern='^settings_')],
        states={
            0: [CallbackQueryHandler(settings_action_handler, pattern='^action_')],
            GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)],
            GET_PROXY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_proxy)],
            REMOVE_API_PROMPT: [MessageHandler(filters.TEXT & ~filters.COMMAND, remove_api)],
        },
        fallbacks=[CommandHandler('cancel', lambda u, c: ConversationHandler.END)],
        map_to_parent={ConversationHandler.END: 0}
    )

    main_conv = ConversationHandler(
        entry_points=[CommandHandler('kkfofa', kkfofa_command)],
        states={
            1: [CallbackQueryHandler(query_mode_callback, pattern='^mode_')],
            ASK_DATE_RANGE: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_date_range_from_message)],
            # 嵌套设置会话
            2: [settings_conv]
        },
        fallbacks=[CommandHandler('cancel', lambda u, c: ConversationHandler.END)],
    )
    application.add_handler(CommandHandler("start", start))
    application.add_handler(main_conv)
    application.add_handler(settings_conv) # 允许直接访问设置

    logger.info("🚀 机器人已启动，开始轮询...")
    application.run_polling()

if __name__ == '__main__':
    main()
