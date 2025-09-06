import os
import json
import logging
import base64
import requests
import urllib.parse
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

# --- 权限与配置管理 ---
def load_config():
    """加载配置文件，如果不存在则创建"""
    if not os.path.exists(CONFIG_FILE):
        encoded_super_admin_id = 'NzY5NzIzNTM1OA=='
        SUPER_ADMIN_ID = int(base64.b64decode(encoded_super_admin_id).decode('utf-8'))
        # 配置中不再存储email，只存储key
        config = {"apis": [], "admins": [SUPER_ADMIN_ID], "super_admin": SUPER_ADMIN_ID}
        save_config(config)
        return config
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

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

# --- Fofa 核心逻辑 (已移除email参数) ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36"
}
TIMEOUT = 20

def verify_fofa_api(key):
    """验证Fofa API是否有效"""
    url = f"https://fofa.info/api/v1/info/my?key={key}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        res.raise_for_status()
        data = res.json()
        return "error" not in data, data
    except requests.exceptions.RequestException as e:
        return False, {'errmsg': str(e)}

def fetch_fofa_data(key, query, page=1, page_size=10000, fields="host"):
    """从Fofa获取数据"""
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    url = f"https://fofa.info/api/v1/search/all?key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        res.raise_for_status()
        data = res.json()
        return data, data.get("errmsg")
    except requests.exceptions.RequestException as e:
        return None, str(e)


# --- Bot 命令处理函数 ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text('欢迎使用 Fofa 查询 Bot！\n点击输入框旁的 "/" 或 "菜单" 按钮查看所有可用命令。')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    help_text = """
    *Fofa查询机器人指令手册*

    `/kkfofa <查询语句>`
    核心查询命令。如果结果超过1万条，会弹出交互式菜单供您选择下载模式。

    *API管理 (仅管理员)*:
    `/addapi` - 添加一个新的Fofa API Key。
    `/root` - 查看/管理已存储的API Key。

    *权限管理 (仅超级管理员)*:
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
        if not CONFIG['apis']:
            await update.message.reply_text("当前没有存储任何API密钥。使用 `/addapi` 添加。")
            return
        message = "已存储的API Key列表 (为保护隐私，仅显示部分):\n"
        for i, key in enumerate(CONFIG['apis']):
            masked_key = key[:4] + '...' + key[-4:]
            message += f"{i+1}. `{masked_key}`\n"
        message += "\n使用 `/root remove <编号>` 来删除API Key。"
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
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

# ... (vip管理, kkfofa, 后台任务等函数的逻辑保持不变，但API调用会相应简化) ...
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
async def kkfofa_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if not CONFIG['apis']:
        await update.message.reply_text("错误：请先使用 `/addapi` 添加至少一个Fofa API。")
        return ConversationHandler.END

    api_key = CONFIG['apis'][0] # 使用第一个API Key
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
            
            context.job_queue.run_once(run_date_range_query, 0, data=job_data, name=f"date_range_{job_data['chat_id']}")
            await update.message.reply_text(f"已收到按天下载任务！\n*查询*: `{job_data['base_query']}`\n*时间*: `{job_data['start_date'].date()}` 到 `{job_data['end_date'].date()}`\n任务已在后台开始。", parse_mode=ParseMode.MARKDOWN)
        except (ValueError, IndexError):
            await update.message.reply_text("错误：日期范围格式不正确。\n请使用: `daterange:YYYY-MM-DD to YYYY-MM-DD`")
        return ConversationHandler.END


    msg = await update.message.reply_text("正在查询数据总数，请稍候...")
    
    data, error = fetch_fofa_data(api_key, query_text, page_size=1)
    if error:
        await msg.edit_text(f"查询出错: {error}")
        return ConversationHandler.END

    total_size = data.get('size', 0)
    if total_size == 0:
        await msg.edit_text("未找到相关结果。")
        return ConversationHandler.END

    context.user_data['query'] = query_text
    context.user_data['total_size'] = total_size

    if total_size <= 10000:
        await msg.edit_text(f"查询到 {total_size} 条结果，符合免费额度，正在为您下载...")
        job_data['total_size'] = total_size
        context.job_queue.run_once(run_full_download_query, 0, data=job_data, name=f"full_download_{job_data['chat_id']}")
        return ConversationHandler.END
    else:
        keyboard = [
            [InlineKeyboardButton("按天下载 (穷人模式)", callback_data='mode_daily')],
            [InlineKeyboardButton("全部下载 (消耗F点)", callback_data='mode_full')],
            [InlineKeyboardButton("仅预览前20条", callback_data='mode_preview')],
            [InlineKeyboardButton("取消", callback_data='mode_cancel')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await msg.edit_text(
            f"查询到 {total_size} 条结果，已超出免费额度(10000条)。\n请选择下载模式:",
            reply_markup=reply_markup
        )
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
        await query.edit_message_text(text="您选择了按天下载模式。\n请输入起止日期 (格式: `YYYY-MM-DD to YYYY-MM-DD`)")
        return ASK_DATE_RANGE
    
    elif mode == 'mode_full':
        await query.edit_message_text(text=f"已开始全量下载任务 ({total_size}条)，请注意这可能会消耗您的F点或会员权益。")
        job_data = {'base_query': base_query, 'total_size': total_size, 'chat_id': chat_id, 'api_key': api_key}
        context.job_queue.run_once(run_full_download_query, 0, data=job_data, name=f"full_download_{chat_id}")
        return ConversationHandler.END

    elif mode == 'mode_preview':
        data, error = fetch_fofa_data(api_key, base_query, page_size=20)
        if error:
            await query.edit_message_text(f"预览失败: {error}")
            return ConversationHandler.END
        
        results = data.get('results', [])
        message = f"*查询语句*: `{base_query}`\n*总数*: `{total_size}`\n\n*前20条预览结果*:\n"
        message += "\n".join([f"`{res[0]}`" for res in results])
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

        await update.message.reply_text(f"日期范围确认！任务已在后台开始。\n*查询*: `{base_query}`\n*时间*: `{start_date.date()}` 到 `{end_date.date()}`", parse_mode=ParseMode.MARKDOWN)
        
        job_data = {
            'chat_id': chat_id, 
            'base_query': base_query,
            'start_date': start_date,
            'end_date': end_date,
            'api_key': api_key
        }
        context.job_queue.run_once(run_date_range_query, 0, data=job_data, name=f"date_range_{chat_id}")
        context.user_data.clear()
        return ConversationHandler.END
    except (ValueError, IndexError):
        await update.message.reply_text("格式错误，请重新输入 (格式: `YYYY-MM-DD to YYYY-MM-DD`)\n或使用 /cancel 取消。")
        return ASK_DATE_RANGE


# --- 后台任务函数 ---
async def run_full_download_query(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    chat_id = job.data['chat_id']
    query_text = job.data['base_query']
    total_size = job.data['total_size']
    api_key = job.data['api_key']
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"fofa_full_{timestamp}.txt"
    
    page_size = 10000 
    pages_to_fetch = (total_size + page_size - 1) // page_size
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        for page in range(1, pages_to_fetch + 1):
            await context.bot.send_message(chat_id, f"正在下载第 {page}/{pages_to_fetch} 页...")
            data, error = fetch_fofa_data(api_key, query_text, page=page, page_size=page_size)
            if error:
                await context.bot.send_message(chat_id, f"下载第 {page} 页时出错: {error}")
                continue
            
            results = data.get('results', [])
            for res in results:
                f.write(f"{res[0]}\n")
    
    await context.bot.send_message(chat_id, "全量数据下载完成，正在发送文件...")
    try:
        with open(output_filename, 'rb') as f:
            await context.bot.send_document(chat_id, document=f)
    except Exception as e:
        await context.bot.send_message(chat_id, f"发送文件失败: {e}")
    finally:
        if os.path.exists(output_filename):
            os.remove(output_filename)

async def run_date_range_query(context: ContextTypes.DEFAULT_TYPE):
    job = context.job
    chat_id = job.data['chat_id']
    base_query = job.data['base_query']
    start_date = job.data['start_date']
    end_date = job.data['end_date']
    api_key = job.data['api_key']
    total_found, current_date = 0, start_date
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"fofa_daily_{timestamp}.txt"

    with open(output_filename, 'w', encoding='utf-8') as f:
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            daily_query = f'({base_query}) && after="{date_str}" && before="{date_str}"'
            await context.bot.send_message(chat_id, f"正在下载 `{date_str}` 的数据...", parse_mode=ParseMode.MARKDOWN)
            page, daily_count = 1, 0
            while True:
                data, error = fetch_fofa_data(api_key, daily_query, page=page, page_size=10000)
                if error:
                    await context.bot.send_message(chat_id, f"下载 `{date_str}` 数据时出错: {error}", parse_mode=ParseMode.MARKDOWN)
                    break 
                results = data.get('results', [])
                if not results: break
                for res in results:
                    f.write(f"{res[0]}\n")
                daily_count += len(results)
                if len(results) < 10000: break 
                page += 1
            await context.bot.send_message(chat_id, f"`{date_str}` 下载完成，共找到 {daily_count} 条数据。", parse_mode=ParseMode.MARKDOWN)
            total_found += daily_count
            current_date += timedelta(days=1)
    
    await context.bot.send_message(chat_id, f"所有日期下载完成！总共找到 {total_found} 条数据。\n正在发送结果文件...")
    try:
        with open(output_filename, 'rb') as f:
            await context.bot.send_document(chat_id, document=f)
    except Exception as e:
        await context.bot.send_message(chat_id, f"发送文件失败: {e}")
    finally:
        if os.path.exists(output_filename):
            os.remove(output_filename)


async def post_init(application: Application):
    """在Bot启动后设置命令菜单"""
    commands = [
        BotCommand("kkfofa", "查询Fofa"),
        BotCommand("root", "查看/管理API (仅管理员)"),
        BotCommand("addapi", "添加API (仅管理员)"),
        BotCommand("vip", "管理管理员 (仅超级管理员)"),
        BotCommand("help", "获取帮助"),
        BotCommand("cancel", "取消当前操作"),
    ]
    await application.bot.set_my_commands(commands)
    logger.info("已成功设置命令菜单！")


def main() -> None:
    """启动Bot"""
    encoded_token = 'ODMyNTAwMjg5MTpBQUZyY1UzWExXYm02c0h5bjNtWm1GOEhwMHlRbHVUUXdaaw=='
    TELEGRAM_BOT_TOKEN = base64.b64decode(encoded_token).decode('utf-8')
    
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).post_init(post_init).build()

    add_api_conv = ConversationHandler(
        entry_points=[CommandHandler('addapi', add_api_start)],
        states={
            GET_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_key)],
        },
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
    application.add_handler(CommandHandler("root", manage_api))
    application.add_handler(CommandHandler("vip", manage_vip))
    application.add_handler(kkfofa_conv)

    logger.info("Bot is running...")
    application.run_polling()

if __name__ == '__main__':
    main()
