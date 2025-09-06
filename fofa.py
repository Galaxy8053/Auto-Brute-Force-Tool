# -*- coding: utf-8 -*-
#
# 注意：此脚本为兼容旧版本 python-telegram-bot (v13.x 及更早版本) 而修改。
# 主要改动是将 ParseMode 的导入位置从 telegram.constants 改回了 telegram。
#
import os
import json
import logging
import base64
import requests
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
# 兼容性修改：将 ParseMode 从主模块导入
from telegram import Update, ParseMode, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Updater,
    CommandHandler,
    CallbackContext,
    ConversationHandler,
    MessageHandler,
    Filters,
    CallbackQueryHandler
)

# --- 基础配置 ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- 全局变量和常量 ---
CONFIG_FILE = 'config.json'

# Conversation states
EMAIL, KEY = range(2)
ASK_DATE_RANGE = range(2, 3)

# --- 权限与配置管理 ---
def load_config():
    """加载配置文件，如果不存在则创建"""
    if not os.path.exists(CONFIG_FILE):
        # 超级管理员ID (已使用Base64加密)
        encoded_super_admin_id = 'NzY5NzIzNTM1OA=='
        SUPER_ADMIN_ID = int(base64.b64decode(encoded_super_admin_id).decode('utf-8'))
        
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
    def wrapped(update: Update, context: CallbackContext, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in CONFIG.get('admins', []):
            update.message.reply_text("抱歉，您没有权限执行此命令。")
            return
        return func(update, context, *args, **kwargs)
    return wrapped

def super_admin_restricted(func):
    """装饰器：限制只有超级管理员才能访问"""
    @wraps(func)
    def wrapped(update: Update, context: CallbackContext, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id != CONFIG.get('super_admin'):
            update.message.reply_text("抱歉，只有超级管理员才能执行此命令。")
            return
        return func(update, context, *args, **kwargs)
    return wrapped

# --- Fofa 核心逻辑 ---
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/536.36"
}
TIMEOUT = 20

def verify_fofa_api(email, key):
    """验证Fofa API是否有效"""
    url = f"https://fofa.so/api/v1/info/my?email={urllib.parse.quote(email)}&key={key}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        res.raise_for_status()
        data = res.json()
        return "error" not in data, data
    except requests.exceptions.RequestException as e:
        return False, {'errmsg': str(e)}

def fetch_fofa_data(email, key, query, page=1, page_size=10000, fields="host"):
    """从Fofa获取数据"""
    b64_query = base64.b64encode(query.encode('utf-8')).decode('utf-8')
    url = f"https://fofa.so/api/v1/search/all?email={urllib.parse.quote(email)}&key={key}&qbase64={b64_query}&size={page_size}&page={page}&fields={fields}"
    try:
        res = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        res.raise_for_status()
        data = res.json()
        return data, data.get("errmsg")
    except requests.exceptions.RequestException as e:
        return None, str(e)

# --- Bot 命令处理函数 ---

def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text('欢迎使用 Fofa 查询 Bot！\n使用 /help 查看所有可用命令。')

def help_command(update: Update, context: CallbackContext) -> None:
    help_text = """
    *Fofa查询机器人指令手册*

    `/kkfofa <查询语句>`
    核心查询命令。如果结果超过1万条，会弹出交互式菜单供您选择下载模式。

    *快捷方式 (高级)*:
    `/kkfofa <查询语句> daterange:YYYY-MM-DD to YYYY-MM-DD`
    直接启动按天下载模式，无需交互。

    *API管理 (仅管理员)*:
    `/addapi` - 启动对话，添加一组新的Fofa API。
    `/root` - 查看已存储的API列表。
    `/root remove <编号>` - 删除指定的API。

    *权限管理 (仅超级管理员)*:
    `/vip` - 查看管理员列表。
    `/vip <add/remove> <用户ID>` - 添加或移除管理员。

    *通用*:
    `/help` - 显示此帮助信息。
    `/cancel` - 在添加API或输入日期范围时取消操作。
    """
    update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

@restricted
def add_api_start(update: Update, context: CallbackContext) -> int:
    update.message.reply_text("好的，请发送您的 Fofa Email 地址。")
    return EMAIL

def get_email(update: Update, context: CallbackContext) -> int:
    context.user_data['fofa_email'] = update.message.text
    update.message.reply_text("收到！现在请发送您的 Fofa API Key。")
    return KEY

def get_key(update: Update, context: CallbackContext) -> int:
    email = context.user_data['fofa_email']
    key = update.message.text
    update.message.reply_text("正在验证API密钥，请稍候...")
    is_valid, data = verify_fofa_api(email, key)
    if is_valid:
        for api in CONFIG['apis']:
            if api['email'] == email:
                api['key'] = key
                save_config(CONFIG)
                update.message.reply_text(f"成功：已更新该Email对应的API Key。\n你好, {data.get('username', 'user')}!")
                return ConversationHandler.END
        CONFIG['apis'].append({'email': email, 'key': key})
        save_config(CONFIG)
        update.message.reply_text(f"成功：API密钥已验证并成功添加！\n你好, {data.get('username', 'user')}!")
    else:
        update.message.reply_text(f"错误：API验证失败！原因: {data.get('errmsg', '未知错误')}")
    return ConversationHandler.END

def cancel(update: Update, context: CallbackContext) -> int:
    update.message.reply_text('操作已取消。')
    context.user_data.clear()
    return ConversationHandler.END

@restricted
def manage_api(update: Update, context: CallbackContext) -> None:
    args = context.args
    if not args:
        if not CONFIG['apis']:
            update.message.reply_text("当前没有存储任何API密钥。使用 `/addapi` 添加。")
            return
        message = "已存储的API列表 (Email):\n"
        for i, api in enumerate(CONFIG['apis']):
            message += f"{i+1}. `{api['email']}`\n"
        message += "\n使用 `/root remove <编号>` 来删除API。"
        update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
    elif args[0].lower() == 'remove' and len(args) > 1:
        try:
            index = int(args[1]) - 1
            if 0 <= index < len(CONFIG['apis']):
                removed_api = CONFIG['apis'].pop(index)
                save_config(CONFIG)
                update.message.reply_text(f"成功移除了API: {removed_api['email']}")
            else:
                update.message.reply_text("错误：编号无效。")
        except ValueError:
            update.message.reply_text("错误：请输入有效的编号。")
    else:
        update.message.reply_text("用法: `/root` 或 `/root remove <编号>`")

@super_admin_restricted
def manage_vip(update: Update, context: CallbackContext) -> None:
    args = context.args
    if len(args) != 2:
        admin_list = "\n".join([f"- `{admin_id}`" for admin_id in CONFIG['admins']])
        update.message.reply_text(f"用法: `/vip <add/remove> <user_id>`\n\n*当前管理员列表:*\n{admin_list}", parse_mode=ParseMode.MARKDOWN)
        return
    action, user_id_str = args
    try:
        user_id = int(user_id_str)
        if action.lower() == 'add':
            if user_id not in CONFIG['admins']:
                CONFIG['admins'].append(user_id)
                save_config(CONFIG)
                update.message.reply_text(f"成功添加管理员: {user_id}")
            else: update.message.reply_text("该用户已经是管理员。")
        elif action.lower() == 'remove':
            if user_id == CONFIG.get('super_admin'):
                update.message.reply_text("不能移除超级管理员！")
                return
            if user_id in CONFIG['admins']:
                CONFIG['admins'].remove(user_id)
                save_config(CONFIG)
                update.message.reply_text(f"成功移除管理员: {user_id}")
            else: update.message.reply_text("该用户不是管理员。")
        else: update.message.reply_text("无效的操作。请使用 `add` 或 `remove`。")
    except ValueError:
        update.message.reply_text("错误: User ID必须是数字。")

@restricted
def kkfofa_command(update: Update, context: CallbackContext) -> None:
    """处理Fofa查询命令，增加模式选择"""
    if not CONFIG['apis']:
        update.message.reply_text("错误：请先使用 `/addapi` 添加至少一个Fofa API。")
        return

    query_text = " ".join(context.args)
    if not query_text:
        update.message.reply_text("请输入查询语句。\n用法: `/kkfofa <查询语句>`")
        return
    
    if "daterange:" in query_text.lower():
        try:
            parts = query_text.lower().split("daterange:")
            base_query = parts[0].strip()
            date_parts = parts[1].strip().split("to")
            start_date = datetime.strptime(date_parts[0].strip(), "%Y-%m-%d")
            end_date = datetime.strptime(date_parts[1].strip(), "%Y-%m-%d")
            context.job_queue.run_once(run_date_range_query, 0, context={'chat_id': update.effective_chat.id, 'base_query': base_query, 'start_date': start_date, 'end_date': end_date})
            update.message.reply_text(f"已收到按天下载任务！\n*查询*: `{base_query}`\n*时间*: `{start_date.date()}` 到 `{end_date.date()}`\n任务已在后台开始。", parse_mode=ParseMode.MARKDOWN)
        except (ValueError, IndexError):
            update.message.reply_text("错误：日期范围格式不正确。\n请使用: `daterange:YYYY-MM-DD to YYYY-MM-DD`")
        return

    api = CONFIG['apis'][0]
    msg = update.message.reply_text("正在查询数据总数，请稍候...")
    
    data, error = fetch_fofa_data(api['email'], api['key'], query_text, page_size=1)
    if error:
        msg.edit_text(f"查询出错: {error}")
        return

    total_size = data.get('size', 0)
    if total_size == 0:
        msg.edit_text("未找到相关结果。")
        return

    context.user_data['query'] = query_text
    context.user_data['total_size'] = total_size

    if total_size <= 10000:
        msg.edit_text(f"查询到 {total_size} 条结果，符合免费额度，正在为您下载...")
        context.job_queue.run_once(run_full_download_query, 0, context={'chat_id': update.effective_chat.id, 'query': query_text, 'total_size': total_size})
    else:
        keyboard = [
            [InlineKeyboardButton("按天下载 (穷人模式)", callback_data='mode_daily')],
            [InlineKeyboardButton("全部下载 (消耗F点)", callback_data='mode_full')],
            [InlineKeyboardButton("仅预览前20条", callback_data='mode_preview')],
            [InlineKeyboardButton("取消", callback_data='mode_cancel')],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        msg.edit_text(
            f"查询到 {total_size} 条结果，已超出免费额度(10000条)。\n请选择下载模式:",
            reply_markup=reply_markup
        )
    # The return value is not strictly needed here as we are not in a conversation
    # but returning it doesn't hurt and makes the logic clear.
    return 1 # A placeholder state

def query_mode_callback(update: Update, context: CallbackContext) -> int:
    """处理用户选择的下载模式"""
    query = update.callback_query
    query.answer()
    
    mode = query.data
    base_query = context.user_data.get('query')
    total_size = context.user_data.get('total_size')

    if mode == 'mode_daily':
        query.edit_message_text(text="您选择了按天下载模式。\n请输入起止日期 (格式: `YYYY-MM-DD to YYYY-MM-DD`)")
        return ASK_DATE_RANGE
    
    elif mode == 'mode_full':
        query.edit_message_text(text=f"已开始全量下载任务 ({total_size}条)，请注意这可能会消耗您的F点或会员权益。")
        context.job_queue.run_once(run_full_download_query, 0, context={'chat_id': query.message.chat_id, 'query': base_query, 'total_size': total_size})
        return ConversationHandler.END

    elif mode == 'mode_preview':
        api = CONFIG['apis'][0]
        data, error = fetch_fofa_data(api['email'], api['key'], base_query, page_size=20)
        if error:
            query.edit_message_text(f"预览失败: {error}")
            return ConversationHandler.END
        
        results = data.get('results', [])
        message = f"*查询语句*: `{base_query}`\n*总数*: `{total_size}`\n\n*前20条预览结果*:\n"
        message += "\n".join([f"`{res[0]}`" for res in results])
        query.edit_message_text(message, parse_mode=ParseMode.MARKDOWN)
        return ConversationHandler.END
        
    elif mode == 'mode_cancel':
        query.edit_message_text(text="操作已取消。")
        context.user_data.clear()
        return ConversationHandler.END
    return ConversationHandler.END


def get_date_range_from_message(update: Update, context: CallbackContext) -> int:
    """从消息中获取日期范围并启动任务"""
    date_range_str = update.message.text
    base_query = context.user_data.get('query')

    try:
        date_parts = date_range_str.lower().split("to")
        start_date = datetime.strptime(date_parts[0].strip(), "%Y-%m-%d")
        end_date = datetime.strptime(date_parts[1].strip(), "%Y-%m-%d")

        update.message.reply_text(f"日期范围确认！任务已在后台开始。\n*查询*: `{base_query}`\n*时间*: `{start_date.date()}` 到 `{end_date.date()}`", parse_mode=ParseMode.MARKDOWN)
        
        context.job_queue.run_once(
            run_date_range_query, 0, 
            context={
                'chat_id': update.effective_chat.id, 
                'base_query': base_query,
                'start_date': start_date,
                'end_date': end_date
            }
        )
        context.user_data.clear()
        return ConversationHandler.END
    except (ValueError, IndexError):
        update.message.reply_text("格式错误，请重新输入 (格式: `YYYY-MM-DD to YYYY-MM-DD`)\n或使用 /cancel 取消。")
        return ASK_DATE_RANGE

# --- 后台任务函数 ---
def run_full_download_query(context: CallbackContext):
    """后台任务：下载全部数据"""
    job_context = context.job.context
    chat_id = job_context['chat_id']
    query_text = job_context['query']
    total_size = job_context['total_size']
    api = CONFIG['apis'][0]
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"fofa_full_{timestamp}.txt"
    
    page_size = 10000 
    pages_to_fetch = (total_size + page_size - 1) // page_size
    
    with open(output_filename, 'w', encoding='utf-8') as f:
        for page in range(1, pages_to_fetch + 1):
            context.bot.send_message(chat_id, f"正在下载第 {page}/{pages_to_fetch} 页...")
            data, error = fetch_fofa_data(api['email'], api['key'], query_text, page=page, page_size=page_size)
            if error:
                context.bot.send_message(chat_id, f"下载第 {page} 页时出错: {error}")
                continue
            
            results = data.get('results', [])
            for res in results:
                f.write(f"{res[0]}\n")
    
    context.bot.send_message(chat_id, "全量数据下载完成，正在发送文件...")
    try:
        with open(output_filename, 'rb') as f:
            context.bot.send_document(chat_id, document=f)
    except Exception as e:
        context.bot.send_message(chat_id, f"发送文件失败: {e}")
    finally:
        os.remove(output_filename)

def run_date_range_query(context: CallbackContext):
    """后台任务：按天下载数据"""
    job_context = context.job.context
    chat_id, base_query = job_context['chat_id'], job_context['base_query']
    start_date, end_date = job_context['start_date'], job_context['end_date']
    api = CONFIG['apis'][0]
    total_found, current_date = 0, start_date
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_filename = f"fofa_daily_{timestamp}.txt"

    with open(output_filename, 'w', encoding='utf-8') as f:
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            daily_query = f'({base_query}) && after="{date_str}" && before="{date_str}"'
            context.bot.send_message(chat_id, f"正在下载 `{date_str}` 的数据...", parse_mode=ParseMode.MARKDOWN)
            page, daily_count = 1, 0
            while True:
                data, error = fetch_fofa_data(api['email'], api['key'], daily_query, page=page, page_size=10000)
                if error:
                    context.bot.send_message(chat_id, f"下载 `{date_str}` 数据时出错: {error}", parse_mode=ParseMode.MARKDOWN)
                    break 
                results = data.get('results', [])
                if not results: break
                for res in results:
                    f.write(f"{res[0]}\n")
                daily_count += len(results)
                if len(results) < 10000: break 
                page += 1
            context.bot.send_message(chat_id, f"`{date_str}` 下载完成，共找到 {daily_count} 条数据。", parse_mode=ParseMode.MARKDOWN)
            total_found += daily_count
            current_date += timedelta(days=1)
    
    context.bot.send_message(chat_id, f"所有日期下载完成！总共找到 {total_found} 条数据。\n正在发送结果文件...")
    try:
        with open(output_filename, 'rb') as f:
            context.bot.send_document(chat_id, document=f)
    except Exception as e:
        context.bot.send_message(chat_id, f"发送文件失败: {e}")
    finally:
        os.remove(output_filename)

def main() -> None:
    """启动Bot"""
    # Telegram Bot Token (已使用Base64加密)
    encoded_token = 'ODMyNTAwMjg5MTpBQUZyY1UzWEVibTZzSHluM21abUY4SHAweVFMdVRRd1pr'
    TELEGRAM_BOT_TOKEN = base64.b64decode(encoded_token).decode('utf-8')
    
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    add_api_conv = ConversationHandler(
        entry_points=[CommandHandler('addapi', add_api_start)],
        states={
            EMAIL: [MessageHandler(Filters.text & ~Filters.command, get_email)],
            KEY: [MessageHandler(Filters.text & ~Filters.command, get_key)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    # 主查询与模式选择的会话
    # 注意：这里的实现方式做了一些简化，以更好地兼容旧版本逻辑
    kkfofa_handler = CommandHandler('kkfofa', kkfofa_command)
    
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("help", help_command))
    dispatcher.add_handler(add_api_conv)
    dispatcher.add_handler(CommandHandler("root", manage_api))
    dispatcher.add_handler(CommandHandler("vip", manage_vip))
    
    # 将核心命令和回调处理分开
    dispatcher.add_handler(kkfofa_handler)
    dispatcher.add_handler(CallbackQueryHandler(query_mode_callback))
    
    # 添加一个单独的处理器来接收日期范围
    date_range_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(query_mode_callback, pattern='^mode_daily$')],
        states={
            ASK_DATE_RANGE: [MessageHandler(Filters.text & ~Filters.command, get_date_range_from_message)]
        },
        fallbacks=[CommandHandler('cancel', cancel)]
    )
    # dispatcher.add_handler(date_range_handler) # This logic is simplified above

    updater.start_polling()
    logger.info("Bot is running...")
    updater.idle()

if __name__ == '__main__':
    main()
