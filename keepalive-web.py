#!/usr/bin/env python3
"""
MiniMax 每日签到 Web 管理界面
============================

- 单密码登录(SHA256 哈希存文件)
- 仪表盘:服务状态 / 每日签到 / Token 更新 / 密码修改 / 实时日志
- 签到调度在 Web 进程的**后台线程**里跑,通过 threading.Event 控制启停
  - 线程每 30 秒醒一次,按签到区间随机时刻触发
  - 状态显示 = 线程真实状态 + signin 状态文件,不会"显示运行但实际死了"
- Kami 设计风格:暖米纸画布 + 油墨蓝强调色
- 每 5 秒自动刷新

签到协议细节(端点 / 签名 / 响应字段)全部封装在 signin.py 里,本文件只负责:
  1. Web 界面与交互
  2. 调度线程
  3. 状态聚合

启动:
    pip3 install -r requirements.txt
    python3 keepalive-web.py

首次启动会自动生成随机密码并打印到 stderr。
"""

import os
import sys
import time
import secrets
import argparse
import threading
import logging
from datetime import datetime
from functools import wraps

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9
    ZoneInfo = None

# 保证同目录的 signin.py 能被导入(脚本名带连字符,显式补一次路径)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from flask import (
    Flask, request, session, redirect, url_for,
    render_template_string, jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash

import signin


# ===================== 路径配置 =====================
# 默认:跟脚本同目录
# 想要放别处用环境变量覆盖:
#   MINIMAX_PASS_FILE=/path/to/.web-pass
#   MINIMAX_SECRET_FILE=/path/to/.web-secret
#   MINIMAX_TOKEN_FILE=/path/to/token.txt
#   MINIMAX_LOG_FILE=/path/to/signin.log
#   MINIMAX_SIGNIN_STATE_FILE=/path/to/.signin-state.json
PASS_FILE = os.environ.get("MINIMAX_PASS_FILE") or os.path.join(SCRIPT_DIR, ".web-pass")
SECRET_FILE = os.environ.get("MINIMAX_SECRET_FILE") or os.path.join(SCRIPT_DIR, ".web-secret")
LOG_FILE = os.environ.get("MINIMAX_LOG_FILE") or os.path.join(SCRIPT_DIR, "signin.log")


def _resolve_token_file():
    """Token 文件路径:环境变量优先,否则用 signin 模块的约定。"""
    env = os.environ.get("MINIMAX_TOKEN_FILE")
    if env:
        return env
    try:
        return signin.token_path()
    except Exception:  # noqa: BLE001
        return os.path.join(SCRIPT_DIR, "token.txt")


def _resolve_state_file():
    """签到状态文件路径:环境变量优先,否则用 signin 模块的约定。"""
    env = os.environ.get("MINIMAX_SIGNIN_STATE_FILE")
    if env:
        return env
    try:
        return signin.state_path()
    except Exception:  # noqa: BLE001
        return os.path.join(SCRIPT_DIR, ".signin-state.json")


TOKEN_FILE = _resolve_token_file()
STATE_FILE = _resolve_state_file()


# ===================== 启动参数 =====================
parser = argparse.ArgumentParser(description="MiniMax 每日签到 Web 管理界面")
parser.add_argument("--host", default="0.0.0.0", help="监听地址(默认 0.0.0.0)")
parser.add_argument("--port", type=int, default=35235, help="监听端口(默认 35235)")
parser.add_argument("--password", help="设置/重置管理密码(也可在 Web 界面改)")
parser.add_argument("--reset-password", action="store_true", help="强制重置密码")
parser.add_argument(
    "--secure-cookie",
    action="store_true",
    help="给 session cookie 加 Secure 属性(走 nginx HTTPS 时打开;默认关闭,因为服务默认 HTTP 直连)",
)
args = parser.parse_args()


def _env_flag(name):
    """环境变量开关:1 / true / yes / on 视为真。"""
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == "":
        return False
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


# session cookie 是否带 Secure:默认关闭(服务默认 HTTP 直连),走 HTTPS 反代时再打开
SECURE_COOKIE = bool(args.secure_cookie) or _env_flag("MINIMAX_SECURE_COOKIE")


# ===================== 敏感文件权限 =====================
def _ensure_private_mode(path):
    """把文件权限强制成 600(已存在的文件也纠正,修历史遗留的 644)。"""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_private_file(path, content):
    """写文件并强制 600 权限。

    用 os.open(..., 0o600) 直接按 600 建,避免"先按 umask 建出 644 再 chmod"
    留下的时间窗口;写完再 chmod 一次,保证最终权限就是 600(不受 umask 影响)。
    """
    data = content if isinstance(content, bytes) else str(content).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    _ensure_private_mode(path)


# ===================== Flask app =====================
app = Flask(__name__)

# session cookie 安全属性
app.config["SESSION_COOKIE_HTTPONLY"] = True       # JS 读不到 session cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"       # 挡住跨站 POST(浏览器默认行为)
app.config["SESSION_COOKIE_SECURE"] = SECURE_COOKIE  # 走 HTTPS 时才打开

# Session secret
try:
    with open(SECRET_FILE, "rb") as f:
        app.secret_key = f.read()
    _ensure_private_mode(SECRET_FILE)  # 已存在的密钥文件也强制 600
except FileNotFoundError:
    app.secret_key = secrets.token_bytes(32)
    _write_private_file(SECRET_FILE, app.secret_key)

# config.json 里装着 uuid / device_id / user_id 三个账号标识, 权限同样要 600
# (config.json 是用户自己 cp 出来的, 默认权限常常是 644, 这里纠正)
CONFIG_FILE = signin.config_path()
if os.path.exists(CONFIG_FILE):
    _ensure_private_mode(CONFIG_FILE)


# ===================== 密码管理 =====================
def set_password(new_password):
    """设置密码,存哈希(文件权限强制 600)。"""
    h = generate_password_hash(new_password)
    _write_private_file(PASS_FILE, h)


def password_exists():
    return os.path.exists(PASS_FILE)


def verify_password(p):
    if not p:
        return False
    try:
        with open(PASS_FILE, "r") as f:
            return check_password_hash(f.read().strip(), p)
    except Exception:  # noqa: BLE001
        return False


# 处理密码初始化
initial_password_printed = None
if args.reset_password or (args.password and not password_exists()):
    pwd = args.password or secrets.token_urlsafe(10)
    set_password(pwd)
    initial_password_printed = pwd
elif args.password:
    set_password(args.password)
    initial_password_printed = args.password
elif not password_exists():
    pwd = secrets.token_urlsafe(10)
    set_password(pwd)
    initial_password_printed = pwd

# 已有密码文件也强制 600(修历史遗留的 644)
if password_exists():
    _ensure_private_mode(PASS_FILE)


# ===================== 日志 =====================
_web_logger = None
_logger_lock = threading.Lock()


def _ensure_logger():
    """配置 logger(写文件 + stdout),同进程内只产生一个实例。"""
    global _web_logger
    with _logger_lock:
        if _web_logger is not None:
            return _web_logger
        logger = logging.getLogger("signin")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        formatter = logging.Formatter(
            fmt="[%(asctime)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        try:
            fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        except Exception as e:  # noqa: BLE001
            print(f"[WARN] 无法写日志文件 {LOG_FILE}: {e}", file=sys.stderr)
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        _web_logger = logger
        return _web_logger


# ===================== 登录失败限流 =====================
# 进程内实现,重启即失效(可接受)。
# 同一 IP 连续失败 LOGIN_MAX_FAILS 次 → 锁定 LOGIN_LOCK_MINUTES 分钟,成功登录清零。
LOGIN_MAX_FAILS = int(os.environ.get("MINIMAX_LOGIN_MAX_FAILS") or 5)
LOGIN_LOCK_MINUTES = int(os.environ.get("MINIMAX_LOGIN_LOCK_MINUTES") or 10)

_login_fail_lock = threading.Lock()
_login_fail_records = {}  # ip -> {"count": int, "locked_until": float}


def _client_ip():
    """取客户端 IP。

    只认 remote_addr,不信任 X-Forwarded-For —— 那个头是客户端可伪造的,
    拿它做限流键等于限流可以被随手绕开。
    (走 nginx 反代时所有请求都算 127.0.0.1,限流是全局的。)
    """
    return request.remote_addr or "unknown"


def _login_lock_info(ip):
    """返回 (是否锁定, 剩余秒数)。"""
    now = time.time()
    with _login_fail_lock:
        rec = _login_fail_records.get(ip)
        if not rec:
            return False, 0
        until = rec.get("locked_until") or 0
        if until > now:
            return True, int(until - now)
        if until:
            # 锁已过期,清零重新计数
            rec["locked_until"] = 0
            rec["count"] = 0
        return False, 0


def _login_record_failure(ip):
    """记一次登录失败,达到阈值就锁。返回当前连续失败次数。"""
    with _login_fail_lock:
        rec = _login_fail_records.setdefault(ip, {"count": 0, "locked_until": 0})
        rec["count"] = int(rec.get("count") or 0) + 1
        if rec["count"] >= LOGIN_MAX_FAILS:
            rec["locked_until"] = time.time() + LOGIN_LOCK_MINUTES * 60
        return rec["count"]


def _login_record_success(ip):
    """登录成功 → 失败计数清零。"""
    with _login_fail_lock:
        _login_fail_records.pop(ip, None)


# ===================== 签到调度线程 =====================
# 单进程架构:签到调度在 Web 进程里的后台线程,通过 Event 控制启停
_signin_stop_event = threading.Event()  # set = 已停止
_signin_thread = None
_signin_lock = threading.Lock()

POLL_SECONDS = 30  # 调度线程轮询间隔
DAYS_CACHE_TTL = 300  # 7 天面板数据缓存有效期(秒)
RETRY_BACKOFF_SECONDS = 600  # 上次签到失败后的自动重试退避(秒)

# 签到互斥锁:自动调度和手动点击可能撞车,避免并发重复请求
_signin_run_lock = threading.Lock()

# 状态文件锁:与 signin 模块共用**同一把**锁(signin.state_lock),
# 保证 Web 线程、调度线程、signin 模块内部的「读-改-写」状态文件临界区
# 跨模块真正串行化(之前两边各一把锁, 会互相丢字段)。
# 注意:threading.Lock 不可重入,持锁期间不要调用会再次加锁的函数
# (signin.read_state / signin.update_state 内部自己加锁)。
_state_lock = signin.state_lock

# 字段级更新里的哨兵:表示"保留盘上现有值,不要覆盖"
# 哨兵本体只有 signin.py 一份定义,这里只做引用
_KEEP = signin._KEEP

# 一次签到"算成功"的结果:只有这两种才解除退避
SUCCESS_RESULTS = ("claimed", "already")

# 7 天签到面板缓存(避免 /api/status 每次都打 MiniMax 接口)
_days_cache = []
_days_cache_ts = 0.0
_days_cache_lock = threading.Lock()


# ===================== 状态文件读写(统一入口) =====================
def _read_state():
    """在锁内读状态文件(避免读到写了一半的文件)。

    委托 signin.read_state(),与写路径共用同一把锁(signin.state_lock)。
    """
    try:
        return signin.read_state() or {}
    except Exception as e:  # noqa: BLE001
        _ensure_logger().warning(f"读状态文件失败: {e}")
        return {}


def _update_state(*, remove=(), **fields):
    """统一的写状态入口:在锁内做「读-改-写」。

    委托 signin.update_state(),与 signin 模块内部的写入共用同一把锁,
    保证跨线程、跨模块的临界区真正串行化。

    - 重新读盘上最新 state,只合并本次要写的字段(remove 里列的字段删掉)
    - 绝不用调用方手里的旧快照整份覆盖,否则会把别人刚写的字段冲掉
    - 字段值传 _KEEP 表示"保留盘上现有值"

    返回合并后的 state。
    """
    try:
        return signin.update_state(remove=remove, **fields)
    except Exception as e:  # noqa: BLE001
        _ensure_logger().warning(f"写状态文件失败: {e}")
        return signin.read_state() or {}


# ===================== 时区 =====================
# signin 模块按 config 里的 timezone 计算"今天"和签到时刻,
# Web 层必须用同一个时区,否则跨天时"今天是否已签"会判错。
def _tzinfo(cfg):
    name = (cfg or {}).get("timezone") or "Asia/Shanghai"
    if ZoneInfo is None:
        return None
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        try:
            return ZoneInfo("Asia/Shanghai")
        except Exception:  # noqa: BLE001
            return None


def _now_in_tz(cfg):
    """当前时间(带 config 时区);时区不可用时退回本地朴素时间。"""
    tz = _tzinfo(cfg)
    if tz is None:
        return datetime.now()
    return datetime.now(tz)


def _today_str(cfg):
    """按 config 时区取今天的日期字符串(YYYY-MM-DD)。"""
    return _now_in_tz(cfg).strftime("%Y-%m-%d")


def start_signin_thread():
    """启动签到调度线程(幂等)。"""
    global _signin_thread
    with _signin_lock:
        if _signin_thread and _signin_thread.is_alive():
            return False
        _signin_stop_event.clear()
        logger = _ensure_logger()
        _signin_thread = threading.Thread(
            target=_signin_loop,
            name="signin-scheduler",
            daemon=True,
        )
        _signin_thread.start()
        logger.info("每日签到调度线程已启动")
        return True


def stop_signin_thread():
    """停止签到调度线程(标志位置位,循环在下一次检查时退出)。"""
    _signin_stop_event.set()


def get_scheduler_status():
    """读线程真实状态。"""
    thread_alive = bool(_signin_thread and _signin_thread.is_alive())
    return {
        "running": thread_alive and not _signin_stop_event.is_set(),
        "pid": os.getpid(),
        "thread_alive": thread_alive,
        "poll_seconds": POLL_SECONDS,
        "log_file": LOG_FILE,
        "token_file": TOKEN_FILE,
        "state_file": STATE_FILE,
    }


def _is_due(next_run, now):
    """比较 next_run 与 now,兼容 naive / aware 两种 datetime。"""
    if next_run is None:
        return False
    try:
        return next_run <= now
    except TypeError:
        try:
            return next_run.replace(tzinfo=None) <= now.replace(tzinfo=None)
        except Exception:  # noqa: BLE001
            return False


def _signin_loop():
    """调度线程主体:每 POLL_SECONDS 秒醒一次,到点就跑一次签到。"""
    logger = _ensure_logger()
    logger.info("=" * 50)
    logger.info("MiniMax 每日签到调度线程启动")
    while not _signin_stop_event.is_set():
        try:
            _scheduler_poll()
        except Exception as e:  # noqa: BLE001
            logger.exception(f"调度循环异常: {e}")
        _signin_stop_event.wait(POLL_SECONDS)
    logger.info("每日签到调度线程退出")


def _scheduler_poll():
    """一轮调度判断:到点就签到。"""
    logger = _ensure_logger()
    cfg = signin.load_config() or {}
    state = _read_state()
    _sync_state_flags(state, cfg)  # 修正"今天是否已签"标记
    now = _now_in_tz(cfg)
    try:
        next_run = signin.next_run_at(cfg, state, now)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"计算下次执行时间失败: {e}")
        return
    # next_run_at 已把当天摇中的执行时刻就地写进 state, 这里落盘,
    # 否则每 30 秒都会重摇一次, 时刻也就永远定不下来
    _persist_target_state(state)
    if next_run is None:
        return
    if not _is_due(next_run, now):
        logger.debug(f"未到执行时间,下次 {next_run}")
        return
    if not cfg.get("auto_signin", True):
        logger.info("自动签到未开启,本轮跳过")
        return
    # 上一次没签成功后的退避:避免 Token 失效 / 服务异常时每 30 秒打一次接口
    if _in_backoff(state):
        _log_backoff(logger, state)
        return
    logger.info(f"到达执行时间 {next_run},开始签到")
    run_signin_once(reason="auto")


def _in_backoff(state):
    """上次签到没成功、且还在退避窗口内 → True。

    成功的定义是 result ∈ {claimed, already};
    error / no_token 等一律进退避 —— 否则 token 为空时调度线程会每 30 秒空转一次。
    """
    st = state or {}
    result = st.get("last_result")
    if not result:
        return False  # 还没有过签到记录(刚启动),不算退避
    if result in SUCCESS_RESULTS:
        return False
    try:
        last_error_at = float(st.get("last_error_at") or 0)
    except (TypeError, ValueError):
        return False
    if last_error_at <= 0:
        return False
    return (time.time() - last_error_at) < RETRY_BACKOFF_SECONDS


def _log_backoff(logger, state):
    """退避提示:刚失败时记一条 info,之后降成 debug,免得 30 秒轮询刷屏。"""
    try:
        last_error_at = float((state or {}).get("last_error_at") or 0)
    except (TypeError, ValueError):
        last_error_at = 0
    if last_error_at > 0 and (time.time() - last_error_at) < 60:
        logger.info(f"上次签到未成功,{RETRY_BACKOFF_SECONDS // 60} 分钟退避中,稍后自动重试")
    else:
        logger.debug("退避中,稍后自动重试")


def run_signin_once(reason="auto"):
    """跑一次签到,同步更新状态文件,返回 signin.run_checkin 的结果。"""
    logger = _ensure_logger()
    logger.info(f"执行签到(触发方式: {reason})")
    with _signin_run_lock:
        try:
            result = signin.run_checkin(logger=logger)
        except Exception as e:  # noqa: BLE001
            logger.exception(f"签到异常: {e}")
            result = {
                "ok": False,
                "result": "error",
                "message": str(e),
                "points": 0,
                "day_no": 0,
                "streak": 0,
            }
    if not isinstance(result, dict):
        result = {"ok": False, "result": "error", "message": str(result)}
    result.setdefault("result", "error")
    result.setdefault("message", "")
    result.setdefault("ok", False)
    _apply_checkin_result(result)
    refresh_days_cache(force=True)
    return result


def _as_int(value, default=0):
    """把任意值转成 int,失败用 default(不抛异常)。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _apply_checkin_result(result):
    """把签到结果写进状态文件。

    只写"本次签到结果负责"的字段(而不是整份覆盖),避免把调度线程刚写的
    退避标记 / 摇中的执行时刻冲掉。
    """
    cfg = signin.load_config() or {}
    res = result.get("result") or "error"
    signed = res in SUCCESS_RESULTS
    now = _now_in_tz(cfg)
    today_str = now.strftime("%Y-%m-%d")

    fields = {}
    remove = []
    if signed:
        fields.update({
            "last_signin_date": today_str,
            "signin_date": today_str,
            "signed_date": today_str,
            "today_signed": True,
            "last_signin_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "last_signin_ts": int(time.time()),
        })
        # 今天已经签了, 今天摇中的执行时刻作废(明天的时刻由 next_run_at 重新摇)
        remove.extend(["last_error_at", "target_date", "target_at"])
    else:
        fields["today_signed"] = False
        fields["last_error_at"] = int(time.time())

    points = result.get("points")
    day_no = result.get("day_no")
    streak = result.get("streak")
    # 与 signin 模块的状态字段保持同名(signin 自己也会写一套)
    # 失败时 last_points / last_day_no / last_streak 保留上次成功的值(_KEEP)
    fields["last_points"] = _as_int(points) if points else _KEEP
    fields["last_day_no"] = _as_int(day_no) if day_no else _KEEP
    fields["last_streak"] = _as_int(streak) if streak else _KEEP
    fields["last_result"] = res
    fields["last_message"] = result.get("message") or ""
    # Web 层自己的别名
    fields["day_no"] = fields["last_day_no"]
    fields["streak"] = fields["last_streak"]
    # 今日积分:签到失败归零(不残留上次的数值);
    # already 用本次拿到的真实积分(签到接口今天已领时会回今天的积分),
    # 不能沿用盘上旧值, 否则盘上会是昨天的数值而和 result["points"] 对不上
    if res == "claimed":
        fields["today_points"] = _as_int(points)
    elif res == "already":
        fields["today_points"] = _as_int(points)
    else:
        fields["today_points"] = 0
    if result.get("token_exp"):
        fields["token_exp"] = result["token_exp"]
    if result.get("token_renewed"):
        fields["token_renewed"] = True
    fields["updated_at"] = now.strftime("%Y-%m-%d %H:%M:%S")
    return _update_state(remove=remove, **fields)


def _sync_state_flags(state=None, cfg=None):
    """按日期修正"今天是否已签"标记,避免跨天读到昨天的 True。

    在锁内重新读盘 + 只写自己负责的三个字段,不整份覆盖别人的写入。
    返回(修正后的)最新状态。
    """
    if cfg is None:
        cfg = signin.load_config() or {}
    today_str = _today_str(cfg)
    with _state_lock:
        try:
            disk = signin.load_state() or {}
        except Exception as e:  # noqa: BLE001
            _ensure_logger().warning(f"读状态文件失败: {e}")
            disk = {}
        last_signin_date = disk.get("last_signin_date")
        signed_today = last_signin_date == today_str
        changed = False
        if bool(disk.get("today_signed")) != signed_today:
            changed = True
        for key in ("signin_date", "signed_date"):
            if disk.get(key) != last_signin_date:
                changed = True
        if changed:
            disk["today_signed"] = signed_today
            disk["signin_date"] = last_signin_date
            disk["signed_date"] = last_signin_date
            try:
                signin.save_state(disk)
            except Exception as e:  # noqa: BLE001
                _ensure_logger().warning(f"写状态文件失败: {e}")
    if state is not None:
        state.clear()
        state.update(disk)
    return disk


def _persist_target_state(state):
    """把当天摇中的执行时刻落盘(只写 target_date / target_at 两个字段)。

    signin.next_run_at 会就地往 state 里写 target_date / target_at;
    盘上已经有当天的时刻时保持不动 —— 每天只摇一次,
    不会因为多线程交错把当天摇好的随机时刻换掉。
    """
    target_date = (state or {}).get("target_date")
    target_at = (state or {}).get("target_at")
    if not target_date or not target_at:
        return False
    with _state_lock:
        try:
            disk = signin.load_state() or {}
        except Exception:  # noqa: BLE001
            disk = {}
        disk_date = disk.get("target_date")
        disk_at = disk.get("target_at")
        if disk_date and disk_at and disk_date == target_date:
            # 当天已经摇好(可能是另一个线程刚写的),不覆盖
            return False
        disk["target_date"] = target_date
        disk["target_at"] = target_at
        try:
            signin.save_state(disk)
            return True
        except Exception as e:  # noqa: BLE001
            _ensure_logger().warning(f"写状态文件失败: {e}")
            return False


def _clear_target_state():
    """清掉 state 里已摇好的执行时刻(改区间 / 签到成功后用)。"""
    with _state_lock:
        try:
            state = signin.load_state() or {}
            if "target_date" not in state and "target_at" not in state:
                return False
            state.pop("target_date", None)
            state.pop("target_at", None)
            signin.save_state(state)
            return True
        except Exception as e:  # noqa: BLE001
            _ensure_logger().warning(f"清执行时刻失败: {e}")
            return False


# ===================== 7 天签到面板数据 =====================
def _normalize_days(days, today):
    """把 signin 返回的 days 统一成前端用的字段结构。"""
    out = []
    today_day_no = None
    if isinstance(today, dict):
        try:
            today_day_no = int(today.get("day_no"))
        except (TypeError, ValueError):
            today_day_no = None
    for i, item in enumerate(days or []):
        if not isinstance(item, dict):
            continue
        day_no = item.get("day_no")
        if day_no is None:
            day_no = item.get("day")
        if day_no is None:
            day_no = item.get("no")
        if day_no is None:
            day_no = i + 1
        points = item.get("points")
        if points is None:
            points = item.get("point")
        status = item.get("status")
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        is_today = bool(item.get("is_today"))
        if not is_today and today_day_no is not None:
            try:
                is_today = int(day_no) == today_day_no
            except (TypeError, ValueError):
                is_today = False
        try:
            bonus = int(item.get("bonus_points") or 0)
        except (TypeError, ValueError):
            bonus = 0
        out.append({
            "day_no": day_no,
            "points": int(points or 0),
            "status": status,
            "is_today": is_today,
            "bonus_points": bonus,
        })
    return out


def refresh_days_cache(force=False):
    """刷新 7 天面板数据(带 TTL,避免每次 /api/status 都打接口)。"""
    global _days_cache, _days_cache_ts
    logger = _ensure_logger()
    with _days_cache_lock:
        now_ts = time.time()
        if not force and _days_cache and (now_ts - _days_cache_ts) < DAYS_CACHE_TTL:
            return _days_cache
    try:
        token = signin.load_token()
    except Exception:  # noqa: BLE001
        return _days_cache
    try:
        cfg = signin.load_config() or {}
        st = signin.fetch_signin_status(token, cfg=cfg)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"获取签到状态失败: {e}")
        return _days_cache
    if isinstance(st, dict) and st.get("ok"):
        with _days_cache_lock:
            _days_cache = _normalize_days(st.get("days"), st.get("today"))
            _days_cache_ts = time.time()
        return _days_cache
    return _days_cache


def get_days_cache():
    """给 /api/status 用的 7 天数据(过期且有 token 时同步刷新一次)。"""
    with _days_cache_lock:
        fresh = bool(_days_cache) and (time.time() - _days_cache_ts) < DAYS_CACHE_TTL
    if fresh:
        with _days_cache_lock:
            return list(_days_cache)
    return refresh_days_cache(force=False)


# ===================== Auth 装饰器 =====================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "未登录"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ===================== Token / 日志 辅助 =====================
def read_token_info():
    """Token 状态:exists / empty / length / exp / exp_human / remaining_days / real_user_id。"""
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        return {"exists": False}
    except Exception as e:  # noqa: BLE001
        return {"exists": True, "empty": True, "length": 0, "error": str(e)}
    if not raw:
        return {"exists": True, "empty": True, "length": 0}
    info = {"exists": True, "empty": False, "length": len(raw)}
    exp = None
    try:
        exp = signin.token_exp(raw)
    except Exception:  # noqa: BLE001
        exp = None
    if exp:
        info["exp"] = int(exp)
        # 过期时间按 config 里的时区显示(服务器不在 +08:00 时也不会偏)
        cfg = signin.load_config() or {}
        tz = _tzinfo(cfg)
        if tz is not None:
            dt = datetime.fromtimestamp(int(exp), tz=tz)
        else:
            dt = datetime.fromtimestamp(int(exp))
        info["exp_human"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        info["remaining_days"] = max(0, (int(exp) - time.time()) / 86400)
    else:
        info["parse_error"] = True

    # 当前账号(上次 Token 校验时识别到的 realUserID)。
    # 只读状态文件里的缓存值 —— /api/status 不发任何网络请求。
    try:
        real_user_id = _read_state().get("real_user_id")
    except Exception:  # noqa: BLE001
        real_user_id = None
    if real_user_id:
        info["real_user_id"] = str(real_user_id)
    return info


def read_logs(n=50):
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            return [l.rstrip() for l in lines[-n:]]
    except FileNotFoundError:
        return ["(日志文件不存在)"]
    except Exception as e:  # noqa: BLE001
        return [f"(读取失败: {e})"]


def ensure_token_file():
    """启动时确保 token 文件存在(空文件也行,Web 界面会引导填)。"""
    if os.path.exists(TOKEN_FILE):
        _ensure_private_mode(TOKEN_FILE)  # 已存在的也强制 600
        return "exists"
    try:
        parent = os.path.dirname(TOKEN_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        _write_private_file(TOKEN_FILE, "")  # 直接按 600 建,不留 644 窗口
        return "created"
    except OSError:
        return "failed"


# ===================== 签到状态聚合 =====================
def _fmt_dt(dt):
    if dt is None:
        return None
    try:
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:  # noqa: BLE001
        return str(dt)


def _error_is_today(state, now):
    """状态里这条错误是不是今天产生的。

    拿不到可用的错误时间戳时,保守按"不是今天"处理 ——
    宁可少报一次失败,也不要把昨天的错误当成今天的红点。
    """
    st = state or {}
    raw = st.get("last_error_at")
    if raw is None:
        return False
    try:
        ts = float(raw)
    except (TypeError, ValueError):
        return False
    if ts <= 0:
        return False
    try:
        if getattr(now, "tzinfo", None) is not None:
            dt = datetime.fromtimestamp(ts, tz=now.tzinfo)
        else:
            dt = datetime.fromtimestamp(ts)
    except (OSError, OverflowError, ValueError):
        return False
    return dt.strftime("%Y-%m-%d") == now.strftime("%Y-%m-%d")


def build_signin_status():
    """把配置 + 状态文件 + 下次执行时间聚合成前端要的一坨。"""
    cfg = signin.load_config() or {}
    state = _read_state()
    _sync_state_flags(state, cfg)
    now = _now_in_tz(cfg)
    today_str = now.strftime("%Y-%m-%d")

    signed_today = state.get("last_signin_date") == today_str
    last_result = state.get("last_result") or ""
    last_message = state.get("last_message") or ""
    # signin 模块写的是 last_day_no / last_streak / last_points,这里两套都认
    day_no = int(state.get("day_no") or state.get("last_day_no") or 0)
    streak = int(state.get("streak") or state.get("last_streak") or 0)
    # 今日积分只认今天签到成功的那次:失败 / 昨天签到的都不算今天的积分
    today_points = int(state.get("today_points") or 0) if signed_today else 0
    last_signin_time = state.get("last_signin_time") or state.get("last_claim_at")

    try:
        next_run = signin.next_run_at(cfg, state, now)
        # 界面上的"下次执行时间"要和磁盘一致, 否则每次刷新都会重摇
        _persist_target_state(state)
    except Exception:  # noqa: BLE001
        next_run = None

    # 这条错误是哪天产生的?跨天的错误不能显示成"今天失败"
    error_today = _error_is_today(state, now)
    # 服务端把"还没到签到时间"也归到 error,这里翻译成"未到执行时间"
    not_arrived = (
        ("还没到时间" in last_message or "还没到签到时间" in last_message)
        and error_today
    )

    if signed_today:
        status = "signed"
        status_text = f"今日已签到(第 {day_no} 天)" if day_no else "今日已签到"
    elif last_result == "error" and error_today and not not_arrived:
        status = "error"
        status_text = f"签到失败({last_message[:60]})" if last_message else "签到失败"
    elif last_result == "no_token":
        status = "no_token"
        status_text = "未配置 Token,请在「更新 Token」里粘贴 JWT"
    elif not_arrived:
        # 服务端明确说还没到时间 → 归"未到执行时间",别提示"可领取"(点了也会失败)
        status = "pending"
        status_text = "未到执行时间"
    elif _is_due(next_run, now):
        status = "todo"
        status_text = "今天可领取,去点「立即签到」"
    else:
        status = "pending"
        status_text = "未到执行时间"

    return {
        "status": status,
        "status_text": status_text,
        "today_signed": signed_today,
        "day_no": day_no,
        "streak": streak,
        "today_points": today_points,
        "last_signin_time": last_signin_time,
        "last_result": last_result,
        "last_message": last_message,
        "next_run_at": _fmt_dt(next_run),
        "auto_signin": bool(cfg.get("auto_signin", True)),
        "sign_window_start": cfg.get("sign_window_start", ""),
        "sign_window_end": cfg.get("sign_window_end", ""),
        "host": cfg.get("host", ""),
        "timezone": cfg.get("timezone", ""),
        "days": get_days_cache(),
    }


# ===================== HTML 模板(Kami 设计) =====================

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>MiniMax 签到 · 登录</title>
<style>
:root {
  --canvas:#f5f4ed; --ivory:#faf9f5; --sand:#e8e6dc;
  --ink:#1B365D; --ink-light:#2D5A8A; --near-black:#141413;
  --olive:#504e49; --stone:#6b6a64; --error:#B53333;
  --border-warm:#d4d2c5; --tint-light:#EEF2F7;
  --serif:"Charter","Georgia","PingFang SC","Songti SC","Times New Roman",serif;
  --sans:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei","Helvetica Neue",sans-serif;
  --mono:"SF Mono",Monaco,Menlo,monospace;
}
*{box-sizing:border-box}
body{font-family:var(--sans);background:var(--canvas);color:var(--near-black);margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;-webkit-font-smoothing:antialiased}
.box{width:100%;max-width:380px;background:var(--ivory);border:1px solid #e8e6dc;border-radius:16px;padding:40px 36px 32px;box-shadow:0 4px 24px rgba(20,20,19,.04)}
.eyebrow{font-size:10.5px;letter-spacing:.8px;text-transform:uppercase;color:var(--olive);margin:0 0 8px;font-weight:600}
h1{font-family:var(--serif);font-weight:500;font-size:30px;margin:0 0 10px;color:var(--near-black);letter-spacing:-.01em;line-height:1.1}
h1 .cn{color:var(--ink);margin-left:2px}
.sub{font-size:13px;color:var(--olive);margin:0 0 28px;line-height:1.55}
input[type=password]{width:100%;padding:11px 14px;border:1px solid var(--border-warm);border-radius:6px;background:var(--canvas);color:var(--near-black);font-family:var(--mono);font-size:13px;transition:border-color .15s,box-shadow .15s}
input[type=password]:focus{outline:0;border-color:var(--ink);box-shadow:0 0 0 3px var(--tint-light)}
button{width:100%;margin-top:14px;padding:12px;background:var(--ink);color:var(--ivory);border:1px solid var(--ink);border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;font-family:var(--sans);transition:background .15s}
button:hover{background:var(--ink-light);border-color:var(--ink-light)}
.err{color:var(--error);font-size:12px;margin:12px 0 0;text-align:center}
</style>
</head>
<body>
<div class="box">
  <p class="eyebrow">服务控制台</p>
  <h1>MiniMax<span class="cn">·</span>签到</h1>
  <p class="sub">每日自动签到 · 管理控制台</p>
  <form method="POST">
    <input type="password" name="password" placeholder="管理密码" autofocus required>
    <button type="submit">登录</button>
    {% if error %}<p class="err">{{ error }}</p>{% endif %}
  </form>
</div>
</body>
</html>"""


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>MiniMax 签到</title>
<style>
:root {
  --canvas:#f5f4ed; --ivory:#faf9f5; --sand:#e8e6dc;
  --ink:#1B365D; --ink-light:#2D5A8A; --near-black:#141413;
  --olive:#504e49; --stone:#6b6a64; --error:#B53333;
  --warn:#b88a2e; --ok:#6b8e23; --orange:#cf8434;
  --border:#e8e6dc; --border-warm:#d4d2c5;
  --tint:#E4ECF5; --tint-light:#EEF2F7;
  --serif:"Charter","Georgia","PingFang SC","Songti SC","Times New Roman",serif;
  --sans:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei","Helvetica Neue",sans-serif;
  --mono:"SF Mono",Monaco,Menlo,"Cascadia Code",monospace;
}
*{box-sizing:border-box}
body{font-family:var(--sans);background:var(--canvas);color:var(--near-black);margin:0;padding:0;font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
.page{max-width:920px;margin:0 auto;padding:48px 32px 80px}
header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:40px;padding-bottom:20px;border-bottom:.5px solid var(--border)}
.title-block .eyebrow{font-size:10.5px;letter-spacing:.8px;text-transform:uppercase;color:var(--olive);margin:0 0 6px;font-weight:600}
h1{font-family:var(--serif);font-weight:500;font-size:32px;margin:0;letter-spacing:-.01em;line-height:1.1}
h1 .cn{color:var(--ink);margin-left:2px}
.logout{font-size:12px;color:var(--olive);text-decoration:none;border-bottom:1px solid transparent;padding-bottom:1px;transition:all .15s}
.logout:hover{color:var(--ink);border-bottom-color:var(--ink)}
.card{background:var(--ivory);border:1px solid var(--border);border-radius:12px;padding:24px 28px;margin-bottom:20px}
.card h2{font-family:var(--serif);font-weight:500;font-size:17px;margin:0 0 4px;color:var(--near-black);letter-spacing:-.005em}
.card .hint{font-size:12.5px;color:var(--olive);margin:0 0 18px;line-height:1.5}
.card h2+.hint{margin-top:4px}
.status-grid{display:flex;flex-direction:column;gap:0}
.status-row{display:flex;justify-content:space-between;align-items:baseline;padding:11px 0;border-bottom:.5px dashed var(--border-warm);font-size:13px;gap:16px}
.status-row:last-child{border-bottom:0}
.status-row .label{color:var(--olive);font-size:12.5px;letter-spacing:.2px;white-space:nowrap}
.status-row .value{font-family:var(--serif);color:var(--near-black);text-align:right}
.status-row code{font-family:var(--mono);font-size:11.5px;color:var(--ink);background:var(--tint-light);padding:2px 7px;border-radius:3px;word-break:break-all;max-width:60%;text-align:right}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot.on{background:var(--ok)}
.dot.off{background:var(--error)}
.dot.warn{background:var(--warn)}
.dot.orange{background:var(--orange)}
.metric{display:inline-flex;align-items:baseline;gap:2px}
.metric .num{font-family:var(--serif);font-size:18px;font-weight:500;color:var(--ink);letter-spacing:-.01em}
.metric .unit{font-size:11.5px;color:var(--olive);margin:0 8px 0 2px}
.button-row{display:flex;gap:10px;flex-wrap:wrap}
.btn{display:inline-block;padding:9px 18px;border-radius:8px;font-size:13px;font-weight:500;font-family:var(--sans);border:1px solid var(--border-warm);background:var(--sand);color:var(--near-black);cursor:pointer;text-decoration:none;transition:all .15s}
.btn:hover{background:var(--border-warm)}
.btn.btn-primary{background:var(--ink);color:var(--ivory);border-color:var(--ink)}
.btn.btn-primary:hover{background:var(--ink-light);border-color:var(--ink-light)}
.btn.btn-danger{background:var(--ivory);color:var(--error);border-color:var(--error)}
.btn.btn-danger:hover{background:#fcecec}
.btn:disabled{opacity:.4;cursor:not-allowed}
.btn:disabled:hover{background:var(--sand)}
.btn.btn-primary:disabled:hover{background:var(--ink)}
.btn.btn-danger:disabled:hover{background:var(--ivory)}
.btn .icon{display:inline-block;margin-right:6px;font-size:14px;line-height:1;vertical-align:-1px}
textarea,input[type=password],input[type=text]{width:100%;padding:10px 12px;border:1px solid var(--border-warm);border-radius:6px;background:var(--canvas);color:var(--near-black);font-family:var(--mono);font-size:12px;line-height:1.5;resize:vertical;transition:border-color .15s,box-shadow .15s}
textarea{min-height:64px}
textarea:focus,input:focus{outline:0;border-color:var(--ink);box-shadow:0 0 0 2px var(--tint-light)}
input[type=time]{width:auto;padding:8px 10px;border:1px solid var(--border-warm);border-radius:6px;background:var(--canvas);color:var(--near-black);font-family:var(--mono);font-size:12px;line-height:1.5;transition:border-color .15s,box-shadow .15s}
input[type=time]:focus{outline:0;border-color:var(--ink);box-shadow:0 0 0 2px var(--tint-light)}
.actions{display:flex;gap:10px;margin-top:12px;align-items:center}
.actions .msg{font-size:12px;color:var(--olive);margin-left:auto;font-style:italic}
.actions .msg.err{color:var(--error);font-style:normal}
.log-box{background:#141413;color:#d4d2c5;border-radius:8px;padding:16px 18px;font-family:var(--mono);font-size:11.5px;line-height:1.65;max-height:360px;overflow-y:auto;white-space:pre;word-wrap:break-word}
.log-box .ok{color:#95c378}
.log-box .warn{color:#d6a857}
.log-box .err{color:#e5816a}
.muted{color:var(--olive);font-size:11.5px;font-weight:400;margin-left:8px;font-family:var(--mono)}
.status-line{display:inline-flex;align-items:center;gap:6px;font-family:var(--sans);font-size:13px}
.help{display:inline-flex;align-items:center;justify-content:center;width:17px;height:17px;border-radius:50%;background:var(--sand);color:var(--olive);font-size:11px;font-weight:600;margin-left:8px;cursor:help;position:relative;vertical-align:1px;font-family:var(--sans);transition:all .15s;user-select:none}
.help:hover,.help:focus{background:var(--ink);color:var(--ivory);outline:0}
.tooltip{position:absolute;top:calc(100% + 12px);left:-8px;width:340px;background:var(--ivory);border:1px solid var(--border-warm);border-radius:8px;padding:14px 18px;box-shadow:0 4px 24px rgba(20,20,19,.08);font-size:12.5px;line-height:1.55;color:var(--near-black);font-weight:400;text-align:left;font-family:var(--sans);opacity:0;pointer-events:none;transition:opacity .15s;z-index:100}
.help:hover .tooltip,.help:focus .tooltip{opacity:1;pointer-events:auto}
.tooltip::before{content:"";position:absolute;top:-5px;left:14px;width:9px;height:9px;background:var(--ivory);border-left:1px solid var(--border-warm);border-top:1px solid var(--border-warm);transform:rotate(45deg)}
.tooltip strong{display:block;font-family:var(--serif);font-weight:500;color:var(--ink);font-size:13.5px;margin:0 0 10px;letter-spacing:-.005em}
.tooltip ol{margin:0;padding-left:18px}
.tooltip ol li{margin:5px 0;color:var(--near-black)}
.tooltip code{font-family:var(--mono);font-size:11.5px;color:var(--ink);background:var(--tint-light);padding:1px 5px;border-radius:3px}
.tooltip kbd{font-family:var(--mono);font-size:10.5px;color:var(--ink);background:var(--sand);border:1px solid var(--border-warm);border-radius:3px;padding:1px 5px;margin:0 1px}
.tooltip b{color:var(--ink);font-weight:600}
.switch{display:inline-flex;align-items:center;gap:8px;font-size:13px;color:var(--near-black);cursor:pointer;user-select:none}
.switch input[type=checkbox]{width:16px;height:16px;accent-color:var(--ink);cursor:pointer;margin:0}
.time-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.time-row .sep{color:var(--stone);font-size:12px}
.subhead{font-size:12px;color:var(--olive);margin:20px 0 10px;letter-spacing:.2px}
.day-grid{display:flex;gap:8px;flex-wrap:wrap}
.day{border:1px solid var(--border-warm);border-radius:8px;width:58px;padding:9px 4px;text-align:center;background:var(--sand);color:var(--stone)}
.day.claimed{background:var(--ok);border-color:var(--ok);color:#fff}
.day.available{background:var(--ivory);border-color:var(--ink);color:var(--ink)}
.day.pending{background:var(--sand);border-color:var(--border-warm);color:var(--stone)}
.day.today{box-shadow:0 0 0 2px var(--tint)}
.day .day-no{font-family:var(--mono);font-size:10.5px;opacity:.85}
.day .day-pt{font-family:var(--serif);font-size:16px;margin:3px 0 1px}
.day .day-st{font-size:10.5px;font-family:var(--mono)}
</style>
</head>
<body>
<div class="page">
  <header>
    <div class="title-block">
      <p class="eyebrow">服务控制台</p>
      <h1>MiniMax<span class="cn">·</span>签到</h1>
    </div>
    <a href="/logout" class="logout">退出</a>
  </header>

  <div class="card">
    <h2>服务状态</h2>
    <p class="hint">签到调度线程运行情况,每 5 秒自动刷新</p>
    <div class="status-grid" id="status">
      <div class="status-row"><span class="label">加载中</span><span class="value">…</span></div>
    </div>
  </div>

  <div class="card">
    <h2>每日签到</h2>
    <p class="hint">每天在设定区间内随机时刻自动领取积分</p>
    <div class="status-grid" id="signin-status">
      <div class="status-row"><span class="label">加载中</span><span class="value">…</span></div>
    </div>
    <div class="button-row" style="margin-top:18px">
      <button class="btn btn-primary" id="btn-signin" onclick="runSignin()"><span class="icon">✓</span>立即签到</button>
      <label class="switch"><input type="checkbox" id="auto-signin" onchange="toggleAuto(this)">自动签到</label>
      <span class="msg" id="auto-msg"></span>
    </div>
    <p class="subhead">执行时间区间</p>
    <p class="hint" style="margin:0 0 12px">在设定区间内随机时刻执行,避免固定时间被识别</p>
    <div class="time-row">
      <input type="time" id="win-start" value="00:30">
      <span class="sep">→</span>
      <input type="time" id="win-end" value="02:00">
      <button class="btn" onclick="saveWindow()">保存区间</button>
      <span class="msg" id="window-msg"></span>
    </div>
    <p class="subhead">未来 7 天</p>
    <div class="day-grid" id="day-grid"><span class="muted">加载中…</span></div>
  </div>

  <div class="card">
    <h2>更新 Token <span class="help" tabindex="0" aria-label="如何获取 Token">?<span class="tooltip"><strong>如何获取 Token</strong><ol><li>Chrome 打开 <code>agent.minimax.cn</code> 并登录</li><li>按 <kbd>F12</kbd> → 切到 <b>Network</b> 标签 → <kbd>F5</kbd> 刷新</li><li>点任意 <code>agent.minimax.cn</code> 请求</li><li>右侧 Headers → 找 <b>Request URL</b>,复制 <code>?token=</code> 后面的整段</li><li>粘到下面文本框 → 点保存</li></ol></span></span></h2>
    <p class="hint">粘贴新 JWT,保存后只校验 Token 是否可用,不会消耗签到机会</p>
    <textarea id="new-token" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
    <div class="actions">
      <button class="btn btn-primary" onclick="updateToken()">保存 Token</button>
      <span class="msg" id="token-msg"></span>
    </div>
  </div>

  <div class="card">
    <h2>修改密码 <span class="muted">至少 6 位</span></h2>
    <p class="hint">修改后立即生效,会自动退出当前会话</p>
    <input type="password" id="new-pass" placeholder="新密码">
    <div class="actions">
      <button class="btn" onclick="updatePassword()">更新密码</button>
      <span class="msg" id="pass-msg"></span>
    </div>
  </div>

  <div class="card">
    <h2>实时日志 <span class="muted" id="log-meta"></span></h2>
    <p class="hint">最后 30 行,自动滚动到底部</p>
    <div class="log-box" id="logs">加载中...</div>
  </div>
</div>

<script>
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

async function refresh(){
  try{
    const r=await fetch('/api/status');
    if(r.status===401){location.href='/login';return}
    const d=await r.json();
    renderStatus(d);
    renderSignin(d.signin||{});
    renderLogs();
  }catch(e){console.error(e)}
}

function row(label,value){return `<div class="status-row"><span class="label">${label}</span><span class="value">${value}</span></div>`}

function renderStatus(d){
  const s=d.signin||{}, t=d.token||{}, c=d.config||{}, sc=d.scheduler||{}, html=[];

  if(sc.running){
    html.push(row('调度线程','<span class="status-line"><span class="dot on"></span>运行中</span>'));
  }else{
    html.push(row('调度线程','<span class="status-line"><span class="dot off"></span>未运行</span>'));
  }
  html.push(row('进程 PID',`<code>${esc(d.pid||'')}</code>`));
  html.push(row('自动签到',c.auto_signin?'<span class="status-line"><span class="dot on"></span>已开启</span>':'<span class="status-line"><span class="dot off"></span>已关闭</span>'));
  html.push(row('签到区间',`<code>${esc(c.sign_window_start||'')} → ${esc(c.sign_window_end||'')}</code>`));
  html.push(row('下次执行',`<code>${esc(s.next_run_at||'—')}</code>`));
  html.push(row('接口主机',`<code>${esc(c.host||'')}</code>`));

  if(t.exists && !t.empty && t.exp){
    const days=Math.floor(t.remaining_days);
    const hours=Math.floor((t.remaining_days-days)*24);
    let dotClass='on';
    if(s.status==='error') dotClass='off';
    else if(t.remaining_days<7) dotClass='warn';
    const tagTitle=t.remaining_days<7?'即将过期':'';
    html.push(row('Token 剩余',`<span class="metric" title="${tagTitle}"><span class="dot ${dotClass}"></span><span class="num">${days}</span><span class="unit">天</span><span class="num">${hours}</span><span class="unit">小时</span></span>`));
    html.push(row('Token 过期',`<code>${esc(t.exp_human)}</code>`));
    html.push(row('Token 长度',`<code>${t.length} 字节</code>`));
  }else if(t.exists && t.empty){
    html.push(row('Token','<span class="status-line"><span class="dot warn"></span>文件为空</span>'));
  }else if(!t.exists){
    html.push(row('Token','<span class="status-line"><span class="dot off"></span>文件不存在</span>'));
  }else{
    html.push(row('Token','<span class="status-line"><span class="dot warn"></span>无法解析</span>'));
  }

  // 当前账号:上次保存 Token 时自动识别到的 realUserID(读缓存,不发网络请求)
  if(t.real_user_id) html.push(row('当前账号',`<code>${esc(t.real_user_id)}</code>`));

  if(d.last_log && d.last_log.length>0){
    const last=d.last_log[d.last_log.length-1];
    html.push(row('最后日志',`<code>${esc(last.substring(0,80))}</code>`));
  }

  document.getElementById('status').innerHTML=html.join('');
}

function badge(s){
  if(s.status==='signed') return `<span class="status-line"><span class="dot on"></span>${esc(s.status_text||'今日已签到')}</span>`;
  if(s.status==='todo') return `<span class="status-line"><span class="dot warn"></span>${esc(s.status_text||'今天可领取')}</span>`;
  if(s.status==='pending') return `<span class="status-line"><span class="dot orange"></span>${esc(s.status_text||'未到执行时间')}</span>`;
  if(s.status==='no_token') return `<span class="status-line"><span class="dot warn"></span>${esc(s.status_text||'未配置 Token')}</span>`;
  return `<span class="status-line"><span class="dot off"></span>${esc(s.status_text||'签到失败')}</span>`;
}

function renderSignin(s){
  const html=[];
  html.push(row('当前状态',badge(s)));
  html.push(row('今日积分',s.today_points?`<span class="metric"><span class="num">${s.today_points}</span><span class="unit">分</span></span>`:'<span class="muted">—</span>'));
  html.push(row('签到第几天',s.day_no?`<span class="metric"><span class="num">${s.day_no}</span><span class="unit">天</span></span>`:'<span class="muted">—</span>'));
  html.push(row('上次签到',s.last_signin_time?`<code>${esc(s.last_signin_time)}</code>`:'<span class="muted">从未</span>'));
  html.push(row('下次执行',s.next_run_at?`<code>${esc(s.next_run_at)}</code>`:'<span class="muted">—</span>'));
  if(s.last_message) html.push(row('最近结果',`<code>${esc(String(s.last_message).substring(0,80))}</code>`));
  document.getElementById('signin-status').innerHTML=html.join('');

  const box=document.getElementById('auto-signin');
  if(box && document.activeElement!==box) box.checked=!!s.auto_signin;

  const ws=document.getElementById('win-start');
  const we=document.getElementById('win-end');
  if(ws && document.activeElement!==ws && s.sign_window_start) ws.value=s.sign_window_start;
  if(we && document.activeElement!==we && s.sign_window_end) we.value=s.sign_window_end;

  renderDays(s.days||[]);
}

function renderDays(days){
  const box=document.getElementById('day-grid');
  if(!days||days.length===0){box.innerHTML='<span class="muted">暂无数据,签到一次后显示</span>';return}
  const parts=[];
  for(const d of days){
    let cls='pending',label='未到';
    const st=Number(d.status);
    if(st===3){cls='claimed';label='已领'}
    else if(st===2){cls='available';label='可领'}
    else if(st===4){cls='pending';label='不满足'}
    const todayCls=d.is_today?' today':'';
    const pt=Number(d.points||0)+Number(d.bonus_points||0);
    parts.push(`<div class="day ${cls}${todayCls}"><div class="day-no">D${esc(d.day_no)}</div><div class="day-pt">${pt||'—'}</div><div class="day-st">${label}</div></div>`);
  }
  box.innerHTML=parts.join('');
}

function showMsg(id,text,isErr){
  const el=document.getElementById(id);
  if(!el) return;
  el.textContent=text||'';
  el.classList.toggle('err',!!isErr);
  if(isErr) setTimeout(()=>el.classList.remove('err'),4000);
}

async function renderLogs(){
  try{
    const r=await fetch('/api/logs?lines=30');
    if(r.status===401){location.href='/login';return}
    const d=await r.json();
    const box=document.getElementById('logs');
    const colored=d.lines.map(l=>{
      let cls='';
      if(l.includes('签到成功')||l.includes('今日已签')) cls='ok';
      else if(l.includes('失败')||l.includes('异常')||l.includes('失效')) cls='err';
      else if(l.includes('警告')||l.includes('WARN')) cls='warn';
      return cls?`<span class="${cls}">${esc(l)}</span>`:esc(l);
    });
    box.innerHTML=colored.join('\n');
    box.scrollTop=box.scrollHeight;
    document.getElementById('log-meta').textContent=`(30 行 · 5s 刷新 · ${new Date().toLocaleTimeString()})`;
  }catch(e){console.error(e)}
}

async function runSignin(){
  const btn=document.getElementById('btn-signin');
  if(btn) btn.disabled=true;
  showMsg('auto-msg','签到中…',false);
  try{
    const r=await fetch('/api/signin/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
    const d=await r.json();
    showMsg('auto-msg',d.message||(d.ok?'签到成功':'签到失败'),!d.ok);
  }catch(e){showMsg('auto-msg','请求失败: '+e.message,true)}
  if(btn) btn.disabled=false;
  refresh();
}

async function toggleAuto(el){
  const val=el.checked;
  try{
    const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({auto_signin:val})});
    const d=await r.json();
    showMsg('auto-msg',d.message||'',!d.ok);
  }catch(e){showMsg('auto-msg','请求失败: '+e.message,true)}
  refresh();
}

async function saveWindow(){
  const s=document.getElementById('win-start').value;
  const e=document.getElementById('win-end').value;
  try{
    const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sign_window_start:s,sign_window_end:e})});
    const d=await r.json();
    showMsg('window-msg',d.message||'保存失败',!d.ok);
  }catch(e){showMsg('window-msg','请求失败: '+e.message,true)}
  refresh();
}

async function updateToken(){
  const tk=document.getElementById('new-token').value.trim();
  if(!tk){alert('Token 不能为空');return}
  const r=await fetch('/api/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:tk})});
  const d=await r.json();
  showMsg('token-msg',d.message||'',!d.ok);
  if(d.ok){document.getElementById('new-token').value='';setTimeout(refresh,1000)}
}

async function updatePassword(){
  const p=document.getElementById('new-pass').value;
  if(!p||p.length<6){alert('密码至少 6 位');return}
  if(!confirm('确认修改密码?会强制重新登录'))return;
  const r=await fetch('/api/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p})});
  const d=await r.json();
  showMsg('pass-msg',d.message||'',!d.ok);
  if(d.ok){setTimeout(()=>location.href='/login',1200)}
}

refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


# ===================== 路由 =====================
# 只给前端下发前端真正用得到的配置字段:
# uuid / device_id / user_id 属于账号标识,前端不显示,没必要明文下发。
PUBLIC_CONFIG_FIELDS = (
    "host",
    "sign_window_start",
    "sign_window_end",
    "auto_signin",
    "timezone",
)


def _public_config(cfg):
    """下发用的配置:去掉 uuid / device_id / user_id 等账号标识。"""
    cfg = cfg or {}
    return {key: cfg.get(key) for key in PUBLIC_CONFIG_FIELDS}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        locked, remain = _login_lock_info(ip)
        if locked:
            return render_template_string(
                LOGIN_HTML,
                error=f"登录失败次数过多,已锁定,请 {remain} 秒后再试",
            )
        if verify_password(request.form.get("password", "")):
            _login_record_success(ip)
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        count = _login_record_failure(ip)
        if count >= LOGIN_MAX_FAILS:
            return render_template_string(
                LOGIN_HTML,
                error=f"密码错误,已连续失败 {count} 次,锁定 {LOGIN_LOCK_MINUTES} 分钟",
            )
        return render_template_string(LOGIN_HTML, error="密码错误")
    return render_template_string(LOGIN_HTML, error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/status")
@login_required
def api_status():
    cfg = signin.load_config() or {}
    return jsonify({
        "signin": build_signin_status(),
        "config": _public_config(cfg),
        "token": read_token_info(),
        "scheduler": get_scheduler_status(),
        "pid": os.getpid(),
        "last_log": read_logs(3),
    })


@app.route("/api/logs")
@login_required
def api_logs():
    try:
        n = int(request.args.get("lines", 30))
    except (TypeError, ValueError):
        n = 30
    n = max(1, min(n, 500))
    return jsonify({"lines": read_logs(n)})


@app.route("/api/signin/run", methods=["POST"])
@login_required
def api_signin_run():
    """立即签到(同步执行,返回本次结果)。"""
    result = run_signin_once(reason="manual")
    res = result.get("result")
    message = result.get("message") or ""
    if res == "claimed":
        message = f"签到成功,获得 {result.get('points', 0)} 积分(第 {result.get('day_no', 0)} 天)"
    elif res == "already":
        message = f"今日已签过(第 {result.get('day_no', 0)} 天)"
    elif res == "no_token":
        message = "未配置 Token,请先在「更新 Token」里粘贴 JWT"
    elif res == "error":
        message = f"签到失败: {message}"
    ok = res in ("claimed", "already")
    return jsonify({
        "ok": ok,
        "result": res,
        "message": message,
        "points": result.get("points", 0),
        "day_no": result.get("day_no", 0),
        "streak": result.get("streak", 0),
        "signin": build_signin_status(),
    })


@app.route("/api/config", methods=["GET", "POST"])
@login_required
def api_config():
    """GET:读配置;POST:改签到区间 / 自动签到开关。"""
    cfg = signin.load_config() or {}
    if request.method == "GET":
        return jsonify({"ok": True, "config": _public_config(cfg)})

    data = request.get_json(silent=True) or request.form or {}
    changed = []
    window_submitted = False

    for field in ("sign_window_start", "sign_window_end"):
        if field not in data:
            continue
        window_submitted = True
        val = (data.get(field) or "").strip()
        parts = val.split(":")
        if len(parts) != 2 or not all(p.isdigit() for p in parts):
            return jsonify({"ok": False, "message": f"{field} 格式错误,应为 HH:MM"}), 400
        hh, mm = int(parts[0]), int(parts[1])
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            return jsonify({"ok": False, "message": f"{field} 超出范围,应为 HH:MM"}), 400
        norm = f"{hh:02d}:{mm:02d}"
        if cfg.get(field) != norm:
            cfg[field] = norm
            changed.append(f"{field}={norm}")

    # 零长度区间拒收: 开始和结束时间相同时, 窗口会退化成"整天窗口",
    # 午夜边界上"窗口起始日"翻转, 把刚摇好、刚过点的执行时刻当成过期目标丢掉,
    # 结果整整一天没签到。跨午夜请写成 23:00 -> 01:00 这种形式(end < start 才是跨午夜)。
    if window_submitted:
        ws = str(cfg.get("sign_window_start") or "").strip()
        we = str(cfg.get("sign_window_end") or "").strip()
        if ws and we and ws == we:
            return jsonify({
                "ok": False,
                "message": "签到区间不能是零长度:开始和结束时间相同,请改成不同的时间"
                           "(跨午夜请写成 23:00 -> 01:00 这种形式)",
            }), 400

    if "auto_signin" in data:
        raw = data.get("auto_signin")
        if isinstance(raw, str):
            val = raw.strip().lower() in ("1", "true", "yes", "on")
        else:
            val = bool(raw)
        if bool(cfg.get("auto_signin", True)) != val:
            cfg["auto_signin"] = val
            changed.append(f"auto_signin={'开启' if val else '关闭'}")

    if changed:
        try:
            signin.save_config(cfg)
        except Exception as e:  # noqa: BLE001
            return jsonify({"ok": False, "message": f"保存配置失败: {e}"}), 500
        _ensure_logger().info(f"配置已更新: {', '.join(changed)}")
        # 区间变了, 之前摇好的执行时刻作废, 让下一次调度重新摇
        if any(item.startswith("sign_window_") for item in changed):
            _clear_target_state()

    return jsonify({
        "ok": True,
        "message": ("已保存: " + ", ".join(changed)) if changed else "没有变化",
        "config": _public_config(cfg),
    })


def _clear_cached_user_id():
    """清掉状态文件里缓存的"当前账号"(real_user_id)。

    Token 校验失败时必须清: 否则仪表盘「服务状态 → 当前账号」还显示着旧账号,
    用户会以为还是那个账号在签, 属于误导。
    用 update_state 的字段级删除语义(remove), 不整份覆盖状态文件。
    """
    try:
        _update_state(remove=["real_user_id", "real_user_id_synced_at"])
    except Exception as e:  # noqa: BLE001
        _ensure_logger().warning(f"清空状态文件里的当前账号失败: {e}")


@app.route("/api/token", methods=["POST"])
@login_required
def api_token():
    """校验并保存 JWT(只校验可用性,不发签到请求)。

    顺序是**先校验、后落盘**:
        1. 发 1 个只读请求 GET /v1/api/user/info,校验这个 token 还能不能用
        2. 校验通过才写 token.txt(strip + 600 权限)
        3. 校验失败 -> **原来的 token 文件保持不动**
           (以前是"先写盘再校验", 粘贴时多复制一个字符就会把能用的好 token 顶掉,
            服务直接变成"无 token")

    校验失败时还会清掉状态文件里缓存的 real_user_id, 免得仪表盘显示旧账号误导用户。

    明确**不做**:续期 token、查签到状态、领积分、动调度线程状态机。
    换句话说,保存 Token 只回答"这个 cookie 还能不能用",不消耗签到机会。
    """
    data = request.get_json(silent=True) or request.form or {}
    new_token = (data.get("token") or "").strip()
    if not new_token:
        return jsonify({"ok": False, "message": "Token 不能为空"}), 400

    # 1) 先校验(唯一的网络请求: 只读的账号信息查询)
    try:
        info = signin.fetch_user_info(new_token) or {}
    except Exception as e:  # noqa: BLE001
        _clear_cached_user_id()
        return jsonify({
            "ok": False,
            "message": f"Token 校验未通过,未保存(原 Token 文件未改动): {e}",
            "real_user_id": None,
        }), 200

    real_user_id = info.get("real_user_id")
    if not info.get("ok") or not real_user_id:
        reason = info.get("message") or "服务端未返回账号信息"
        _clear_cached_user_id()
        return jsonify({
            "ok": False,
            "message": f"Token 无效,未保存(原 Token 文件未改动): {reason}",
            "real_user_id": None,
        }), 200

    # 2) 校验通过 -> 这时才落盘(token.txt 保持 strip + 600 权限)
    try:
        signin.save_token(new_token)
    except Exception as e:  # noqa: BLE001
        return jsonify({
            "ok": False,
            "message": f"Token 校验通过,但保存到 token.txt 失败(原 Token 文件未改动): {e}",
            "real_user_id": None,
        }), 500

    real_user_id = str(real_user_id)

    # 把识别到的账号回写进配置(换账号后不用改配置)
    synced = False
    try:
        cfg = signin.load_config() or {}
        if str(cfg.get("user_id") or "") != real_user_id:
            cfg["user_id"] = real_user_id
            signin.save_config(cfg)
            synced = True
    except Exception as e:  # noqa: BLE001
        _ensure_logger().warning(f"同步 user_id 到配置失败: {e}")

    # 缓存到状态文件,供 /api/status 展示(展示时不发网络请求)
    try:
        _update_state(real_user_id=real_user_id, real_user_id_synced_at=int(time.time()))
    except Exception as e:  # noqa: BLE001
        _ensure_logger().warning(f"写账号信息到状态文件失败: {e}")

    message = (
        f"Token 可用 · 账号 realUserID 已同步({real_user_id})"
        if synced
        else f"Token 可用 · 账号已识别(realUserID={real_user_id})"
    )
    _ensure_logger().info(f"Token 已保存并校验通过,账号 realUserID={real_user_id}(user_id_synced={synced})")
    return jsonify({
        "ok": True,
        "message": message,
        "real_user_id": real_user_id,
        "user_id_synced": synced,
    })


@app.route("/api/password", methods=["POST"])
@login_required
def api_password():
    data = request.get_json(silent=True) or request.form or {}
    new_pass = (data.get("password") or "").strip()
    if not new_pass or len(new_pass) < 6:
        return jsonify({"ok": False, "message": "密码至少 6 位"}), 400
    try:
        set_password(new_pass)
        session.clear()  # 改完强制重新登录
        return jsonify({"ok": True, "message": "密码已更新,1.2 秒后跳到登录页"})
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "message": str(e)}), 500


# ===================== 启动 =====================
if __name__ == "__main__":
    # 启动前:确保 token 文件存在(空文件也行,Web 界面会引导填)
    token_status = ensure_token_file()
    if token_status == "created":
        print(f"\n⚠️  Token 文件不存在,已自动创建空文件: {TOKEN_FILE}", file=sys.stderr)
        print("   登录 Web 后在「更新 Token」填入即可,无需重启\n", file=sys.stderr)

    # 单进程架构:Web 启动时拉起签到调度线程
    # 线程第一轮立即判断:今天该签还没签 → 立刻补签,不等 30 秒轮询
    start_signin_thread()

    print(f"\n{'='*60}", file=sys.stderr)
    print("🌐 MiniMax 每日签到 Web 界面", file=sys.stderr)
    print(f"   地址: http://{args.host}:{args.port}", file=sys.stderr)
    if initial_password_printed:
        print(f"\n   🔐 初始密码: {initial_password_printed}", file=sys.stderr)
        print(f"   (已加密保存到 {PASS_FILE},登录后可在界面修改)", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
