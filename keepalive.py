#!/usr/bin/env python3
"""
MiniMax Code 会话保活服务(v3 - 模块化)
==========================================

两种运行模式:
    1. CLI 模式:`python3 keepalive.py`
       独立进程,SIGTERM 优雅退出
    2. 线程模式:被 `keepalive-web.py` import
       在 Web 进程里跑后台线程,通过 Event 控制启停

部署:
    pip3 install requests
    chmod +x /opt/minimax-keepalive.py
    nohup python3 /opt/minimax-keepalive.py > /var/log/minimax-keepalive.log 2>&1 &
"""

import os
import sys
import time
import json
import base64
import signal
import logging
import threading
import requests
from datetime import datetime, timezone


# ===================== 配置 =====================

# 默认路径:跟脚本同目录(token.txt / keepalive.log 放一起)
# 想要放别处可以用环境变量覆盖:
#   MINIMAX_TOKEN_FILE=/path/to/token.txt
#   MINIMAX_LOG_FILE=/var/log/keepalive.log
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.environ.get("MINIMAX_TOKEN_FILE") or os.path.join(SCRIPT_DIR, "token.txt")
LOG_FILE = os.environ.get("MINIMAX_LOG_FILE") or os.path.join(SCRIPT_DIR, "keepalive.log")
INTERVAL_SECONDS = 300  # 5 分钟
REQUEST_TIMEOUT = 10

# 候选保活端点(按顺序,首个 200 即视为成功)
HEARTBEAT_ENDPOINTS = [
    "/v1/api/user/info",
    "/v1/api/config/web/common_config",
    "/matrix/api/v1/user/get_user_extra_info",
]

# 浏览器请求里带的固定 query 参数(分析/路由用)
STATIC_QUERY_PARAMS = {
    "device_platform": "web",
    "biz_id": "3",
    "app_id": "3001",
    "version_code": "22201",
    "timezone_offset": "28800",
    "sys_language": "zh",
    "lang": "zh",
    "uuid": "651066bf-d1ac-40e2-bb30-78d08f671c97",
    "device_id": "84269071",
    "os_name": "macOS",
    "browser_name": "Chrome",
    "device_memory": "16",
    "cpu_core_num": "8",
    "browser_language": "zh-CN",
    "browser_platform": "MacIntel",
    "user_id": "",  # 留空,服务端不强校验;想精准伪装就填你自己的 user_id
    "screen_width": "1440",
    "screen_height": "900",
    "client": "web",
}

BASE_URL = "https://agent.minimaxi.com"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/130.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Referer": "https://agent.minimaxi.com/",
    "Origin": "https://agent.minimaxi.com",
}


# ===================== 日志 =====================

def setup_logging():
    """配置 logger,同进程内多次调用只产生一个实例。"""
    logger = logging.getLogger("keepalive")
    if logger.handlers:  # 已经配过,直接复用
        return logger
    logger.setLevel(logging.INFO)

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

    if sys.stdout.isatty():
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    return logger


# ===================== Token 加载与校验 =====================

def ensure_token_file():
    """启动时确保 token 文件存在(空文件也行),方便首次部署不用手动创建。

    返回:
        "exists"  - 文件本来就有
        "created" - 这次自动创建的
        "failed"  - 创建失败(权限/磁盘问题)
    """
    if os.path.exists(TOKEN_FILE):
        return "exists"
    try:
        # 父目录不存在时一并建(放 /opt/ 这种需要 root,放 wwwroot 不用)
        parent = os.path.dirname(TOKEN_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            pass  # 创建空文件
        try:
            os.chmod(TOKEN_FILE, 0o600)
        except OSError:
            pass
        return "created"
    except OSError as e:
        print(f"[WARN] 无法自动创建 token 文件 {TOKEN_FILE}: {e}", file=sys.stderr)
        return "failed"


def load_token():
    """读 token 文件,清洗格式。失败抛 RuntimeError。"""
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        raise RuntimeError(f"Token 文件不存在: {TOKEN_FILE}")
    except OSError as e:
        raise RuntimeError(f"读取 token 文件失败: {e}")

    if not raw:
        raise RuntimeError(f"Token 文件为空: {TOKEN_FILE}")

    return raw


def jwt_exp_unix(token):
    """从 JWT 解析 exp(unix 秒),失败返回 None。"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes)
        return int(payload.get("exp", 0)) or None
    except Exception:  # noqa: BLE001
        return None


def format_remaining(exp_unix):
    """把剩余时间格式化成 'X 天 Y 小时'。"""
    if not exp_unix:
        return "未知"
    now = int(time.time())
    remaining = exp_unix - now
    if remaining <= 0:
        return "已过期"
    days, rem = divmod(remaining, 86400)
    hours = rem // 3600
    return f"剩 {days} 天 {hours} 小时"


# ===================== 单次探测 =====================

def probe(session, path, token, logger):
    """对单个 endpoint 发一次 GET,带 token。"""
    params = dict(STATIC_QUERY_PARAMS)
    params["unix"] = str(int(time.time() * 1000))
    params["token"] = token
    url = f"{BASE_URL}{path}"
    try:
        resp = session.get(
            url, params=params, headers=HEADERS,
            timeout=REQUEST_TIMEOUT, allow_redirects=True,
        )
        return True, resp.status_code, resp
    except requests.exceptions.Timeout:
        return False, "TIMEOUT", None
    except requests.exceptions.ConnectionError:
        return False, "CONNECTION_ERROR", None
    except requests.exceptions.RequestException as e:
        return False, f"REQUEST_ERROR({type(e).__name__})", None


def tick(session, token, logger, on_tick=None):
    """
    按顺序尝试候选端点,首个 200 视为成功。

    返回: "ok" | "token_invalid" | "server_error" | "network_error" | "failed"
    on_tick: 可选回调 on_tick(result, path, status_code),被调用于每种结果
    """
    for path in HEARTBEAT_ENDPOINTS:
        ok, info, _ = probe(session, path, token, logger)
        if not ok:
            logger.warning(f"网络异常 {path} -> {info}")
            if on_tick: on_tick("network_error", path, None)
            continue
        status = info
        if status == 200:
            logger.info(f"OK - {path} (200)")
            if on_tick: on_tick("ok", path, status)
            return "ok"
        if status in (401, 403):
            logger.warning(
                f"TOKEN 失效 ({status}) - 在 Web 界面「更新 Token」填一个新的"
            )
            if on_tick: on_tick("token_invalid", path, status)
            return "token_invalid"
        if 500 <= status < 600:
            logger.warning(f"服务端错误 {status},尝试下一个 ({path})")
            if on_tick: on_tick("server_error", path, status)
            continue
        logger.info(f"跳过 {path} (状态码 {status})")
    logger.warning("本轮所有候选端点都没有成功")
    if on_tick: on_tick("failed", None, None)
    return "failed"


# ===================== 主循环(可独立运行 / 可被外部调用) =====================

def run_keepalive_forever(stop_event, logger, session=None, on_tick=None):
    """
    保活主循环,直到 stop_event 被 set 时优雅退出。

    参数:
        stop_event: threading.Event,set 时主循环在下一次检查时退出
        logger:     已配置好的 logger 实例
        on_tick:    可选回调 on_tick(result, path, status_code),Web 用来同步状态显示
                    result ∈ {"ok", "no_token", "token_invalid", "server_error", "network_error", "failed"}
        session:    可选,requests.Session(不传则新建)
    """
    if session is None:
        session = requests.Session()
        session.trust_env = False

    first_tick = True
    while not stop_event.is_set():
        try:
            token = load_token()
            if first_tick:
                exp = jwt_exp_unix(token)
                if exp:
                    logger.info(
                        f"Token 过期时间: {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()} "
                        f"({format_remaining(exp)})"
                    )
                first_tick = False
            tick(session, token, logger, on_tick=on_tick)
        except RuntimeError as e:
            logger.error(f"本轮跳过: {e}")
            if on_tick: on_tick("no_token", None, None)
        except Exception as e:  # noqa: BLE001
            logger.exception(f"未预期异常: {e}")
            if on_tick: on_tick("error", None, None)

        # 可中断 sleep
        for _ in range(INTERVAL_SECONDS):
            if stop_event.is_set():
                break
            time.sleep(1)

    try:
        session.close()
    except Exception:  # noqa: BLE001
        pass


# ===================== CLI 入口 =====================

def main():
    logger = setup_logging()
    logger.info("=" * 50)
    logger.info("MiniMax keepalive 启动 (v3 - 模块化)")
    logger.info(
        f"配置: 间隔={INTERVAL_SECONDS}s, 超时={REQUEST_TIMEOUT}s, "
        f"候选端点数={len(HEARTBEAT_ENDPOINTS)}"
    )

    # 启动时:确保 token 文件存在(空文件也行,后面 Web 界面会引导填)
    status = ensure_token_file()
    if status == "created":
        logger.info(f"Token 文件不存在,已自动创建空文件: {TOKEN_FILE}")
        logger.info("请通过 Web 界面填入 token,或直接编辑此文件")

    # 启动时尝试读 token,失败不退出
    try:
        token = load_token()
        exp = jwt_exp_unix(token)
        logger.info(
            f"Token 加载成功(长度 {len(token)} 字节,过期时间 {format_remaining(exp)})"
        )
    except RuntimeError as e:
        logger.warning(
            f"启动时 token 读取失败(进程继续运行,主循环会重试): {e}"
        )

    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda s, f: stop_event.set())
    signal.signal(signal.SIGINT, lambda s, f: stop_event.set())

    run_keepalive_forever(stop_event, logger)

    logger.info("MiniMax keepalive 收到退出信号,正常退出")
    sys.exit(0)


if __name__ == "__main__":
    main()
