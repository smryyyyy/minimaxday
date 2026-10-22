#!/usr/bin/env python3
"""
MiniMax Code 每日自动签到模块
================================

功能:
    1. 续期 JWT token(把新 token 写回 token.txt)
    2. 查询签到面板(连签天数 / 今日是否可领 / 积分)
       连签天数口径 = 服务端 day_no(今天已领)/ day_no - 1(今天未领),详见 _streak_value
    3. 领取积分(幂等:今日已领过返回 claim_result=2 也算成功)
    4. 一次性跑完整流程(run_checkin)
    5. 定时调度时间点计算(pick_daily_time / next_run_at)

本模块只依赖标准库 + requests,可被 Web 层(keepalive-web.py)import 调用,
也可以单独当脚本用:

    python3 signin.py          # 立刻跑一次签到

约定:
    - token 存放在脚本同目录 token.txt,可用环境变量 MINIMAX_TOKEN_FILE 覆盖
    - 配置存放在脚本同目录 config.json,可用环境变量 MINIMAX_CONFIG_FILE 覆盖
    - 签到状态存放在脚本同目录 .signin-state.json,可用 MINIMAX_SIGNIN_STATE_FILE 覆盖
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import random
import sys
import tempfile
import threading
import time
from datetime import date, datetime, time as dt_time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

try:  # Python 3.9+ 标准库;系统缺 tzdata 时回退到固定 +08:00
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - 老 Python 兜底
    ZoneInfo = None  # type: ignore[assignment]


# ===================== 常量 =====================

# 脚本所在目录(所有默认文件路径都基于它推导)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 三个业务端点
RENEW_PATH = "/v1/api/user/renewal"
STATUS_PATH = "/minimax-cloud/api/v1/signin/status"
CLAIM_PATH = "/minimax-cloud/api/v1/signin/claim"

# 账号信息端点(只读):按 token 查出它属于哪个账号(realUserID)
# 这是"换账号只需换 token"的基础 —— user_id 不再靠手填,直接问服务端
USER_INFO_PATH = "/v1/api/user/info"

# 签名盐值(与服务端一致,硬编码)
SIGN_SALT = "I*7Cf%WZ#S&%1RlZJ&C2"

# 签到区间的默认值: 零长度区间(开始和结束时间相同)时退化到这里
DEFAULT_WINDOW_START = "00:30"
DEFAULT_WINDOW_END = "02:00"

# 零长度区间只警告一次: 调度线程 30 秒一轮, 不去重会把日志刷爆
_ZERO_WINDOW_WARNED: set = set()

# 请求超时(秒)
REQUEST_TIMEOUT = 15

# 默认配置:与 config.json 合并时用于补齐缺失字段
DEFAULT_CONFIG: Dict[str, Any] = {
    "host": "agent.minimax.cn",
    "uuid": "",
    "device_id": "",
    "user_id": "",
    "sign_window_start": "00:30",
    "sign_window_end": "02:00",
    "timezone": "Asia/Shanghai",
    "auto_signin": True,
}

# 固定设备参数(与网页端抓包一致)
FIXED_PARAMS: Dict[str, str] = {
    "device_platform": "web",
    "biz_id": "3",
    "app_id": "3001",
    "version_code": "22201",
    "timezone_offset": "28800",
    "sys_language": "zh",
    "lang": "zh",
    "os_name": "macOS",
    "browser_name": "Chrome",
    "device_memory": "16",
    "cpu_core_num": "8",
    "browser_language": "zh-CN",
    "browser_platform": "MacIntel",
    "screen_width": "1366",
    "screen_height": "768",
    "client": "web",
}

BASE_HEADERS: Dict[str, str] = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/130.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
}

# 签到格子状态
DAY_STATUS_NOT_ARRIVED = 1  # 未到(还没到可签时间)
DAY_STATUS_CLAIMABLE = 2  # 可领
DAY_STATUS_CLAIMED = 3  # 已领
DAY_STATUS_UNQUALIFIED = 4  # 不符合条件

# 面板场景
SCENE_UNKNOWN = 0
SCENE_FIRST = 1
SCENE_RUNNING = 2
SCENE_DONE = 3
SCENE_BROKEN = 4

# 领取结果
CLAIM_RESULT_SUCCESS = 1  # 本次真的领到了
CLAIM_RESULT_ALREADY = 2  # 今日已领过


# ===================== 日志 =====================

LOG_FORMAT = "[%(asctime)s] %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 模块级 logger(沿用原项目「同名风格」的写法,名字叫 signin)
LOGGER = logging.getLogger("signin")
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(logging.NullHandler())


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """给模块 logger 挂一个 stderr 输出,格式沿用原项目「单行时间戳 + 消息」的风格。

    返回配置好的 logger;重复调用不会重复挂 handler。
    """
    if any(isinstance(h, logging.StreamHandler) for h in LOGGER.handlers):
        LOGGER.setLevel(level)
        return LOGGER

    LOGGER.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT))
    LOGGER.addHandler(handler)
    return LOGGER


# ===================== 通用小工具 =====================


def _script_dir() -> str:
    """脚本所在目录。"""
    return os.path.dirname(os.path.abspath(__file__))


def _atomic_write(path: str, content: str, mode: int = 0o600) -> None:
    """原子写文件:先写同目录临时文件,再 os.replace 覆盖目标。

    这样中途失败不会留下半截文件。
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_signin_", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _tzinfo(cfg: Optional[Dict[str, Any]] = None) -> Any:
    """取配置里的时区;拿不到就退回东八区固定偏移。"""
    name = "Asia/Shanghai"
    if cfg:
        name = str(cfg.get("timezone") or name)
    if ZoneInfo is not None:
        try:
            return ZoneInfo(name)
        except Exception:  # noqa: BLE001 - 系统缺 tzdata 等情况
            pass
    return timezone(timedelta(hours=8))


def _now_in_tz(cfg: Optional[Dict[str, Any]] = None) -> datetime:
    """当前时间(配置时区)。"""
    return datetime.now(_tzinfo(cfg))


def _parse_hhmm(value: Any, default: Tuple[int, int] = (0, 0)) -> Tuple[int, int]:
    """把 "HH:MM" 解析成 (时, 分);格式不对就用默认值。"""
    try:
        parts = str(value).strip().split(":")
        hh = int(parts[0])
        mm = int(parts[1])
        if not (0 <= hh <= 23 and 0 <= mm <= 59):
            return default
        return hh, mm
    except Exception:  # noqa: BLE001
        return default


def _as_date(value: Any) -> date:
    """把 date / datetime / ISO 字符串统一成 date。"""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return datetime.fromisoformat(str(value)).date()


def _int_or(value: Any, default: int = 0) -> int:
    """尽量转 int,失败用默认值。"""
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


def _error_message(data: Any, status_code: int) -> str:
    """从响应体里提取一句能直接给人看的错误描述。"""
    if isinstance(data, dict):
        err = data.get("error")
        if err:
            return str(err)
        base_resp = data.get("base_resp")
        if isinstance(base_resp, dict) and base_resp.get("status_msg"):
            return str(base_resp.get("status_msg"))
        status_info = data.get("statusInfo")
        if isinstance(status_info, dict) and status_info.get("message"):
            return str(status_info.get("message"))
    return f"HTTP {status_code}"


def _streak_value(days: Optional[List[Dict[str, Any]]], day_no: Any = 0) -> int:
    """连签天数的统一口径(claim_points / run_checkin 共用, 保证两条路径取值一致)。

    口径(以服务端 day_no 为准):
        服务端的 day_no 是「含今天」的连签计数(真实抓包:第一天就是 day_no=1),
        真实面板是 [今天, 今天+1, …, 今天+6] 的未来格, **永远不存在 day_no 更小的历史格**,
        所以连签天数不能靠「从昨天往回数已领格数」算 —— 那样恒等于 0。

        streak = day_no - (今天这一格还没领 ? 1 : 0), 下界 0
            - 今天那格 status == 3(已领) -> streak = day_no
            - 今天那格 status != 3(还没领) -> streak = max(day_no - 1, 0)
            - 面板里没有 is_today 格 -> 兜底 max(day_no - 1, 0)(保守, 宁可少算一天)
            - 面板为空 / day_no 缺失 -> 0

    day_no 优先取面板里今天那格自带的, 取不到才用调用方传入的服务端 day_no。
    """
    items = [d for d in (days or []) if isinstance(d, dict)]

    today_cell: Optional[Dict[str, Any]] = None
    for item in items:
        if item.get("is_today"):
            today_cell = item
            break

    # day_no: 优先用今天那格自带的, 没有就用调用方传进来的服务端值
    effective = _int_or(today_cell.get("day_no"), 0) if today_cell is not None else 0
    if effective <= 0:
        effective = _int_or(day_no, 0)
    if effective <= 0:
        return 0

    # 今天已领(status==3)时今天这一格计入连签, 还没领则不计入
    claimed_today = (
        today_cell is not None
        and _int_or(today_cell.get("status"), 0) == DAY_STATUS_CLAIMED
    )
    if claimed_today:
        return effective
    return max(effective - 1, 0)


# ===================== 配置 =====================


def config_path() -> str:
    """配置文件路径(默认脚本同目录 config.json,可用环境变量覆盖)。"""
    return os.environ.get("MINIMAX_CONFIG_FILE") or os.path.join(_script_dir(), "config.json")


def default_config() -> dict:
    """返回一份全新的默认配置(每次都是新对象,不会共享可变状态)。"""
    return dict(DEFAULT_CONFIG)


def load_config() -> dict:
    """读取配置文件并与默认配置合并(文件里的值优先)。

    文件不存在或损坏时返回默认配置,不抛异常。
    """
    cfg = default_config()
    path = config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return cfg
    except (OSError, ValueError) as exc:
        LOGGER.warning("配置文件读取失败(%s),改用默认配置: %s", path, exc)
        return cfg

    if isinstance(raw, dict):
        for key, value in raw.items():
            if value is not None:
                cfg[key] = value
    return cfg


def save_config(cfg: dict) -> None:
    """原子写配置文件(UTF-8,缩进 2)。"""
    payload = json.dumps(cfg, ensure_ascii=False, indent=2) + "\n"
    _atomic_write(config_path(), payload, mode=0o600)


# ===================== 凭据(token) =====================


def token_path() -> str:
    """token 文件路径(默认脚本同目录 token.txt,可用环境变量覆盖)。"""
    return os.environ.get("MINIMAX_TOKEN_FILE") or os.path.join(_script_dir(), "token.txt")


def load_token() -> str:
    """读取 token;文件不存在或为空时抛 RuntimeError(消息可直接展示给用户)。"""
    path = token_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        raise RuntimeError(f"Token 文件不存在: {path}")
    except OSError as exc:
        raise RuntimeError(f"读取 Token 文件失败: {exc}")

    if not raw:
        raise RuntimeError(f"Token 文件为空: {path}")
    return raw


def save_token(token: str) -> None:
    """写 token 到 token.txt(权限 600);token 为空则不写。"""
    value = (token or "").strip()
    if not value:
        LOGGER.warning("token 为空,不写入 %s", token_path())
        return
    _atomic_write(token_path(), value, mode=0o600)


def token_exp(token: str) -> Optional[int]:
    """解析 JWT 的 exp(unix 秒),不做签名校验;解析不出来返回 None。"""
    try:
        parts = (token or "").split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = int(payload.get("exp", 0))
        return exp or None
    except Exception:  # noqa: BLE001
        return None


# ===================== 请求与签名 =====================


def build_params(cfg: dict, token: str, user_id: Optional[str] = None) -> dict:
    """拼网页端固定设备参数 + unix 毫秒时间戳 + token。

    user_id 参数为 None 时用配置里的值(保持老行为);
    非 None 时用传入值(自动识别出来的 realUserID 走这条路;
    传空串则表示"不带 user_id", 用于只读端点做防御性置空)。
    """
    cfg = cfg or {}
    params: Dict[str, str] = dict(FIXED_PARAMS)
    params["unix"] = str(int(time.time() * 1000))
    params["uuid"] = str(cfg.get("uuid") or "")
    params["device_id"] = str(cfg.get("device_id") or "")
    # user_id 必须是账号的 realUserID,不是 JWT 里的 user.id
    if user_id is None:
        params["user_id"] = str(cfg.get("user_id") or "")
    else:
        params["user_id"] = str(user_id or "")
    # 允许配置里显式覆盖时区偏移,默认国内站 28800
    if cfg.get("timezone_offset") is not None:
        params["timezone_offset"] = str(cfg.get("timezone_offset"))
    params["token"] = (token or "").strip()
    return params


def sign_headers(ts: str, body_str: str) -> dict:
    """按协议计算签名头。

    x-signature = md5(f"{ts}{盐值}{实际发送的 body}")
    body_str 必须与真正发出去的字节一致(GET/renewal 为空串,claim 为 "{}")。
    """
    raw = f"{ts}{SIGN_SALT}{body_str or ''}"
    signature = hashlib.md5(raw.encode("utf-8")).hexdigest()
    return {"x-timestamp": str(ts), "x-signature": signature}


def _request(
    cfg: dict,
    path: str,
    method: str,
    body_str: str,
    token: str,
    session: Optional[Any] = None,
    user_id: Optional[str] = None,
) -> Tuple[int, Optional[dict], str]:
    """发一次带签名的请求。

    返回 (status_code, data, err):
        - 正常返回:status_code 是 HTTP 状态码,data 是解析后的 JSON,err 为空串
        - HTTP 非 200:status_code 是状态码,data 可能是解析出的 JSON,err 是可读错误
        - 网络异常:status_code 为 0,data 为 None,err 是异常描述

    user_id: 传给 build_params 的 user_id(None = 用配置里的值)。
    """
    cfg = cfg or {}
    host = str(cfg.get("host") or DEFAULT_CONFIG["host"]).strip()
    url = f"https://{host}{path}"

    params = build_params(cfg, token, user_id=user_id)
    ts = str(int(time.time()))
    headers = dict(BASE_HEADERS)
    # content-type 只在有 body 时才带:
    # - claim 的 body 是字面量 "{}" -> 带 content-type: application/json
    # - renewal / status 是空 body -> 不带(真实客户端的 renewal 只有 content-length: 0)
    if body_str:
        headers["Content-Type"] = "application/json"
    else:
        headers.pop("Content-Type", None)
    headers["Referer"] = f"https://{host}/"
    headers["Origin"] = f"https://{host}"
    headers.update(sign_headers(ts, body_str))
    # token 放 HTTP 头(renewal 端点必须走头,只放 query 会 400)
    clean_token = (token or "").strip()
    if clean_token:
        headers["token"] = clean_token

    own_session = False
    if session is None:
        session = requests.Session()
        # 忽略系统代理,避免代理把请求带偏
        session.trust_env = False
        own_session = True

    try:
        method = str(method).upper()
        if method == "GET":
            resp = session.get(
                url,
                params=params,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
        else:
            resp = session.request(
                method,
                url,
                params=params,
                headers=headers,
                data=(body_str or ""),
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

        status_code = int(resp.status_code)
        try:
            text = resp.text or ""
        except Exception:  # noqa: BLE001
            text = ""
        data: Optional[dict]
        if not text.strip():
            data = {}
        else:
            try:
                parsed = resp.json()
                data = parsed if isinstance(parsed, dict) else {"data": parsed}
            except Exception:  # noqa: BLE001 - 响应不是 JSON
                data = None

        if status_code != 200:
            return status_code, data, _error_message(data, status_code)
        if data is None:
            return status_code, None, "响应不是合法的 JSON"
        return status_code, data, ""
    except requests.exceptions.RequestException as exc:
        return 0, None, f"网络异常: {type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        return 0, None, f"请求失败: {type(exc).__name__}: {exc}"
    finally:
        if own_session:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass


# ===================== 账号识别 =====================


def fetch_user_info(token: str, cfg: Optional[dict] = None, session: Optional[Any] = None) -> dict:
    """GET /v1/api/user/info —— 查这个 token 属于哪个账号。

    返回 {"ok", "code", "message", "real_user_id", "name"}:
        - 成功:ok=True, real_user_id = data.userInfo.realUserID
        - 401:ok=False, message 说清"token 无效或已过期"
        - 网络异常:ok=False, message 带异常描述

    这个端点是只读的:不查签到状态、不领积分、不续期 token,
    纯粹用来按 token 反查账号(realUserID)。
    注意 realUserID 才是账号 ID,JWT 里的 user.id 是另一套编号,不能拿来用。
    """
    cfg = load_config() if cfg is None else cfg
    result: Dict[str, Any] = {
        "ok": False,
        "code": None,
        "message": "",
        "real_user_id": None,
        "name": None,
    }

    clean_token = (token or "").strip()
    if not clean_token:
        result["message"] = "缺少 token,无法查询账号信息"
        return result

    # GET,body 为空串,签名按空串算
    # user_id 显式置空: 实测该端点完全不校验 user_id(正确/错误/留空都返回同一个账号),
    # 所以置空当前无害; 这是防御性措施 —— 万一服务端将来加上校验,
    # 也不至于让"发现账号"这一步因为带着旧账号的 user_id 被拒,
    # 从而静默回退旧 user_id -> status/claim 401 这种最难查的故障。
    status_code, data, err = _request(
        cfg, USER_INFO_PATH, "GET", "", clean_token, session=session, user_id=""
    )

    if status_code == 0:
        result["message"] = err or "查询账号信息失败"
        return result
    if status_code == 401:
        result["message"] = "token 无效或已过期(401),请重新抓取 Token"
        return result
    if status_code != 200:
        result["message"] = err or f"查询账号信息失败(HTTP {status_code})"
        return result

    status_info = (data or {}).get("statusInfo") or {}
    code = status_info.get("code")
    result["code"] = code
    if code is not None and code != 0:
        result["message"] = str(status_info.get("message") or err or "查询账号信息失败")
        return result

    user_info = ((data or {}).get("data") or {}).get("userInfo") or {}
    real_user_id = user_info.get("realUserID")
    if not real_user_id:
        result["message"] = "账号信息里没有 realUserID"
        return result

    result["real_user_id"] = str(real_user_id)
    result["name"] = user_info.get("name")
    result["ok"] = True
    result["message"] = str(status_info.get("message") or "ok")
    return result


def resolve_user_id(token: str, cfg: Optional[dict] = None, session: Optional[Any] = None) -> Tuple[Optional[str], dict]:
    """定出这个 token 该用的 user_id,返回 (user_id, info_result)。

    优先用 fetch_user_info 自动发现到的 realUserID;
    拿不到(接口失败 / 没返回)时回退到配置里手填的 cfg["user_id"];
    两个都没有 -> user_id 为 None,由调用方报错。

    info_result 里额外带一个 "user_id_source": "auto" / "config" / "none"。
    """
    cfg = load_config() if cfg is None else cfg
    info = dict(fetch_user_info(token, cfg=cfg, session=session) or {})

    auto_user_id = info.get("real_user_id")
    if info.get("ok") and auto_user_id:
        info["user_id_source"] = "auto"
        return str(auto_user_id), info

    cfg_user_id = str(cfg.get("user_id") or "").strip()
    if cfg_user_id:
        info["user_id_source"] = "config"
        return cfg_user_id, info

    info["user_id_source"] = "none"
    return None, info


# ===================== 三个业务动作 =====================


def renew_token(
    token: str,
    cfg: Optional[dict] = None,
    session: Optional[Any] = None,
) -> dict:
    """续期 token。

    返回 {"ok", "new_token", "code", "message"};
    成功时新 token 会自动写回 token.txt。
    """
    cfg = load_config() if cfg is None else cfg
    result: Dict[str, Any] = {
        "ok": False,
        "new_token": None,
        "code": None,
        "message": "",
    }

    clean_token = (token or "").strip()
    if not clean_token:
        result["message"] = "缺少 token,无法续期"
        return result

    # body 必须是空串(不是 "{}"),签名按空串算
    status_code, data, err = _request(cfg, RENEW_PATH, "POST", "", clean_token, session=session)

    if status_code == 0:
        result["message"] = err or "续期请求失败"
        return result
    if status_code != 200:
        result["message"] = err or f"续期失败(HTTP {status_code})"
        return result

    status_info = (data or {}).get("statusInfo") or {}
    code = status_info.get("code")
    result["code"] = code
    message = str(status_info.get("message") or "")

    if code == 0:
        new_token = ((data or {}).get("data") or {}).get("token")
        if new_token:
            result["ok"] = True
            result["new_token"] = str(new_token)
            result["message"] = message or "续期成功"
            try:
                save_token(result["new_token"])
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("新 token 写回文件失败: %s", exc)
                result["message"] = f"{result['message']}(但新 token 写回文件失败: {exc})"
        else:
            result["message"] = "续期响应里没有新 token"
    else:
        # 服务端这个提示不区分"签名错"和"token 缺",这里补一句排查提示
        result["message"] = f"续期失败: {message or err or '未知原因'}(注意 token 需放在 HTTP 头 token: 上)"
    return result


def fetch_signin_status(
    token: str,
    cfg: Optional[dict] = None,
    session: Optional[Any] = None,
    user_id: Optional[str] = None,
) -> dict:
    """查询签到面板。

    返回 {"ok", "code", "message", "scene", "days", "today"};
    today 是 days 里 is_today 为真的那一格,没有则 None。

    user_id 为 None 时用配置里的值,非 None 时用传入值(自动识别路径)。
    """
    cfg = load_config() if cfg is None else cfg
    result: Dict[str, Any] = {
        "ok": False,
        "code": None,
        "message": "",
        "scene": None,
        "days": [],
        "today": None,
    }

    clean_token = (token or "").strip()
    if not clean_token:
        result["message"] = "缺少 token,无法查询签到状态"
        return result

    # GET,body 为空串
    status_code, data, err = _request(
        cfg, STATUS_PATH, "GET", "", clean_token, session=session, user_id=user_id
    )

    if status_code == 0:
        result["message"] = err or "查询签到状态失败"
        return result
    if status_code != 200:
        result["message"] = err or f"查询签到状态失败(HTTP {status_code})"
        return result

    base_resp = (data or {}).get("base_resp") or {}
    code = base_resp.get("status_code")
    result["code"] = code

    if code != 0:
        result["message"] = str(base_resp.get("status_msg") or err or "查询签到状态失败")
        return result

    payload = (data or {}).get("data") or {}
    days = payload.get("days")
    result["days"] = days if isinstance(days, list) else []
    result["scene"] = payload.get("scene")

    today: Optional[Dict[str, Any]] = None
    for item in result["days"]:
        if isinstance(item, dict) and item.get("is_today"):
            today = item
            break
    result["today"] = today
    result["ok"] = True
    result["message"] = str(base_resp.get("status_msg") or "ok")
    return result


def claim_points(
    token: str,
    cfg: Optional[dict] = None,
    session: Optional[Any] = None,
    user_id: Optional[str] = None,
) -> dict:
    """领取积分。

    返回 {"ok", "code", "message", "claim_result", "points", "day_no",
    "streak", "already", "expire_at_ms"};
    claim_result 为 1(本次领到)或 2(今日已领)都算成功,天然幂等。

    user_id 为 None 时用配置里的值,非 None 时用传入值(自动识别路径)。
    """
    cfg = load_config() if cfg is None else cfg
    result: Dict[str, Any] = {
        "ok": False,
        "code": None,
        "message": "",
        "claim_result": None,
        "points": 0,
        "day_no": 0,
        "streak": 0,
        "already": False,
        "expire_at_ms": None,
    }

    clean_token = (token or "").strip()
    if not clean_token:
        result["message"] = "缺少 token,无法领取积分"
        return result

    # POST,body 必须是字面量 "{}"(两个字符)
    status_code, data, err = _request(
        cfg, CLAIM_PATH, "POST", "{}", clean_token, session=session, user_id=user_id
    )

    if status_code == 0:
        result["message"] = err or "领取积分失败"
        return result
    if status_code != 200:
        result["message"] = err or f"领取积分失败(HTTP {status_code})"
        return result

    base_resp = (data or {}).get("base_resp") or {}
    code = base_resp.get("status_code")
    result["code"] = code

    if code != 0:
        result["message"] = str(base_resp.get("status_msg") or err or "领取积分失败")
        return result

    payload = (data or {}).get("data") or {}
    claim_result = payload.get("claim_result")
    result["claim_result"] = claim_result
    result["points"] = _int_or(payload.get("points"), 0)
    result["day_no"] = _int_or(payload.get("day_no"), 0)
    expire_at = payload.get("expire_at_ms")
    result["expire_at_ms"] = _int_or(expire_at, 0) or None

    panel = payload.get("panel") or {}
    # 与 run_checkin 同一口径: 面板格子优先, 算不出时退回服务端给的 day_no
    result["streak"] = _streak_value(
        panel.get("days") if isinstance(panel, dict) else None, result["day_no"]
    )

    if claim_result == CLAIM_RESULT_SUCCESS:
        result["ok"] = True
        result["already"] = False
        result["message"] = f"领取成功,{result['points']} 积分"
    elif claim_result == CLAIM_RESULT_ALREADY:
        result["ok"] = True
        result["already"] = True
        result["message"] = "今天已经领过了"
    else:
        result["message"] = str(base_resp.get("status_msg") or "领取结果未知")
    return result


# ===================== 全流程 =====================


def _merge_claim_counters(result: Dict[str, Any], claim: Dict[str, Any]) -> None:
    """把 claim 响应里的 day_no / streak 合并进 result(取不到真值就沿用面板阶段的取值)。

    注意:claim 响应里这两个键**总是存在**(claim_points 的初值就是 0), 所以
    `dict.get(key, default)` 里的 default 根本不会生效 —— claim 失败时它们是 0,
    会把面板阶段已经拿到的真值(day_no / streak)直接清零。

    「有没有真值」的判据是 claim 的 day_no:
      - day_no > 0: 服务端确实给了计数, 它配套算出来的 streak 一并采用
        (streak 的合法最小值就是 0 —— 第 1 天还没领过时就是 0, 不能当成"没值"丢掉)
      - day_no == 0: claim 没给出有效计数, 它算出来的 streak 也必然是 0, 没有意义,
        两个值一起沿用面板阶段(状态接口)的取值
    """
    claim_day_no = _int_or(claim.get("day_no"), 0)
    if claim_day_no <= 0:
        return
    result["day_no"] = claim_day_no
    result["streak"] = _int_or(claim.get("streak"), 0)


def _apply_notes(result: Dict[str, Any], notes: List[str]) -> Dict[str, Any]:
    """把说明(notes)拼到结果 message 的前面,返回 result(原地改)。

    例:notes=["检测到账号切换,user_id 已自动更新"] + message="领取成功,100 积分"
    -> "检测到账号切换,user_id 已自动更新；领取成功,100 积分"
    """
    if notes:
        base = result.get("message") or ""
        result["message"] = "；".join(list(notes) + ([base] if base else []))
    return result


def run_checkin(
    token: Optional[str] = None,
    cfg: Optional[dict] = None,
    logger: Optional[logging.Logger] = None,
    session: Optional[Any] = None,
) -> dict:
    """跑一次完整签到流程。

    顺序:读 token -> 续期(成功则用新 token 继续) -> 自动识别账号(user_id)
          -> 查签到面板 -> 今日可领则领取。

    返回 {"ok", "result", "message", "points", "day_no", "streak",
    "expire_at_ms", "token_exp", "token_renewed",
    "user_id", "user_id_source", "user_id_changed"};
    result ∈ {claimed, already, no_token, error}。
    """
    log = logger or LOGGER
    cfg = load_config() if cfg is None else cfg

    result: Dict[str, Any] = {
        "ok": False,
        "result": "error",
        "message": "",
        "points": 0,
        "day_no": 0,
        "streak": 0,
        "expire_at_ms": None,
        "token_exp": None,
        "token_renewed": False,
        # 本次实际使用的账号 ID / 它的来源(auto=自动识别, config=配置里的手填值)
        "user_id": None,
        "user_id_source": "none",
        "user_id_changed": False,
    }
    # 需要在最终 message 前面拼上去的说明(账号切换之类)
    notes: List[str] = []

    # 1) 取 token
    if token is None:
        try:
            token = load_token()
        except RuntimeError as exc:
            result["result"] = "no_token"
            result["message"] = str(exc)
            log.warning("签到跳过: %s", exc)
            return result
    else:
        token = str(token).strip()
        if not token:
            result["result"] = "no_token"
            result["message"] = "token 为空"
            return result

    own_session = False
    if session is None:
        session = requests.Session()
        session.trust_env = False
        own_session = True

    result["token_exp"] = token_exp(token)

    try:
        # 2) 续期(失败不中断,继续用原 token 试签到)
        renew = renew_token(token, cfg=cfg, session=session)
        if renew.get("ok") and renew.get("new_token"):
            token = renew["new_token"]
            result["token_renewed"] = True
            result["token_exp"] = token_exp(token)
            log.info("token 已续期,新 token 有效期约 40 天")
        else:
            log.info("token 续期未成功(%s),继续用原 token", renew.get("message") or "未知原因")

        # 3) 自动识别账号(user_id):问服务端这个 token 属于哪个账号
        #    优先用自动发现到的 realUserID,拿不到才回退配置里手填的值
        user_id, info = resolve_user_id(token, cfg=cfg, session=session)
        result["user_id"] = user_id
        result["user_id_source"] = info.get("user_id_source") or "none"

        # 识别到账号就写进状态文件: 仪表盘「服务状态 → 当前账号」显示的就是这串数字。
        # 以前只有 Web 层「保存 Token」那条路会写, 命令行触发 / 调度线程自动签到都不写,
        # 界面上的账号是空的或过期的, 用户没法确认现在到底是哪个账号在签。
        # 用 update_state 做字段级合并(锁内重新读盘再写), 不整份覆盖状态文件;
        # 写失败只记 warning, 不影响签到结果。
        if user_id and result["user_id_source"] == "auto":
            try:
                update_state(real_user_id=str(user_id))
            except Exception as exc:  # noqa: BLE001
                log.warning("写当前账号到状态文件失败: %s", exc)

        if not user_id:
            result["result"] = "error"
            result["message"] = "无法确定账号(user_id),请在「更新 Token」保存一次以自动识别"
            log.error(result["message"])
            return _apply_notes(result, notes)

        cfg_user_id = str(cfg.get("user_id") or "").strip()
        if result["user_id_source"] == "auto" and cfg_user_id != user_id:
            # 自动发现的账号和配置里配的不一致 -> 以自动发现的为准,并回写配置
            result["user_id_changed"] = True
            if cfg_user_id:
                notes.append("检测到账号切换,user_id 已自动更新")
            else:
                notes.append("已自动识别账号,user_id 已自动更新")
            try:
                new_cfg = dict(cfg)
                new_cfg["user_id"] = user_id
                save_config(new_cfg)
                log.info("user_id 已自动更新: %s -> %s", cfg_user_id or "(空)", user_id)
            except Exception as exc:  # noqa: BLE001
                LOGGER.warning("回写 user_id 到配置失败: %s", exc)

        # 4) 查签到面板
        status = fetch_signin_status(token, cfg=cfg, session=session, user_id=user_id)
        if not status.get("ok"):
            result["result"] = "error"
            result["message"] = status.get("message") or "查询签到状态失败"
            log.error("查询签到状态失败: %s", result["message"])
            return _apply_notes(result, notes)

        days = status.get("days") or []
        today = status.get("today")
        if not today:
            result["result"] = "error"
            result["message"] = "签到面板里没找到今天的记录"
            log.error(result["message"])
            return _apply_notes(result, notes)

        today_status = _int_or(today.get("status"), 0)
        result["day_no"] = _int_or(today.get("day_no"), 0)
        # 与 claim_points 同一口径: 面板格子优先, 算不出时退回服务端给的 day_no
        result["streak"] = _streak_value(days, result["day_no"])

        # 5) 今日可领就领取,否则按已领/未到处理
        if today_status == DAY_STATUS_CLAIMABLE:
            claim = claim_points(token, cfg=cfg, session=session, user_id=user_id)
            if not claim.get("ok"):
                result["result"] = "error"
                result["message"] = claim.get("message") or "领取积分失败"
                result["points"] = claim.get("points", 0)
                _merge_claim_counters(result, claim)
                result["expire_at_ms"] = claim.get("expire_at_ms")
                log.error("领取积分失败: %s", result["message"])
                return _apply_notes(result, notes)

            result["points"] = claim.get("points", 0)
            _merge_claim_counters(result, claim)
            result["expire_at_ms"] = claim.get("expire_at_ms")
            result["ok"] = True
            if claim.get("already"):
                result["result"] = "already"
            else:
                result["result"] = "claimed"
            result["message"] = claim.get("message") or ""
        elif today_status == DAY_STATUS_CLAIMED:
            result["ok"] = True
            result["result"] = "already"
            result["points"] = _int_or(today.get("points"), 0)
            result["message"] = "今天已经领过了"
        else:
            # 未到时间(1)或不符合条件(4):既没领到也不算已领,归为 error
            if today_status == DAY_STATUS_NOT_ARRIVED:
                result["message"] = "今天的签到还没到时间"
            else:
                result["message"] = "今天不符合签到条件"
            result["result"] = "error"
            log.warning(result["message"])

        # 6) 记状态(供 next_run_at 判断今天是否已签)
        if result["result"] in ("claimed", "already"):
            _record_signin_state(cfg, result)
        return _apply_notes(result, notes)
    finally:
        if own_session:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass


# ===================== 状态持久化 =====================

# 状态文件锁:signin 模块与 Web 层(keepalive-web.py)共用同一把锁。
# 之前 Web 层一把锁、signin 内部又是另一套「整份覆盖」写法, 两边同时写会互相丢字段;
# 统一到这一把锁后, 跨线程、跨模块的临界区才真正串行化。
# 注意:threading.Lock 不可重入, 持锁期间不要调用会再次加锁的函数
# (read_state / update_state 内部自己加锁, 别在持锁时调用它们)。
state_lock = threading.Lock()

# 字段级更新里的哨兵:表示"保留盘上现有值,本次不写这个字段"。
# 哨兵本体只有这一份定义, Web 层引用 signin._KEEP。
_KEEP = object()


def state_path() -> str:
    """签到状态文件路径(默认脚本同目录 .signin-state.json,可用环境变量覆盖)。"""
    return os.environ.get("MINIMAX_SIGNIN_STATE_FILE") or os.path.join(
        _script_dir(), ".signin-state.json"
    )


def load_state() -> dict:
    """读签到状态;读不到或损坏都返回空字典。

    底层原语(自己不加锁); 对外读请用 read_state()。
    """
    path = state_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        LOGGER.warning("签到状态读取失败(%s),按空状态处理: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def save_state(state: dict) -> None:
    """原子写签到状态(底层原语, 自己不加锁); 对外写请用 update_state()。"""
    payload = json.dumps(state or {}, ensure_ascii=False, indent=2) + "\n"
    _atomic_write(state_path(), payload, mode=0o600)


def read_state() -> dict:
    """在锁内读签到状态(避免读到写了一半的文件)。"""
    with state_lock:
        return load_state()


def update_state(*, remove: Iterable[str] = (), **fields) -> dict:
    """锁内做 读-改-写: 重新读盘上最新 state, 合并本次字段, 再整份写回。

    - fields 里值为哨兵 _KEEP 表示"保留盘上原值, 本次不写这个字段"
    - remove 里的 key 从盘上状态里删掉
    - 返回合并后的 state

    绝不用调用方手里的旧快照整份覆盖, 否则会把别的线程刚写的字段冲掉;
    写盘失败只记日志不抛(调用方都是"尽力而为"地记状态)。
    """
    with state_lock:
        state = load_state()
        for key, value in fields.items():
            if value is _KEEP:
                continue
            state[key] = value
        for key in (remove or ()):
            state.pop(key, None)
        try:
            save_state(state)
        except Exception as exc:  # noqa: BLE001
            LOGGER.warning("写状态文件失败: %s", exc)
        return state


def _record_signin_state(cfg: dict, result: dict) -> None:
    """把一次签到结果写进状态文件(失败不影响主流程)。"""
    try:
        now = _now_in_tz(cfg)
        # 走 update_state: 锁内重新读盘再合并, 不会把 Web 层刚写的字段冲掉
        update_state(
            last_signin_date=now.date().isoformat(),
            last_result=result.get("result"),
            last_points=result.get("points", 0),
            last_day_no=result.get("day_no", 0),
            last_streak=result.get("streak", 0),
            last_claim_at=now.isoformat(),
        )
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("写签到状态失败: %s", exc)


# ===================== 定时调度 =====================


def _window_bounds(cfg: dict, day: date) -> Tuple[datetime, datetime]:
    """起始日 day 对应的签到窗口 [start, end]。

    区间格式 "HH:MM";
    - end < start: 跨午夜(比如 23:00 -> 01:00), 结束时间算到第二天
    - end == start: 零长度区间 —— **不再**解释成 24 小时窗口。
      24 小时窗口会在午夜边界让"窗口起始日"翻转(候选顺序 day 在前),
      把刚摇好、刚过点的执行时刻当成过期目标丢掉, 结果整天没签到;
      所以这里记一条 warning 并退化成默认区间 00:30-02:00, 保证任何入口都不漏签。
    """
    cfg = cfg or {}
    tz = _tzinfo(cfg)
    start_h, start_m = _parse_hhmm(cfg.get("sign_window_start"), (0, 30))
    end_h, end_m = _parse_hhmm(cfg.get("sign_window_end"), (2, 0))

    if (start_h, start_m) == (end_h, end_m):
        key = (start_h, start_m)
        if key not in _ZERO_WINDOW_WARNED:
            _ZERO_WINDOW_WARNED.add(key)
            LOGGER.warning(
                "签到区间为零长度(开始和结束时间都是 %02d:%02d), 已退化为默认区间 %s-%s",
                start_h, start_m, DEFAULT_WINDOW_START, DEFAULT_WINDOW_END,
            )
        start_h, start_m = 0, 30
        end_h, end_m = 2, 0

    start_dt = datetime.combine(day, dt_time(start_h, start_m), tzinfo=tz)
    end_dt = datetime.combine(day, dt_time(end_h, end_m), tzinfo=tz)
    if end_dt <= start_dt:
        # 跨午夜:结束时间算到第二天
        end_dt = end_dt + timedelta(days=1)
    return start_dt, end_dt


def pick_daily_time(cfg: dict, today: Optional[Any] = None) -> datetime:
    """在签到窗口 [start, end] 内随机取一个时刻(以 today 为窗口起始日)。

    区间格式 "HH:MM";若 start > end(跨午夜),end 视为次日;
    start == end(零长度)时退化到默认区间 00:30-02:00, 不会退化成 24 小时窗口。
    返回带时区的 datetime。
    """
    cfg = cfg or {}
    day = _as_date(today) if today is not None else _now_in_tz(cfg).date()

    start_dt, end_dt = _window_bounds(cfg, day)
    span = int((end_dt - start_dt).total_seconds())
    offset = random.randint(0, span) if span > 0 else 0
    return start_dt + timedelta(seconds=offset)


def _normalize_now(cfg: dict, now: Optional[datetime] = None) -> datetime:
    """把传入的 now 归一到配置时区(naive 当成本地时间)。"""
    tz = _tzinfo(cfg)
    if now is None:
        return _now_in_tz(cfg)
    if now.tzinfo is None:
        return now.replace(tzinfo=tz)
    return now.astimezone(tz)


def _parse_target_at(state: Optional[dict]) -> Optional[datetime]:
    """从 state 里读出已摇好的执行时刻;读不出/坏掉返回 None。"""
    raw = (state or {}).get("target_at")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return None


def _window_start_date(cfg: dict, moment: datetime) -> Optional[date]:
    """返回 moment 落在哪个窗口里 -> 该窗口的起始日;不在任何窗口内返回 None。

    语义: 存在某个起始日 d, 使得 d_start <= moment <= d_end。
    跨午夜时一个窗口横跨两个自然日, 所以要同时看"今天"和"昨天"两个窗口。
    """
    cfg = cfg or {}
    tz = _tzinfo(cfg)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=tz)
    else:
        moment = moment.astimezone(tz)

    day = moment.date()
    for candidate in (day, day - timedelta(days=1)):
        start_dt, end_dt = _window_bounds(cfg, candidate)
        if start_dt <= moment <= end_dt:
            return candidate
    return None


def _current_window_start_date(cfg: dict, moment: datetime) -> date:
    """当前时刻所处的窗口起始日。

    - 落在今天的窗口里 -> 今天
    - 落在昨天那个窗口的后段里(跨午夜: 昨天 23:00 -> 今天 01:00) -> 昨天
    - 都不在 -> 今天(下一个窗口从今天的 start 开始)
    """
    cfg = cfg or {}
    tz = _tzinfo(cfg)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=tz)
    else:
        moment = moment.astimezone(tz)

    found = _window_start_date(cfg, moment)
    return found if found is not None else moment.date()


def _within_window(cfg: dict, target: datetime) -> bool:
    """判断某个时刻是否落在当前配置的签到区间内。

    区间格式 "HH:MM";start > end(跨午夜)时 end 视为次日,窗口是 [start, 次日 end];
    start == end(零长度)时按默认区间 00:30-02:00 处理, 不是 24 小时窗口。

    语义: 存在某个起始日 d, 使得 d_start <= target <= d_end。
    跨午夜时必须分别检查"今天"和"昨天"两个窗口, 否则窗口长度会算成 26 小时、恒真。
    """
    cfg = cfg or {}
    tz = _tzinfo(cfg)
    if target.tzinfo is None:
        target = target.replace(tzinfo=tz)
    else:
        target = target.astimezone(tz)

    day = target.date()
    for candidate in (day, day - timedelta(days=1)):
        start_dt, end_dt = _window_bounds(cfg, candidate)
        if start_dt <= target <= end_dt:
            return True
    return False


def _target_belongs_to(cfg: dict, state: dict, existing: datetime, wanted_date: date) -> bool:
    """已有的 target 是不是"目标窗口"那个已经摇好的时刻。

    正常口径: state["target_date"] 存的就是**窗口起始日**, 直接和 wanted_date 比。
    兼容老状态: 老版本把 target_date 记成"摇出来那个时刻的真实日期",
    跨午夜时会比窗口起始日晚一天; 这时改用时刻反查它所属窗口的起始日再比。
    """
    stored = str((state or {}).get("target_date") or "")
    if not stored:
        return False
    if stored == wanted_date.isoformat():
        return True
    if stored == existing.date().isoformat():
        owner = _window_start_date(cfg, existing)
        return owner is not None and owner == wanted_date
    return False


def daily_target(cfg: dict, state: dict, now: Optional[datetime] = None) -> Tuple[datetime, dict]:
    """返回 (执行时刻, 需要落盘的新 state)。

    窗口起始日模型:
    - 一个"窗口"是 [起始日 start, 结束时刻 end]; 跨午夜(start > end)时 end 落在次日,
      一个窗口横跨两个自然日, "窗口起始日"和"当前自然日"不是一回事
    - 窗口起始日(window_start_date): 给定 now, now 落在今天这个窗口里就是今天,
      落在昨天那个窗口的后段里就是昨天, 都不在就是今天(下一个窗口从今天 start 开始)
    - 目标窗口(wanted_date): 今天已签到 -> 明天那个窗口; 否则 -> 当前所在的窗口
    - 复用: state["target_date"](窗口起始日) == wanted_date 且 target_at 仍落在
      当前配置区间内 -> 直接复用, 不重摇
    - state["target_date"] 存的是**窗口起始日**(不是摇出来那个时刻的真实日期)
    - 不修改传入的 state(返回新 dict); 本函数自身不落盘 ——
      目标时刻由调用方负责写进状态文件的 target_date / target_at
    """
    cfg = cfg or {}
    state = state if isinstance(state, dict) else {}
    tz = _tzinfo(cfg)
    current = _normalize_now(cfg, now)
    today = current.date()

    signed_today = state.get("last_signin_date") == today.isoformat()
    # 目标窗口的起始日: 今天已签 -> 明天那个窗口; 否则 -> 当前所在的窗口
    wanted_date = (
        today + timedelta(days=1) if signed_today else _current_window_start_date(cfg, current)
    )

    # 1) 复用:state 里已有可用的 target(属于目标窗口, 且仍落在当前配置区间内)
    existing = _parse_target_at(state)
    if existing is not None:
        if existing.tzinfo is None:
            existing = existing.replace(tzinfo=tz)
        else:
            existing = existing.astimezone(tz)
        if _target_belongs_to(cfg, state, existing, wanted_date) and _within_window(cfg, existing):
            new_state = dict(state)
            new_state["target_date"] = wanted_date.isoformat()
            new_state["target_at"] = existing.isoformat()
            return existing, new_state

    # 2) 重摇一个(摇在目标窗口里)
    target = pick_daily_time(cfg, today=wanted_date)
    new_state = dict(state)
    # target_date 记的是**窗口起始日**(跨午夜时摇出来的时刻可能落在次日)
    new_state["target_date"] = wanted_date.isoformat()
    new_state["target_at"] = target.isoformat()
    return target, new_state


def next_run_at(cfg: dict, state: dict, now: Optional[datetime] = None) -> datetime:
    """算下一次签到的执行时刻。

    规则:
        - 状态里记录了今天已签到 -> 返回明天那个窗口内的随机时刻
        - 今天还没签、且窗口内的随机时刻已过 -> 返回 now(立即补签)
        - 其余 -> 返回窗口内的随机时刻

    跨午夜区间时"窗口"横跨两个自然日, 窗口起始日由 daily_target 判定;
    每天的随机时刻只摇一次, 摇中后写进 state["target_date"] / state["target_at"],
    同一天内不再变(用户改了签到区间会自动重摇)。
    为兼容现有调用方, 本函数会**就地更新传入的 state dict**(写入 target_date / target_at),
    但本函数自身不落盘 —— 目标时刻由调用方负责写进状态文件的 target_date / target_at
    (Web 层走 _persist_target_state,只写这两个字段)。
    """
    cfg = cfg or {}
    if not isinstance(state, dict):
        state = {}
    current = _normalize_now(cfg, now)

    target, new_state = daily_target(cfg, state, now=current)
    # 就地把摇中的时刻写回传入的 state(落盘由调用方负责)
    state["target_date"] = new_state.get("target_date")
    state["target_at"] = new_state.get("target_at")

    today = current.date()
    signed_today = state.get("last_signin_date") == today.isoformat()
    if not signed_today and current >= target:
        # 今天窗口内的时刻已过,还没签 -> 立刻补签
        return current
    return target


# ===================== CLI 入口 =====================


def main() -> int:
    """命令行跑一次签到(仅供本地调试,Web 层请直接调 run_checkin)。"""
    log = setup_logging()
    log.info("=" * 50)
    log.info("MiniMax 每日签到")

    try:
        result = run_checkin(logger=log)
    except Exception as exc:  # noqa: BLE001
        log.error("签到流程异常: %s", exc)
        return 1

    log.info("结果: %s", json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
