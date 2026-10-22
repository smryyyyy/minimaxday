<h1 align="center">MiniMax 每日自动签到</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Flask-3.x-000000?style=flat-square&logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Memory-<100MB-brightgreen?style=flat-square" alt="Memory">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License">
</p>

<p align="center">
  每天自动在 MiniMax 领取签到积分 · 单进程 Web 仪表盘一键管理。
</p>

---

## 目录

- [功能特点](#功能特点)
- [快速开始](#快速开始)
  - [前置条件](#前置条件)
  - [四步跑起来](#四步跑起来)
- [签到原理](#签到原理)
  - [四个端点](#四个端点)
  - [签名公式](#签名公式)
  - [响应字段枚举](#响应字段枚举)
- [架构](#架构)
  - [单进程（默认且唯一推荐）](#单进程默认且唯一推荐)
  - [状态机](#状态机)
- [部署方式](#部署方式)
  - [方式一：宝塔 Python 项目管理器（推荐国内服务器）](#方式一宝塔-python-项目管理器推荐国内服务器)
  - [方式二：systemd（Linux 通用）](#方式二systemdlinux-通用)
  - [方式三：手动 nohup](#方式三手动-nohup)
- [配置说明](#配置说明)
  - [config.json](#configjson)
  - [签到时间区间](#签到时间区间)
  - [路径约定](#路径约定)
  - [Token 获取](#token-获取)
  - [Web 端口与启动参数](#web-端口与启动参数)
- [换账号](#换账号)
- [安全](#安全)
  - [默认是「公网可访问 + 明文 HTTP」](#默认是公网可访问--明文-http)
  - [nginx 反代 HTTPS 的最小配置](#nginx-反代-https-的最小配置)
  - [已经做了的安全处理](#已经做了的安全处理)
  - [还要自己做的](#还要自己做的)
- [常见问题](#常见问题)
  - [401 Unauthorized](#401-unauthorized)
  - [「登陆失败，请稍后再试」——这是 Token 失效，不是让你等](#登陆失败请稍后再试这是-token-失效不是让你等)
  - [400 invalid signature](#400-invalid-signature)
  - [400「请求异常，请检查请求参数」](#400请求异常请检查请求参数)
  - [续期成功但签到 401](#续期成功但签到-401)
  - [Token 过期了怎么办](#token-过期了怎么办)
  - [一直显示「今天可领取」但不自动签](#一直显示今天可领取但不自动签)
  - [「未到执行时间」和「今天可领取」有什么区别](#未到执行时间和今天可领取有什么区别)
  - [自动重试会不会把接口打爆](#自动重试会不会把接口打爆)
  - [签到接口通了但 0 积分](#签到接口通了但-0-积分)
- [项目结构](#项目结构)
- [技术栈](#技术栈)
- [许可证](#许可证)

---

## 功能特点

- **单进程架构**：Web + 签到调度在同一个 Python 进程，调度跑在后台线程，通过 `threading.Event` 控制启停。线程本身**没有独立 watchdog**——线程真死了只能靠守护进程把整个进程重启（宝塔 / systemd 都配了 `Restart`）
- **JWT 鉴权**：直接用 MiniMax 接口的 JWT 鉴权机制（`token` 头 / query），免抓 Cookie
- **保存即校验（先校验、后落盘）**：Web 改完 Token → 先发 1 个只读请求校验「这个 cookie 还能不能用」→ 通过了才写入 `token.txt` 并顺带自动识别账号（校验失败不覆盖原文件，**不消耗签到机会**），5 秒后仪表盘自动显示新结果；完整流程见[换账号](#换账号)
- **换账号只换 Token**：账号 ID（`user_id`）自动识别，换账号不用改任何配置文件
- **随机执行时刻**：在设定的时间区间内随机挑一个时刻执行，避免固定时间被服务端识别成机器人
- **Web 仪表盘 · 状态如实显示**：密码登录，看状态 / 手动签到 / 改 Token / 开关自动签到 / 看实时日志，5 秒自动刷新；状态直接读线程标志位 + 状态文件，不会「显示运行但实际死了」（状态文件是磁盘快照，异常断电时可能滞后一次）
- **Token 自愈**：Token 快过期时自动调用续期接口换新 JWT，有效期重置为「当前时间 + 40 天」；细节见[Token 过期了怎么办](#token-过期了怎么办)
- **失败退避**：签到没成功（失败 / 没 Token）后 10 分钟内不自动重试，避免每 30 秒打一次接口；退避期内手动点「立即签到」随时能试，详见[自动重试会不会把接口打爆](#自动重试会不会把接口打爆)
- **登录限流**：同一 IP 连续输错密码 5 次锁 10 分钟，防止被暴力破解
- **极低资源 · 零手动配置**：内存 < 100MB，CPU 几乎为 0，2 核 4G 服务器随便跑；除 Token 外无需手动配置，首次启动自动建文件、生成密码（打到 stderr）、随机端口可选，账号信息（`user_id`）在粘 Token 时自动识别

## 快速开始

### 前置条件

- Python 3.9+
- 2 个依赖：`requests` / `flask`（`werkzeug` 是 flask 的传递依赖）

### 四步跑起来

```bash
# 1. 装依赖
pip3 install -r requirements.txt

# 2. 复制配置模板（账号信息不用手填，粘 Token 时自动识别）
#    user_id 自动获取；uuid / device_id 服务端不校验，留着只为指纹稳定 → 详见「配置说明」
cp config.json.example config.json
chmod 600 config.json

# 3. 抓 Token（Mac Chrome）：打开 https://agent.minimax.cn → F12 → Network
#    → 任意带 ?token= 的请求，复制 Query String 里 token 参数的值（整段 JWT）

# 4. 启动（脚本所在目录就是数据目录，不用 sudo）
python3 keepalive-web.py
# 首次启动会打印初始密码到 stderr（形如 "初始密码: s-0BmGBUHy_qog"），浏览器打开 http://localhost:35235 用它登录 → 「更新 Token」粘 JWT → 保存
```

> [!TIP]
> 想要换端口：`python3 keepalive-web.py --port 12345`
> 想要预设密码：`python3 keepalive-web.py --password "your-password"`

登录后建议顺手核对三样东西：

1. 「每日签到」卡片里状态点变绿 → 说明 Token 有效、签到成功
2. 「未来 7 天」面板出现小方块 → 说明签到状态接口通了
3. 「服务状态」卡片里的「当前账号」是一串数字（realUserID）→ 说明账号已被自动识别；这串数字应该和你要用的账号对得上

## 签到原理

### 四个端点

| 端点 | 方法 | body | token 放哪 | 用途 |
|---|---|---|---|---|
| `/minimax-cloud/api/v1/signin/status` | GET | 空串 | query 或 header 均可 | 查签到状态（7 天面板、今天能不能领） |
| `/minimax-cloud/api/v1/signin/claim` | POST | **字面量 `{}`** | query 或 header 均可 | 领取积分 |
| `/v1/api/user/renewal` | POST | **空串**（不是 `{}`） | **必须放 HTTP 头 `token:`** | 续期 JWT，有效期重置为「当前时间 + 40 天」 |
| `/v1/api/user/info` | GET | 空串 | query 或 header 均可 | **只读**：按 token 反查账号 `realUserID`（自动识别用） |

> [!WARNING]
> body 差一点就对不上：`claim` 要 `{}`，`renewal` 要空串。写成 `{}` / 空串互串，服务端会报签名错误（见[常见问题](#常见问题)）。另外 `user_id` 只有 `status` / `claim` 会校验（**必须和 token 是同一个账号**，填错一律 401）；`renewal` / `user/info` 不校验它。

### 签名公式

每个请求带两个头：

```text
x-timestamp: <秒级 unix 时间戳>
x-signature: md5(f"{ts}I*7Cf%WZ#S&%1RlZJ&C2{body}")
```

其中 `{body}` 是**实际发出去的请求体原文**：

- `status`：body 为空 → `md5(f"{ts}I*7Cf%WZ#S&%1RlZJ&C2")`
- `claim`：body 为 `{}` → `md5(f"{ts}I*7Cf%WZ#S&%1RlZJ&C2{{}}")`
- `renewal`：body 为空 → `md5(f"{ts}I*7Cf%WZ#S&%1RlZJ&C2")`

`yy` 头不用做。

> [!NOTE]
> 签名细节、请求头拼装、响应解析全部封装在 `signin.py` 里，本项目不重复实现，直接调用即可。

### 响应字段枚举

**`base_resp.status_code`**

| 值 | 含义 |
|---|---|
| `0` | 成功 |
| 非 0 | 失败，具体含义看 `base_resp.status_msg` |

**`days[].status`（7 天面板的每一天）**

面板恒为 `[今天 … 今天+6]` 共 7 格，不存在历史格。

| 值 | 含义 | 面板显示 |
|---|---|---|
| `1` | 未到（还没开始签） | 灰块 |
| `2` | 可领取 | 描边蓝块 |
| `3` | 已领取 | 实心绿块 |
| `4` | 不符合条件 | 灰块 |

**`claim_result`（领取结果）**

| 值 | 含义 |
|---|---|
| `1` | 本次领取成功 |
| `2` | 今日已领过（**也算成功**，不是错误） |

**`scene`（签到场景标识）**

服务端下发的活动场景编号，取值 `0` ~ `4`。不同数值对应服务端配置的不同签到活动 / 积分规则；客户端不参与判断，原样透传即可。

**`today`（今天这一天的汇总）**

| 字段 | 含义 |
|---|---|
| `day_no` | 服务端签到面板里的第几天 |
| `points` | 今天的基础积分（常见 400 / 1000） |
| `bonus_points` | 额外奖励积分 |
| `status` | 同 `days[].status` |
| `is_today` | 是否是今天 |

> [!NOTE]
> `day_no` 是服务端自己的计数，不是本地算的连签天数。

**`streak`（连续签到天数）**

面板上显示的连签天数不是本地数出来的，而是按服务端的 `day_no` 推出来的：

```text
streak = day_no - (今天这一格还没领 ? 1 : 0)
```

- **今天还没领**（`status = 2` 可领取）：`today.day_no` 里仍然**含今天**这一天，所以要减 1 —— `day_no = 3` 时连签天数是 **2**
- **今天已经领过**（`status = 3`）：今天这格计入连签，不减 —— `day_no = 3` 时连签天数是 **3**
- 连签天数不会小于 0；`day_no` 缺失或面板为空时按 0 算

## 架构

### 单进程（默认且唯一推荐）

```text
┌────────────────────────────────────────┐
│  python3 keepalive-web.py              │
│  ┌──────────────────────────────────┐  │
│  │  Flask Web  (主线程)             │  │
│  │  - 登录 / 状态 / 手动签到 / 日志  │  │
│  │  - 改 Token → 只读校验+识别账号  │  │
│  └──────────────────────────────────┘  │
│  ┌──────────────────────────────────┐  │
│  │  签到调度  (后台线程)            │  │
│  │  - 每 30 秒醒一次                │  │
│  │  - 到点调 signin.run_checkin()   │  │
│  │  - Event 控制启停(0 内存开销)    │  │
│  │  - 实时读 token.txt / 状态文件   │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
        ↓                       ↓
   浏览器 :35235            MiniMax API
```

**核心交互**：

- 调度线程每 30 秒醒一次，调 `signin.next_run_at(cfg, state, now)` 算出下次执行时刻
- 到点且 `auto_signin` 开启 → 调 `signin.run_checkin()` → 结果写进状态文件
- **进程启动时**：如果按规则今天该签还没签 → **立即补签**，不等 30 秒轮询
- 用户点「立即签到」→ 走同一个 `signin.run_checkin()`，同步更新状态文件
- 用户改 Token → **先校验可用性**（1 个只读请求，不签到；校验失败则原 `token.txt` 原样不动、不覆盖）→ 通过才写文件 + 账号自动识别，状态 / 日志 5 秒内可见；完整流程见[换账号](#换账号)

### 状态机

`signin.run_checkin()` 的 `result` 字段直接决定 UI 状态：

| 返回 | 含义 | UI 显示 |
|---|---|---|
| `claimed` | 领取成功 | 🟢 绿点 + 「今日已签到（第 N 天）」 |
| `already` | 今日已领过 | 🟢 绿点 + 「今日已签到（第 N 天）」 |
| `no_token` | Token 文件不存在或为空 | 🟡 黄点 + 引导填 Token |
| `error` | 签名错 / 401 / 网络异常 | 🔴 红点 + 错误原因 |

> [!NOTE]
> 红点**只显示当天产生的失败**；昨天的失败跨天后自动归为「未到执行时间」。

## 部署方式

### 方式一：宝塔 Python 项目管理器（推荐国内服务器）

> [!NOTE]
> 单进程架构：Web 启动时自动拉起签到调度线程，**1 个项目搞定所有事**，不用写重启脚本，也不用计划任务。

#### 文件部署

把 `signin.py` / `keepalive-web.py` / `requirements.txt` 三个文件放到服务器任意目录。下面用 `<项目路径>` 占位符（宝塔添加项目时让你填什么就是什么，常见 `/www/wwwroot/minimaxday/`，也可以放 `/opt/`、`/home/`、挂载盘等）：

```bash
# 本机
scp signin.py keepalive-web.py requirements.txt config.json.example root@<服务器IP>:<项目路径>/
```

> [!NOTE]
> `config.json` 也一起传（里面是 host / 签到区间，账号 `user_id` 粘一次 Token 就自动写入），或者部署完在 Web 界面里改。传模板 `config.json.example` 也行，服务器上 `cp config.json.example config.json` 即可，`user_id` / `uuid` / `device_id` 留空不影响运行。

> [!WARNING]
> `config.json` 含账号标识，已经写进 `.gitignore`，**不要提交进仓库**（仓库里只留 `config.json.example` 模板）。

#### 宝塔添加项目

宝塔面板 → **Python 项目** → **添加项目**：

| 字段 | 填什么 |
|---|---|
| 名称 | `minimaxday` |
| 路径 | `<项目路径>`（你刚 scp 上去的那个目录） |
| Python 版本 | 系统默认（3.9+） |
| 框架 | **其他** |
| 启动方式 | **python** |
| 启动文件 | `keepalive-web.py` |
| **启动参数** | `--host 0.0.0.0 --port 35235` |
| 端口 | `35235` |
| 是否守护进程 | 启用 |
| 自动启动 | 启用 |
| 启动用户 | 看你服务器习惯（root/www 都行） |

下一步 → **模块** → **从 requirements.txt 安装** → 选 `<项目路径>/requirements.txt` → 安装。

提交。宝塔会建 venv → 装依赖 → 启动 → 自动守护（Web 进程死了 1 分钟内拉起，调度线程随之重新跑；重启时会自动判断今天要不要补签）。

#### 获取初始密码

首次启动后：

- 宝塔 → Python 项目 → 找到 `minimaxday` → **日志** → 找 `初始密码: xxxx`
- 浏览器打开 `http://<服务器IP>:35235` → 输密码登录
- 登录后第一件事：去「更新 Token」填 JWT

> [!WARNING]
> 如果从公网访问不了，先去腾讯云控制台 → 安全组 → 放行 TCP:35235（宝塔防火墙只是其中一层）。

### 方式二：systemd（Linux 通用）

```ini
# /etc/systemd/system/minimaxday.service
[Unit]
Description=MiniMax Signin Web
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 <项目路径>/keepalive-web.py --host 0.0.0.0 --port 35235
Restart=always
RestartSec=10
User=root
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=<项目路径>

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now minimaxday
systemctl status minimaxday
```

### 方式三：手动 nohup

```bash
# 启动（只跑 web，签到调度是 web 进程内的线程）
nohup python3 keepalive-web.py --host 0.0.0.0 --port 35235 > /tmp/minimaxday.log 2>&1 &

# 停止
pkill -TERM -f keepalive-web.py

# 看日志（默认在脚本同目录的 signin.log）
tail -f <项目路径>/signin.log
```

## 配置说明

### config.json

所有可调项都在 `config.json`（推荐直接改这个文件，或在 Web 界面的「每日签到」卡片里改区间和开关）。

**首次部署先复制模板**：

```bash
cp config.json.example config.json
# 不用填任何账号标识：粘一次 Token，user_id 会自动识别并写回这个文件
chmod 600 config.json
```

仓库里只提供 `config.json.example` 模板；真正的 `config.json` 已被 `.gitignore` 忽略（含账号标识，别提交）。

| 字段 | 含义 | 默认 / 备注 |
|---|---|---|
| `host` | 接口域名 | `agent.minimax.cn`（国内站） |
| `uuid` | 设备 UUID | 设备指纹，服务端不校验 |
| `device_id` | 设备 ID | 设备指纹，服务端不校验 |
| `user_id` | 账号 realUserID | 自动获取，一般不用手填 |
| `sign_window_start` | 签到区间开始 | `HH:MM`，默认 `00:30` |
| `sign_window_end` | 签到区间结束 | `HH:MM`，默认 `02:00` |
| `auto_signin` | 是否自动签到 | `true` / `false`，Web 界面上的「自动签到」开关就是它 |
| `timezone` | 时区 | `Asia/Shanghai` |

> [!NOTE]
> `host` 的国际站域名是 `agent.minimaxi.com`；`uuid` / `device_id` 留着只是为了指纹稳定，留空即可；`user_id` 自动获取，一般不用手填（见下方说明）。`timezone` 决定「今天」的判断、「下次执行时间」和 Token 过期时间的显示，服务器不在 +08:00 也不会偏。

> [!IMPORTANT]
> `user_id` 现在自动获取，不用手填。在 Web 界面「更新 Token」里粘一次 Token，服务端会用 `GET /v1/api/user/info` 查出这个 Token 属于哪个账号，把返回的 `realUserID` 自动写回 `config.json` 的 `user_id`；之后每次签到也会先自动核对一次，**换账号只换 Token，配置不用动**。仪表盘「服务状态 → 当前账号」显示的就是这串数字，可以拿它确认现在是哪个账号在签到。

> [!WARNING]
> `user_id` 必须是 realUserID，不能是昵称 / displayName，也不是 JWT 里的 `user.id`。实测这两者是两套不同的编号（JWT 里的 `user.id` 填进去一样 401）。现在不会再让你手填，但如果你手动改过这个字段，请改成 `user/info` 返回的 `realUserID`。`uuid` / `device_id` 实测**服务端完全不校验**，填随机值也能签到，留着只是为了指纹稳定。

### 签到时间区间

不是「每 5 分钟打一次」，而是**每天在区间内随机挑一个时刻**执行一次：

- `sign_window_start` / `sign_window_end` 决定区间（`HH:MM`）
- 每天在这个区间里随机取一个时刻作为执行时间
- 固定时间签到容易被识别成自动化，随机时刻更稳
- 区间可以跨天（比如 `23:30` → `00:30`）
- Web 界面「每日签到」卡片里可以直接改，不用重启

> [!WARNING]
> **区间必须是非零长度**：开始和结束时间不能是同一个值。`00:00` → `00:00`（或 `23:00` → `23:00`）这种零长度区间会被 Web 界面**直接拒收**，提示「签到区间不能是零长度:开始和结束时间相同,请改成不同的时间」。原因是零长度窗口在午夜边界上会让「窗口起始日」翻转，把刚摇好、刚过点的执行时刻当成过期目标丢掉，结果整整一天没签到。真要跨午夜，请写成 `23:00` → `01:00` 这种形式（**结束时间小于开始时间**才算跨午夜）。万一绕过 Web 界面手改了 `config.json` 写成了零长度，程序也会记一条 warning 日志并自动退回到默认区间 `00:30` → `02:00`，不会漏签。

### 路径约定

所有数据文件默认在**脚本同目录**（`os.path.dirname(os.path.abspath(__file__))`），可用环境变量覆盖：

| 文件 | 默认位置 | 环境变量覆盖 | 权限 |
|---|---|---|---|
| `signin.py` | 脚本目录 | — | 755 |
| `keepalive-web.py` | 脚本目录 | — | 755 |
| `requirements.txt` | 脚本目录 | — | 644 |
| `config.json` | 脚本目录 | `MINIMAX_CONFIG_FILE` | **600** |
| `config.json.example` | 脚本目录 | — | 644（模板，可以进仓库） |
| `token.txt` | 脚本目录 | `MINIMAX_TOKEN_FILE` | **600** |
| `.web-pass` | 脚本目录 | `MINIMAX_PASS_FILE` | 600 |
| `.web-secret` | 脚本目录 | `MINIMAX_SECRET_FILE` | 600 |
| `.signin-state.json` | 脚本目录 | `MINIMAX_SIGNIN_STATE_FILE` | 600 |
| `signin.log` | 脚本目录 | `MINIMAX_LOG_FILE` | 644 |

> [!NOTE]
> 不再写 `/var/log/`：避免权限问题；服务器上用 `MINIMAX_LOG_FILE` 指向 `/var/log/...` 即可。

### Token 获取

1. Mac Chrome 打开 <https://agent.minimax.cn>，正常登录
2. F12 打开 DevTools → 切到 **Network** 标签
3. F5 刷新页面
4. 列表里找任意 `agent.minimax.cn` 的请求 → 点击
5. 右侧 Headers 面板 → 找 **Request URL**（含 query string）
6. 复制 `?token=eyJ...` 里 `token=` 后面的整段值
7. 粘贴到 Web 仪表盘「更新 Token」保存即可（**不要**直接编辑 `token.txt`；保存时 Web 会自动识别账号并写回 `config.json`）

或者在 Web 仪表盘「更新 Token」卡片标题旁的 `?` 悬停看 5 步教程。

### Web 端口与启动参数

```bash
# 默认 0.0.0.0:35235（公网可访问，需密码保护）
python3 keepalive-web.py

# 自定义端口
python3 keepalive-web.py --port 12345

# 仅本机访问（SSH 隧道场景）
python3 keepalive-web.py --host 127.0.0.1

# 自定义初始密码（首次启动用，之后会被 .web-pass 覆盖）
python3 keepalive-web.py --password "your-password"

# 强制重置密码
python3 keepalive-web.py --reset-password

# 走 nginx HTTPS 时打开 secure cookie（等价环境变量 MINIMAX_SECURE_COOKIE=1）
python3 keepalive-web.py --secure-cookie
```

> [!NOTE]
> 登录失败限流参数（都是环境变量，进程内生效，重启即失效）：`MINIMAX_LOGIN_MAX_FAILS`（默认 5 次）、`MINIMAX_LOGIN_LOCK_MINUTES`（默认 10 分钟）。

## 换账号

**换账号只需换一个 Token，配置文件一个字都不用改。**

操作步骤：

1. 用新账号登录 <https://agent.minimax.cn>，按[获取 Token](#token-获取)的方法抓到新 Token
2. Web 界面「更新 Token」卡片里粘上新 Token → 点「保存 Token」
3. 保存时**先**只发 **1 个只读请求** `GET /v1/api/user/info`，纯粹回答「这个 cookie 还能不能用」（此刻还没落盘）
  - 成功 → 提示「Token 可用 · 账号 realUserID 已同步(XXXX)」，Token 写入 `token.txt`，新账号的 `realUserID` 已自动写进 `config.json`
  - 失败 → 提示「Token 无效,未保存(原 Token 文件未改动): <服务端原因>」（校验请求本身出错时提示「Token 校验未通过,未保存(原 Token 文件未改动): <原因>」），**不会**覆盖原来的 `token.txt`、**不会**触发任何签到请求，也不会消耗签到机会
4. 仪表盘「服务状态 → 当前账号」会显示新账号的 realUserID，确认一下是不是你要的那个账号
5. 想立刻签一次 → 点「立即签到」（这才是真正跑签到流程的动作）

之后每天的自动签到流程里，程序每轮都会先按当前 Token 自动核对一次账号；发现 Token 换了账号会自动改用新账号的 `user_id`，并把变化记进日志（`检测到账号切换,user_id 已自动更新`）。

> [!IMPORTANT]
> 「保存 Token」和「立即签到」是**两件事**：
> 保存 Token = 只校验可用性（1 个只读请求，不签到；**先校验、通过后才写 `token.txt`**，校验失败不覆盖原文件）；
> 立即签到 = 完整签到流程（续期 → 自动识别账号 → 查状态 → 领积分）。

## 安全

### 默认是「公网可访问 + 明文 HTTP」

服务默认监听 `0.0.0.0:35235`，也就是**所有网卡都能连**，而协议是明文 HTTP：

- 管理密码是明文过网的（请求体里就是密码本身）
- session cookie 也是明文过网的
- 任何中间人（同一个 WiFi、机房邻居、云厂商的流量镜像）都能看到并重放

所以：**这个服务默认不适合直接暴露在公网上**。有三条路可选，从推荐到最省事：

| 方案 | 做法 | 适合 |
|---|---|---|
| 反代 HTTPS（推荐） | nginx / Caddy 监听 443 → 反代到 `127.0.0.1:35235`，同时用 `--secure-cookie` | 长期公网部署 |
| 只监听本机 | `--host 127.0.0.1`，外部用 SSH 隧道访问 | 个人用、图省事 |
| 直连公网（不推荐） | 什么都不改 | 内网 / 自家设备，且有强密码 |

### nginx 反代 HTTPS 的最小配置

```nginx
server {
    listen 443 ssl;
    server_name minimaxday.example.com;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:35235;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

同时把后端改成只听本机，并打开 secure cookie：

```bash
python3 keepalive-web.py --host 127.0.0.1 --port 35235 --secure-cookie
```

`--secure-cookie` 让浏览器只在 HTTPS 下发送 session cookie（等价环境变量 `MINIMAX_SECURE_COOKIE=1`）。**默认是关的**——因为默认部署是 HTTP 直连，贸然打开会导致 HTTP 访问时登录状态根本存不住。

### 已经做了的安全处理

- **登录限流**：同一 IP 连续输错密码 5 次 → 锁 10 分钟，锁定期内给明确提示；登录成功计数清零。进程内实现，重启即失效（可接受）
- **session cookie**：`HttpOnly`（JS 读不到）+ `SameSite=Lax`（浏览器默认挡住跨站 POST）
- **敏感文件权限**：`token.txt` / `.web-pass` / `.web-secret` / `.signin-state.json` / `config.json` 一律 600；已存在的文件每次启动也会被纠正回 600
- **不泄漏凭证**：`/api/status` 只下发前端真正用到的配置字段，不下发 `uuid` / `device_id` / `user_id`；仪表盘上的「当前账号」只显示账号编号 realUserID（不是 JWT、不含密钥），它来自状态文件缓存，查看时不会发任何网络请求
- **账号配置不进仓库**：`config.json` 已写进 `.gitignore`，仓库里只留 `config.json.example` 模板

### 还要自己做的

- **用强密码**：首次启动自动生成的是随机密码，但你在 Web 界面里改的时候别改成 `123456`
- **别把 35235 端口在安全组里对 0.0.0.0 放行**，除非你确实要走直连公网这条路
- **登录限流是按 IP 记的**：走 nginx 反代时所有请求都算 `127.0.0.1`，所以限流是全局的（对你这种单人部署没影响，但也意味着一个 IP 的暴力破解会把你一起锁 10 分钟）

---

## 常见问题

### 401 Unauthorized

Token 被服务端拒绝。逐条排查：

1. **JWT 本身过期**：看 Web 仪表盘「Token 过期」时间，JWT 的 `exp` 通常是签发后 30 天左右
2. **Token 被服务端作废**：改了密码 / 退出登录 / 主动踢下线都会让旧 JWT 立刻失效，哪怕 `exp` 还没到
3. **Token 抄错了**：必须是完整的 `eyJ...` 三段，中间不能有换行 / 空格。Web 界面保存时会 `.strip()`，但中间断行照样错
4. **换了账号**：Token 跟账号绑定，串号必然 401（`user_id` 现在会自动跟着 Token 识别，一般不用手改）

处理：重新抓一次 Token，在「更新 Token」里粘贴保存 —— 保存时会自动识别账号并写回 `config.json`。

### 「登陆失败，请稍后再试」——这是 Token 失效，不是让你等

**实测坑**：服务端把 **token 无效**也报成

```json
{"statusInfo":{"code":1000021,"message":"登陆失败，请稍后再试"}}
```

文案极具误导性：**「请稍后再试」是骗你的**。它不代表服务端临时抽风、等几分钟就能好；它实际含义是「你手上这个 Token 已经作废了」。

看到这条 = **Token 已失效**，正确处理是：

1. 去浏览器重新登录 `agent.minimax.cn`
2. F12 → Network → 重新抓一次 `?token=` 的 JWT
3. 粘到 Web 界面「更新 Token」里保存（保存时先校验可用性，不消耗签到机会，详见[换账号](#换账号)）

> [!IMPORTANT]
> 反过来说：仪表盘出现红点「签到失败」时，先看失败原因里有没有这句话——有就是 Token 的事，重试多少次都没用；没有才考虑网络或服务端抖动。注意仪表盘只会把**今天**的失败标成红点，昨天的失败跨天后会自动回到「未到执行时间」。

### 400 invalid signature

签名算错了。要点：

1. **`x-timestamp` 必须是秒级**，不是毫秒级。传了毫秒，服务端会当成未来时间戳，签名对不上
2. **`{body}` 必须是实际发出去的原文**，一个字都不能差：
  - `claim` → 字面量 `{}`
  - `status` / `renewal` → 空串
3. **服务器时间不准**：签名基于本机时间戳，机器时间偏了超过服务端容忍窗口就会一直 invalid signature。用 `date` 校一下服务器时间（NTP 同步）
4. **`renewal` 的 token 必须放 HTTP 头 `token:`**，放 query 无效（但签名本身是对的，所以这个错法不报 invalid signature，而是报 401）

### 400「请求异常，请检查请求参数」

**这条错误信息极具误导性，实际绝大多数情况是 `renewal` 的签名错了**，不是参数写错。

原因：`renewal` 的 body 必须是**空串**，很多人是照抄 `claim` 的写法发成了 `{}`：

```text
renewal 错误:  body = "{}"   → 签名算的是 md5(f"{ts}...{{}}")，服务端按空串算 → 对不上
renewal 正确:  body = ""      → 签名算的是 md5(f"{ts}...")
```

另外两个常见诱因：

- `user_id` 不是 realUserID（纯数字）→ 服务端解析不出用户 → 报「请求参数」异常（现在这个值是自动识别的，一般不会手填错）
- `device_id` 不是纯数字

排查顺序：先确认 `renewal` 的 body 是不是空串，再确认 `user_id` 是不是数字。

### 续期成功但签到 401

几乎都是同一个原因：**Token 和 `config.json` 里的 `user_id` 不是同一个账号**。

`renewal`（续期）端点只验 Token 本身，**不校验 `user_id`**；而 `status` / `claim`（签到）端点**必须**校验 `user_id`，而且它必须和 Token 属于同一个账号 —— 填错或留空一律 401。所以就会出现「续期成功、签到 401」这种看起来自相矛盾的现象。

典型触发场景：浏览器 cookie 里的 `_token` 是另一个账号的，但 `config.json` 里的 `user_id` 还是老账号的。

**现在会自动处理**：每次签到前，程序都先调 `GET /v1/api/user/info` 查当前 Token 属于哪个账号，用返回的 `realUserID` 覆盖掉配置里的旧值（不一致时日志里会出现 `检测到账号切换,user_id 已自动更新`）。

如果仍然出现 401，请在 Web 界面「更新 Token」里**重新保存一次 Token** —— 保存时会重新识别账号并写回 `config.json`。

### Token 过期了怎么办

有两层自愈：

1. **自动续期**：签到流程里发现 Token 快过期 / 已过期，会先调 `POST /v1/api/user/renewal` 换一个新的 JWT（有效期重置为「当前时间 + 40 天」），写回 `token.txt`，然后用新 Token 继续签到。整个过程你无感，仪表盘上会看到「Token 过期」时间被刷新
2. **手动补签**：如果续期也失败（服务端不再给续期），就在 Web 界面「立即签到」点一下看看具体报错；确认是 401 就重新抓 Token 粘贴保存

### 一直显示「今天可领取」但不自动签

- `auto_signin` 被关了 → Web 界面「自动签到」开关
- Token 是空的或读不到 → 看「更新 Token」卡片
- 进程根本没在跑 → 看「服务状态」里的调度线程状态和日志文件 `signin.log`
- 上一次签到失败后还在 10 分钟退避里 → 等退避结束，或直接手动点「立即签到」

### 「未到执行时间」和「今天可领取」有什么区别

- **未到执行时间**（橙色点）：还没到今天摇中的那个时刻，或者服务端明确说「今天的签到还没到时间」。这时候点「立即签到」大概率会失败
- **今天可领取**（黄色点）：已经到点了、今天还没领，可以点「立即签到」

昨天 / 上次留下的失败**不会**一直挂成红点——只有当天产生的失败才显示「签到失败」。

### 自动重试会不会把接口打爆

不会。自动调度每 30 秒醒一次，但**上次签到没成功（失败 / 没 Token / 其他非成功结果）后有 10 分钟退避**：这 10 分钟内不自动重试（手动点「立即签到」不受退避限制，随时能试）。

原因：服务端会把「今天还没到签到时间」也归成失败，如果不退避，调度线程会每 30 秒打一次接口；退避期内日志只记一条提示，不会刷屏。

> [!IMPORTANT]
> **只有真正签到成功（claimed / already）才会解除退避**。Token 没配好（`no_token`）同样进退避——不会每 30 秒去空打一次接口。

### 签到接口通了但 0 积分

`user_id` 和 Token 不是同一个账号（现在会自动纠正，见[续期成功但签到 401](#续期成功但签到-401)），或者该账号本来就不在签到活动名单里（`days[].status == 4` 表示不符合条件）。

## 项目结构

```text
.
├── signin.py                 # 签到核心（签名 / 四个端点 / 续期 / 账号自动识别 / 状态文件 / 调度时间计算）
├── keepalive-web.py          # Flask Web + 调度线程（单进程入口）
├── requirements.txt          # 依赖列表
├── .gitignore                # 忽略凭据 / 账号配置 / 日志等
├── config.json.example       # 配置模板（复制成 config.json；账号信息粘 Token 自动写入）
├── config.json               # 你的配置（host / uuid / device_id / user_id / 签到区间 / 开关）· 已在 .gitignore 里
├── token.txt                 # 首次启动自动创建（空文件），Web 界面填
├── .web-pass                 # 首次启动自动生成（密码哈希）
├── .web-secret               # 首次启动自动生成（Flask session 密钥）
├── .signin-state.json        # 签到状态（今天是否已签 / 积分 / 第几天）
├── signin.log                # 运行日志
├── LICENSE                   # MIT 许可证全文
└── README.md                 # 本文档
```

> [!NOTE]
> 部署到服务器后，**所有数据文件都在启动目录里**，删了项目目录就连带清理干净。`config.json` / `token.txt` / `.web-pass` / `.web-secret` / `.signin-state.json` 都已在 `.gitignore` 里，`git add .` 不会把它们带进仓库。

## 技术栈

| 组件 | 用途 |
|---|---|
| Python 3.9+ | 主语言 |
| requests | HTTP 调用（带连接复用 + 代理穿透） |
| Flask 3.x | Web 界面 |
| werkzeug | 密码哈希 + Session |
| threading | 后台调度线程 + `Event` 控制启停 |
| hashlib / md5 | 请求签名 |
| logging | 日志（文件 + stdout） |

接口端点、方法、body、token 位置与签名公式统一见[签到原理](#签到原理)，此处不重复列出；鉴权方式为 JWT（`token` 头或 query），不依赖 Cookie。

## 许可证

MIT License

Copyright (c) 2026 smryyyyy

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
