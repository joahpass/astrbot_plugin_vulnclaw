# AstrBot VulnClaw

[GitHub 仓库](https://github.com/joahpass/astrbot_plugin_vulnclaw)

面向 AstrBot 4.9.2+ 的授权漏洞测试任务插件。QQ 负责创建计划、审批、查看进度和
报告；AstrBot 当前会话模型负责推理；固定 Docker Worker 负责执行受控工具。

本项目仅适用于你拥有或已取得明确授权的目标。

## 功能

- `/vuln` QQ 命令和中文 LLM tools
- 一次性审批口令与管理员直接授权
- 全局单任务队列、取消、超时和重启恢复
- SQLite 任务与发现记录、哈希链 JSONL 审计
- 固定目标、IP、端口、路径和有效期的任务 scope
- DNS、HTTP 重定向和工具调用前重复校验
- HMAC、时间戳、nonce 和任务 ID 防重放协议
- 非 root、只读、无特权的临时 Docker Worker
- 固定工具白名单及 `DOCKER-USER` 出口限制
- 内置 VulnClaw 0.2.9 Skills、报告和状态模块

## 安全边界

- QQ 用户不能提交 shell、原始 Docker 参数或任意 Python。
- 只有 Supervisor 可以访问 Docker socket。
- Worker 只能访问审批时固定的目标 IP 和端口。
- loopback、链路本地、云 metadata、Docker 网关和常见管理端口默认拒绝。
- `run`、`exploit`、`persistent`、`post-exploitation` 默认关闭。
- Supervisor API 默认只监听 `127.0.0.1:8765`。

## 安装

Linux 主机需要 Docker 和 Docker Compose。生成至少 32 字节随机密钥：

```bash
openssl rand -hex 32
```

在项目根目录创建 `.env`：

```dotenv
VULNCLAW_WORKER_SECRET=replace-with-random-secret
```

构建并启动 Supervisor：

```bash
docker compose build
docker compose up -d vulnclaw-supervisor
curl http://127.0.0.1:8765/health
```

把 `astrbot_plugin_vulnclaw/` 放到 AstrBot 的 `data/plugins/`，在 WebUI 配置：

- `worker_url`: `http://127.0.0.1:8765`
- `worker_secret`: 与 `.env` 完全一致
- `enable_high_risk_modes`: 首次部署保持关闭

不要将 Supervisor 的 8765 端口暴露到公网。

## QQ 命令

```text
/vuln plan <mode> <target> [ports] [paths] [authorization]
/vuln approve <task_id> <code>
/vuln status [task_id]
/vuln queue
/vuln cancel <task_id>
/vuln scope show <task_id>
/vuln logs [task_id]
/vuln findings <task_id>
/vuln report <task_id>
/vuln doctor
/vuln worker status
```

默认模式：`recon`、`scan`、`report`。

高风险模式：`run`、`exploit`、`persistent`、`post-exploitation`。

## 演示案例

下面的 `vuln-lab.example` 是文档保留示例。运行前必须替换为你自己的授权靶场
域名或 IP，并填写实际开放端口和路径。

### 案例 1：检查部署状态

QQ 输入：

```text
/vuln doctor
```

预期看到：

```text
VulnClaw 插件诊断：
- 数据库：正常
- Worker 配置：已配置
- 高风险模式：关闭
- Supervisor：正常 docker=29.x vulnclaw=0.2.9
```

### 案例 2：低风险侦察并人工审批

创建计划：

```text
/vuln plan recon https://vuln-lab.example 443 / 已取得靶场所有者授权
```

机器人返回任务 ID 和六位一次性口令，例如：

```text
任务计划已创建：vuln-a1b2c3d4e5f6
审批口令：482913
```

管理员批准：

```text
/vuln approve vuln-a1b2c3d4e5f6 482913
```

查看最终固定边界：

```text
/vuln scope show vuln-a1b2c3d4e5f6
```

### 案例 3：扫描指定 Web 路径

只授权 443 端口以及 `/app`、`/api` 两个路径：

```text
/vuln plan scan https://vuln-lab.example 443 /app,/api 已取得本次测试授权
```

批准后查看进度：

```text
/vuln status vuln-a1b2c3d4e5f6
/vuln logs vuln-a1b2c3d4e5f6
```

任务结束后：

```text
/vuln findings vuln-a1b2c3d4e5f6
/vuln report vuln-a1b2c3d4e5f6
```

### 案例 4：管理员自然语言授权启动

管理员可以对机器人说：

```text
对 https://vuln-lab.example 做 scan，端口 443，路径 /app。
我已获得目标所有者授权，授权并启动。
```

模型会调用 `vulnclaw_authorize_and_start` 创建并入队。非管理员发送相同内容只能
生成计划，不能启动任务。

### 案例 5：取消任务

```text
/vuln queue
/vuln cancel vuln-a1b2c3d4e5f6
```

运行中的 Worker 会被销毁，相应出口规则会清理。

### 案例 6：安全拒绝

以下目标应直接拒绝，不会进入队列：

```text
/vuln plan scan http://127.0.0.1 8080 / 已授权
/vuln plan scan http://169.254.169.254 80 / 已授权
/vuln plan scan http://172.17.0.1 80 / 已授权
```

原因分别是 loopback、云 metadata 和常见 Docker 网关。

## 验证

```bash
python -m compileall astrbot_plugin_vulnclaw supervisor worker tests
python -m pytest
docker compose config
docker compose build
docker compose up -d vulnclaw-supervisor
```

## 上游

内置源码固定为 VulnClaw 0.2.9。来源、校验值和升级流程见
[`astrbot_plugin_vulnclaw/vendor/UPSTREAM.md`](astrbot_plugin_vulnclaw/vendor/UPSTREAM.md)。
