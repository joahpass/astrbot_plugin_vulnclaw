# AstrBot VulnClaw

[GitHub 仓库](https://github.com/joahpass/astrbot_plugin_vulnclaw)

`astrbot_plugin_vulnclaw` 是面向 AstrBot 4.9.2+ 的授权漏洞测试任务插件。QQ
负责计划、审批、进度和报告；AstrBot 当前会话模型负责推理；固定 Docker Worker
负责执行受控工具。

本项目只适用于你拥有或取得明确授权的目标。

## 安全边界

- QQ 用户不能提交 shell、Docker 参数或任意 Python。
- Supervisor 是唯一能访问 Docker socket 的组件。
- 每个任务使用临时非 root、只读、无特权容器。
- Worker 出口仅允许审批时固定的 IP 和端口，以及必要 DNS。
- DNS、HTTP 重定向和每次工具调用都会重新检查 scope。
- loopback、链路本地、云 metadata 和常见 Docker 网关永久拒绝。
- `run`、`exploit`、`persistent`、`post-exploitation` 默认关闭。
- HMAC 请求带时间戳、nonce 和任务 ID，拒绝重放与跨任务调用。

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

Supervisor 使用 host 网络和 `NET_ADMIN` 管理 `DOCKER-USER` 出口规则。它不接受
原始 Docker 参数或宿主机命令。不要将 8765 端口暴露到公网。

## QQ 命令

```text
/vuln plan scan https://example.test 443 / 授权测试本系统
/vuln approve vuln-xxxxxxxxxxxx 123456
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

管理员自然语言中明确提供目标、模式并包含“授权并启动”时，LLM tool 可以直接
创建和批准任务。其他自然语言请求只能生成计划。

## 模式

- 默认：`recon`、`scan`、`report`
- 高风险：`run`、`exploit`、`persistent`、`post-exploitation`

模型不能把低风险任务升级为高风险模式。数字化 scope 在任务创建后固定。

## 验证

```bash
python -m compileall astrbot_plugin_vulnclaw supervisor worker tests
python -m pytest
docker compose config
docker compose build
docker compose up -d vulnclaw-supervisor
```

Windows 开发机没有 Docker 时只能完成 Python 与静态配置测试；容器和 iptables
隔离必须在 Linux Docker 主机验证。

## 上游

内置源码固定为 VulnClaw 0.2.9。来源、校验值和升级流程见
[`astrbot_plugin_vulnclaw/vendor/UPSTREAM.md`](astrbot_plugin_vulnclaw/vendor/UPSTREAM.md)。
