# VulnClaw 授权漏洞测试插件

该目录是 AstrBot 可直接加载的插件。完整源码和部署文件：

https://github.com/joahpass/astrbot_plugin_vulnclaw

仅允许测试自有或明确授权的目标。

## 快速检查

```text
/vuln doctor
/vuln worker status
```

正常部署应显示 Worker 已配置、Supervisor 正常、Docker 可用、VulnClaw 版本为
`0.2.9`。

## 基础流程

把示例域名替换为自己的授权靶场：

```text
/vuln plan recon https://vuln-lab.example 443 / 已取得靶场所有者授权
/vuln approve vuln-xxxxxxxxxxxx 123456
/vuln status vuln-xxxxxxxxxxxx
/vuln scope show vuln-xxxxxxxxxxxx
/vuln findings vuln-xxxxxxxxxxxx
/vuln report vuln-xxxxxxxxxxxx
```

扫描指定路径：

```text
/vuln plan scan https://vuln-lab.example 443 /app,/api 已取得本次测试授权
```

取消任务：

```text
/vuln queue
/vuln cancel vuln-xxxxxxxxxxxx
```

## 管理员自然语言演示

```text
对 https://vuln-lab.example 做 scan，端口 443，路径 /app。
我已获得目标所有者授权，授权并启动。
```

只有管理员且明确包含“授权并启动”时才能直接入队。其他用户只能生成待审批计划。

## 安全拒绝演示

以下目标应被拒绝：

```text
/vuln plan scan http://127.0.0.1 8080 / 已授权
/vuln plan scan http://169.254.169.254 80 / 已授权
/vuln plan scan http://172.17.0.1 80 / 已授权
```

高风险模式默认关闭。插件不向 QQ 或模型暴露 shell、Docker socket、原始 Docker
参数或任意 Python。
