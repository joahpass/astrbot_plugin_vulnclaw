# Security Policy

仅对拥有或取得明确书面授权的系统使用本插件。禁止将其用于公网随机目标、第三方
服务、云 metadata、宿主机管理面或任何超出任务 scope 的资源。

发现插件存在 scope 绕过、签名绕过、容器逃逸、敏感信息泄露或任意命令执行问题时，
请停止使用受影响版本并通过 GitHub 私密漏洞报告提交。报告中不要包含真实凭据或
未脱敏的客户数据。

Supervisor 端口应只监听受信网络。Docker socket 仅挂载到 Supervisor，绝不能挂载
到任务 Worker。

