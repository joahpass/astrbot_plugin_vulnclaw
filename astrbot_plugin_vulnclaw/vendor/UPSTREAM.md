# Vendored VulnClaw

- Project: [Unclecheng-li/VulnClaw](https://github.com/Unclecheng-li/VulnClaw)
- Fixed version: `0.2.9`
- Source artifact: PyPI sdist `vulnclaw-0.2.9.tar.gz`
- SHA-256: `105d24bb88479a9f90b8c0ec09a9339688e62c6b25fefa0897aca89ee11a420a`
- License: MIT, preserved as `LICENSE.vulnclaw`

The vendored directory contains the upstream Python package. The AstrBot plugin does
not invoke upstream unrestricted command runners directly. Its Worker adapter exposes
only fixed tools and applies task scope, resource, network, and timeout controls.

To check for a later release without automatically replacing this copy:

```bash
python scripts/check_vulnclaw_update.py
```

Review upstream changes and licenses before updating. Never install from the moving
`main` branch during deployment.

