from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_private_runtime_files_are_ignored() -> None:
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".env", "*.db", "*.jsonl", "data/"):
        assert pattern in ignored


def test_no_known_private_server_data_or_hardcoded_secret() -> None:
    excluded = {
        ROOT / "tests" / "test_publish_hygiene.py",
        ROOT / "README.md",
        ROOT / "scripts" / "install.sh",
    }
    suspicious = ("222.186.50.126", "/root/AstrBot", "VULNCLAW_WORKER_SECRET=")
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path in excluded or ".git" in path.parts:
            continue
        if path.suffix.lower() not in {
            ".py",
            ".md",
            ".yaml",
            ".yml",
            ".json",
            ".toml",
            ".txt",
            ".sh",
        }:
            continue
        text = path.read_bytes().decode("utf-8", errors="ignore")
        for marker in suspicious:
            if marker in text:
                findings.append(f"{path.relative_to(ROOT)}: {marker}")
    assert findings == []
