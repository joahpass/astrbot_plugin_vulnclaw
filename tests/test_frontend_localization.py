from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_chinese_ui_localization_is_enabled() -> None:
    main = (ROOT / "frontend" / "src" / "main.tsx").read_text(encoding="utf-8")
    localization = (
        ROOT / "frontend" / "src" / "localization" / "zhCN.ts"
    ).read_text(encoding="utf-8")
    assert "enableChineseUi();" in main
    for text in (
        "新建扫描",
        "漏洞发现",
        "安全边界",
        "任务控制台",
        "生成报告",
        "目标或文件名",
        "验证命令，例如 id",
    ):
        assert text in localization
