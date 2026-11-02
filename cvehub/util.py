"""低層共用小工具（sync、host_import 都用；不 import 其他 cvehub 模組，避免循環 import）"""
import datetime
import re


def norm_release(r):
    """24.04、"Ubuntu 22.04.5 LTS" → 版本號"""
    m = re.search(r"(\d+\.\d+)", str(r or ""))
    return m.group(1) if m else ""


def parse_time(s):
    """ISO 8601 → 本地時間（naive）；格式不對回傳 None"""
    try:
        t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return t.astimezone().replace(tzinfo=None) if t.tzinfo else t
    except ValueError:
        return None
