"""跨程序鎖：同時只允許一個同步／匯入（網頁排程、手動按鈕、指令列共用）"""
import contextlib
import fcntl
import os

from .config import Config


class Busy(Exception):
    pass


@contextlib.contextmanager
def job_lock(blocking=False):
    path = os.path.join(os.path.dirname(Config.DB_PATH) or ".", ".cvehub-job.lock")
    f = open(path, "a")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
    except BlockingIOError:
        f.close()
        raise Busy("另一個同步／匯入正在執行")
    try:
        yield
    finally:
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()
