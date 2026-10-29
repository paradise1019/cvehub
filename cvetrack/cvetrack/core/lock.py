"""跨程序鎖：同時只允許一個同步／匯入（排程、指令列共用）"""
import contextlib
import fcntl
import os
import time

from ..conf import conf


class Busy(Exception):
    pass


def _lock_path():
    return conf.path(".cvetrack-job.lock")


@contextlib.contextmanager
def job_lock(blocking=False):
    os.makedirs(conf.DATA_DIR, exist_ok=True)
    f = open(_lock_path(), "a")
    try:
        if blocking:
            fcntl.flock(f, fcntl.LOCK_EX)
        else:
            # 網頁的 is_busy() 會短暫拿共享鎖：稍等再試，不要因為剛好有人開網頁就略過這次排程
            for i in range(10):
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if i == 9:
                        raise Busy("另一個同步／匯入正在執行")
                    time.sleep(0.2)
    except Busy:
        f.close()
        raise
    try:
        yield
    finally:
        fcntl.flock(f, fcntl.LOCK_UN)
        f.close()


def is_busy():
    """有沒有同步／匯入在跑：試著拿「共享鎖」（拿得到＝沒有人拿著獨佔鎖），馬上放掉。讀不到鎖檔就當成沒有"""
    try:
        f = open(_lock_path(), "r")
    except OSError:
        return False
    try:
        fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(f, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        f.close()
