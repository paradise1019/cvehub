"""放檔目錄：DATA_DIR/inbox 放 osv-all*.tar.xz 或 vex-all*.tar.xz；匯入成功後移到 DATA_DIR/archive"""
import datetime
import glob
import logging
import os
import shutil

from ..conf import conf
from ..models import OsvImport, VexImport
from . import osv, vex

log = logging.getLogger(__name__)


def dirs():
    inbox, archive = conf.path("inbox"), conf.path("archive")
    os.makedirs(inbox, exist_ok=True)
    os.makedirs(archive, exist_ok=True)
    return inbox, archive


def kind_of(name):
    n = os.path.basename(name).lower()
    return "vex" if "vex" in n else "osv"


def archive_file(path):
    _, archive = dirs()
    name = os.path.basename(path).split("-", 2)[-1] if os.path.dirname(path) == conf.path("processing") else os.path.basename(path)
    if not (len(name) > 9 and name[:8].isdigit() and name[8] == "-"):     # 已有日期前綴就不再加
        name = "%s-%s" % (datetime.date.today().strftime("%Y%m%d"), name)
    shutil.move(path, os.path.join(archive, name))
    keep = {}
    for f in sorted(glob.glob(os.path.join(archive, "*.tar.xz")), key=os.path.getmtime):
        keep.setdefault(kind_of(f), []).append(f)
    for files in keep.values():
        for old in files[:-conf.KEEP_FILES] if conf.KEEP_FILES > 0 else []:
            os.remove(old)


def check():
    """匯入放檔目錄裡沒匯入過的檔案（依修改時間，OSV 先於 VEX）。回傳匯入的種類集合，例如 {"osv"}"""
    inbox, _ = dirs()
    files = sorted(glob.glob(os.path.join(inbox, "*.tar.xz")), key=lambda f: (kind_of(f) != "osv", os.path.getmtime(f)))
    done = set()
    work = conf.path("processing")
    os.makedirs(work, exist_ok=True)
    # 之前中斷留在 processing/ 的檔案先處理
    files = sorted(glob.glob(os.path.join(work, "*.tar.xz")), key=os.path.getmtime) + files
    for n, f in enumerate(files):
        k = kind_of(f)
        if os.path.dirname(f) != work:
            # 先移出放檔目錄再算 sha256、匯入：匯入途中有人上傳／複製同名檔案，不會被當成已處理而搬走
            dest = os.path.join(work, "%s-%d-%s" % (datetime.datetime.now().strftime("%H%M%S"), n, os.path.basename(f)))
            os.replace(f, dest)
            f = dest
        name = os.path.basename(f).split("-", 2)[-1]       # 去掉 processing 用的前綴
        model, mod = (OsvImport, osv) if k == "osv" else (VexImport, vex)
        if not model.objects.filter(sha256=osv.sha256(f), status="ok").exists():
            try:
                mod.import_file(f, filename=name)
            except Exception:
                # 壞檔移到 failed/，不然每次排程都會重試；舊資料不受影響，原因記在匯入紀錄
                failed = conf.path("failed")
                os.makedirs(failed, exist_ok=True)
                shutil.move(f, os.path.join(failed, name))
                log.error("%s 匯入失敗，已移到 %s", name, failed)
                continue
            done.add(k)
        else:
            log.info("%s 已匯入過，直接移到保存目錄", os.path.basename(f))
        archive_file(f)
    return done
