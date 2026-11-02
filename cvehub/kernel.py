"""kernel 套件名稱的共用判斷（匯入、報表、受影響主機都用這裡，規則只有一份）"""
import re

KERNEL_ABI = re.compile(r"^linux-(?:hwe-[0-9.]+-)?(?:image|image-unsigned|modules|modules-extra|headers|tools|cloud-tools|buildinfo)"
                        r"-(\d+\.\d+\.\d+)-(\d+)(?:-[a-z0-9-]+)?$")
SIG_VERSION = re.compile(r"(\d+\.\d+\.\d+-\d+\.\d+(?:~[0-9.]+)?)")


def infer_running(krel, version, pk):
    """執行中 kernel：krel＝uname -r、version＝/proc/version_signature（或其中的版本）、pk＝已安裝套件 {名稱: 版本}
    只有其中一項時從已安裝套件補另一項。回傳 (kernel_release, kernel_version)，補不齊的是空字串／None
    （Landscape＋kernel API 與主機清單匯入共用，兩種來源的判斷一致）"""
    m = SIG_VERSION.search(version or "")
    kver = m.group(1) if m else None
    if kver and not krel:   # 只有版本：從已安裝套件找出對應的 kernel 名稱（linux-image-unsigned-* 要去掉 unsigned-）
        names = [n for n, v in pk.items() if n.startswith("linux-image-") and v == kver and KERNEL_ABI.match(n)]
        if names:
            best = min(names, key=lambda n: n.startswith("linux-image-unsigned-"))     # 優先用一般的 linux-image-*
            krel = re.sub(r"^linux-image-(?:unsigned-)?", "", best)
        else:
            krel = ""
    if not kver and krel:   # 只有 uname -r：從已安裝套件查版本
        kver = pk.get("linux-image-" + krel) or pk.get("linux-image-unsigned-" + krel)
    return krel, kver


def is_kernel(src):
    """linux（GA）與 linux-hwe-*"""
    return src == "linux" or src.startswith("linux-hwe-")


def kernel_variant(src):
    """linux 與 linux-hwe-* 以外的 kernel source（雲端、OEM、lowlatency…）；linux-firmware 不是 kernel"""
    return src.startswith("linux-") and not src.startswith("linux-hwe-") and src != "linux-firmware"
