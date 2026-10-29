"""kernel 套件名稱的共用判斷（匯入、報表、受影響主機都用這裡，規則只有一份）"""


def is_kernel(src):
    """linux（GA）與 linux-hwe-*"""
    return src == "linux" or src.startswith("linux-hwe-")


def kernel_variant(src):
    """linux 與 linux-hwe-* 以外的 kernel source（雲端、OEM、lowlatency…）；linux-firmware 不是 kernel"""
    return src.startswith("linux-") and not src.startswith("linux-hwe-") and src != "linux-firmware"
