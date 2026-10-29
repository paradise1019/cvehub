"""cvetrack 資料模型

公告資料（Vuln／Affected／BinMap／UsnFix／VexStatus）每一列都帶匯入編號 imp：
新的一份 OSV／VEX 先分批寫入（每批一個短交易，不會長時間鎖住和原專案共用的 SQLite），
寫完只改 active 旗標就換成新資料，舊資料再分批刪掉。兩份資料同時存在的這段時間用來算 OSV 差異。
"""
from django.db import models


class Access(models.Model):
    """只用來定義權限（沒有資料表）"""

    class Meta:
        managed = False
        default_permissions = ()
        permissions = [
            ("view_cvetrack", "cvetrack：查看"),
            ("operate_cvetrack", "cvetrack：補單號、開變更單、例外"),
            ("admin_cvetrack", "cvetrack：匯入、同步、設定"),
        ]


# ---------------------------------------------------------------- 公告資料

class OsvImport(models.Model):
    STATUS = [("loading", "匯入中"), ("ok", "成功"), ("failed", "失敗")]
    filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64, db_index=True)
    file_mtime = models.DateTimeField(null=True)
    imported_at = models.DateTimeField()
    releases = models.CharField(max_length=200)
    cve_count = models.IntegerField(null=True)
    affected_count = models.IntegerField(null=True)
    release_counts = models.JSONField(null=True)
    change_counts = models.JSONField(null=True)       # 與前一份的差異統計 {kind: 筆數}
    prev = models.ForeignKey("self", null=True, on_delete=models.SET_NULL, related_name="+")
    status = models.CharField(max_length=10, choices=STATUS)
    message = models.TextField(blank=True)
    active = models.BooleanField(default=False)
    purged = models.BooleanField(default=False)      # 公告資料列已刪除（只留紀錄與差異）

    class Meta:
        ordering = ["-id"]


class Vuln(models.Model):
    imp = models.IntegerField()
    cve = models.CharField(max_length=40)
    priority = models.CharField(max_length=20, blank=True)
    cvss = models.CharField(max_length=200, blank=True)
    published = models.CharField(max_length=40, blank=True)
    details = models.TextField(blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["imp", "cve"], name="cvetrack_vuln_imp_cve")]


class Affected(models.Model):
    imp = models.IntegerField()
    ecosystem = models.CharField(max_length=40)
    source = models.CharField(max_length=200)
    cve = models.CharField(max_length=40)
    fixed = models.CharField(max_length=200, null=True)
    introduced = models.CharField(max_length=200, null=True)
    binaries = models.TextField(null=True)          # JSON：{binary: fixed_version}（只存跟 source 修正版本不同的）

    class Meta:
        indexes = [models.Index(fields=["imp", "ecosystem", "source", "cve"], name="cvetrack_aff_src"),
                   models.Index(fields=["imp", "cve"], name="cvetrack_aff_cve")]


class BinMap(models.Model):
    imp = models.IntegerField()
    ecosystem = models.CharField(max_length=40)
    binary = models.CharField(max_length=200)
    source = models.CharField(max_length=200)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["imp", "ecosystem", "binary"], name="cvetrack_binmap_key")]


class UsnFix(models.Model):
    """每個 CVE × 套件庫 × source 第一次被修正的 USN（輸出報表「截至期末」判斷修正日期）"""
    imp = models.IntegerField()
    cve = models.CharField(max_length=40)
    ecosystem = models.CharField(max_length=40)
    source = models.CharField(max_length=200)
    fixed = models.CharField(max_length=200, null=True)
    usn = models.CharField(max_length=40)
    published = models.CharField(max_length=10, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["imp", "cve", "ecosystem", "source"], name="cvetrack_usnfix_key")]


class AdvisoryChange(models.Model):
    """這份 OSV 與前一份的差異（CVE × 套件庫 × source）"""
    KINDS = [("added", "新增"), ("removed", "移除（撤回）"), ("fix_added", "新增修正"), ("fix_removed", "修正被取消"),
             ("fixed_changed", "修正版本變更"), ("introduced_changed", "受影響範圍變更"), ("priority_changed", "等級變更")]
    imp = models.ForeignKey(OsvImport, on_delete=models.CASCADE, related_name="changes")
    ecosystem = models.CharField(max_length=40, blank=True)     # priority_changed 為空白
    source = models.CharField(max_length=200, blank=True)
    cve = models.CharField(max_length=40)
    kind = models.CharField(max_length=20, choices=KINDS)
    old_value = models.CharField(max_length=200, null=True)
    new_value = models.CharField(max_length=200, null=True)

    class Meta:
        indexes = [models.Index(fields=["imp", "ecosystem", "source", "cve"], name="cvetrack_advchg_key"),
                   models.Index(fields=["cve"], name="cvetrack_advchg_cve")]


class VexImport(models.Model):
    filename = models.CharField(max_length=255)
    sha256 = models.CharField(max_length=64, db_index=True)
    file_mtime = models.DateTimeField(null=True)
    imported_at = models.DateTimeField()
    releases = models.CharField(max_length=200)
    cve_count = models.IntegerField(null=True)
    row_count = models.IntegerField(null=True)
    release_counts = models.JSONField(null=True)
    unknown_count = models.IntegerField(null=True)
    status = models.CharField(max_length=10, choices=OsvImport.STATUS)
    message = models.TextField(blank=True)
    active = models.BooleanField(default=False)
    purged = models.BooleanField(default=False)

    class Meta:
        ordering = ["-id"]


class VexStatus(models.Model):
    imp = models.IntegerField()
    cve = models.CharField(max_length=40)
    release = models.CharField(max_length=10)
    source = models.CharField(max_length=200)
    base_status = models.CharField(max_length=30, null=True)
    pro_status = models.CharField(max_length=30, null=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["imp", "cve", "release", "source"], name="cvetrack_vex_key")]
        indexes = [models.Index(fields=["imp", "release", "source"], name="cvetrack_vex_rel_src")]


# ---------------------------------------------------------------- 主機與 Run

class Run(models.Model):
    TRIGGERS = [("osv", "匯入 OSV"), ("vex", "匯入 VEX"), ("schedule", "排程"), ("manual", "手動")]
    STATUS = [("running", "執行中"), ("ok", "成功"), ("failed", "失敗")]
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True)
    trigger = models.CharField(max_length=10, choices=TRIGGERS)
    status = models.CharField(max_length=10, choices=STATUS)
    baseline = models.BooleanField(default=False)    # 第一個成功的 Run：事件記成「初始」
    osv_import = models.ForeignKey(OsvImport, null=True, on_delete=models.SET_NULL, related_name="+")
    vex_import = models.ForeignKey(VexImport, null=True, on_delete=models.SET_NULL, related_name="+")
    prev_osv_import = models.ForeignKey(OsvImport, null=True, on_delete=models.SET_NULL, related_name="+")
    hosts = models.IntegerField(null=True)
    open_findings = models.IntegerField(null=True)
    counts = models.JSONField(null=True)             # {kind: n, "cause:<cause>": n}
    message = models.TextField(blank=True)

    class Meta:
        ordering = ["-id"]


class Host(models.Model):
    KERNEL_STATUS = [("ok", "正常"), ("stale", "資料過舊"), ("missing", "查無資料"), ("error", "查詢失敗"), ("disabled", "未設定")]
    landscape_id = models.IntegerField(unique=True)
    hostname = models.CharField(max_length=255)
    ip = models.CharField(max_length=64, blank=True)
    title = models.CharField(max_length=255, blank=True)
    release = models.CharField(max_length=10, blank=True)
    pro_attached = models.BooleanField(null=True)
    package_count = models.IntegerField(default=0)
    last_seen = models.DateTimeField(null=True)
    kernel_release = models.CharField(max_length=100, null=True)
    kernel_version = models.CharField(max_length=100, null=True)
    kernel_collected_at = models.CharField(max_length=40, null=True)
    kernel_status = models.CharField(max_length=10, choices=KERNEL_STATUS, default="disabled")
    active = models.BooleanField(default=True)
    first_run = models.ForeignKey(Run, null=True, on_delete=models.SET_NULL, related_name="+")
    fresh_run = models.ForeignKey(Run, null=True, on_delete=models.SET_NULL, related_name="+")    # 最近一次新出現或停用後回來
    evaluated_run = models.ForeignKey(Run, null=True, on_delete=models.SET_NULL, related_name="+")  # 最近一次比對完（事件已寫入）
    retired_run = models.ForeignKey(Run, null=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["hostname"]

    def __str__(self):
        return self.hostname


class HostPackage(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="packages")
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=200)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["host", "name"], name="cvetrack_hostpkg_key")]


class PackageChange(models.Model):
    """這次 Run 主機有變的套件（只記差異）；name 為 running-kernel 時記的是執行中的 kernel"""
    KINDS = [("package", "套件"), ("running-kernel", "執行中 kernel")]
    run = models.ForeignKey(Run, on_delete=models.CASCADE, related_name="package_changes")
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="package_changes")
    kind = models.CharField(max_length=20, choices=KINDS, default="package")
    name = models.CharField(max_length=200)
    old_version = models.CharField(max_length=200, null=True)   # None＝新裝
    new_version = models.CharField(max_length=200, null=True)   # None＝移除

    class Meta:
        indexes = [models.Index(fields=["run", "host"], name="cvetrack_pkgchg_run_host"),
                   models.Index(fields=["host", "name"], name="cvetrack_pkgchg_host_name")]


# ---------------------------------------------------------------- 比對結果與事件

class Finding(models.Model):
    """目前狀態：主機 × CVE × 套件 × 位置；resolved_at 有值＝已解決"""
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="findings")
    cve = models.CharField(max_length=40)
    package = models.CharField(max_length=200)
    location = models.CharField(max_length=20)       # installed | running-kernel
    source = models.CharField(max_length=200, blank=True)
    installed = models.CharField(max_length=200, blank=True)
    running = models.CharField(max_length=200, blank=True)
    fixed = models.CharField(max_length=200, blank=True)
    status = models.CharField(max_length=20)         # fix-available | fix-in-pro | no-fix
    repo = models.CharField(max_length=20, blank=True)
    action = models.CharField(max_length=20, blank=True)   # upgrade | reboot | upgrade+reboot
    priority = models.CharField(max_length=20, blank=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    first_run = models.ForeignKey(Run, null=True, on_delete=models.SET_NULL, related_name="+")
    resolved_at = models.DateTimeField(null=True)
    resolved_run = models.ForeignKey(Run, null=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        constraints = [models.UniqueConstraint(fields=["host", "cve", "package", "location"], name="cvetrack_finding_key")]
        indexes = [models.Index(fields=["resolved_at", "host"], name="cvetrack_finding_open"),
                   models.Index(fields=["cve"], name="cvetrack_finding_cve")]


class ChangeTicket(models.Model):
    number = models.CharField("單號", max_length=100, unique=True)
    title = models.CharField("標題", max_length=200, blank=True)
    description = models.TextField("說明", blank=True)
    planned_start = models.DateTimeField("預計開始", null=True, blank=True)
    planned_end = models.DateTimeField("預計結束", null=True, blank=True)
    hosts = models.ManyToManyField(Host, blank=True, related_name="tickets", verbose_name="預計主機")
    created_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-id"]
        verbose_name = verbose_name_plural = "變更單"

    def __str__(self):
        return self.number


class FindingEvent(models.Model):
    """事件：只新增，不修改（單號除外，改單號另記稽核）"""
    KINDS = [("initial", "初始"), ("appeared", "新出現"), ("reappeared", "重新出現"), ("resolved", "已解決"),
             ("changed", "狀態變化")]
    CAUSES = [
        ("initial", "基準"),
        ("new_host", "新主機"), ("package_change", "主機套件變更"), ("new_advisory", "新公告"),
        ("advisory_revised", "公告修訂"),
        ("patched", "已修補"), ("removed", "已移除"), ("rebooted", "已重開機"), ("host_retired", "主機移除"),
        ("fix_released", "釋出修正"), ("fixed_changed", "修正版本變更"), ("need_reboot", "待重開機"),
        ("priority_changed", "等級變更"), ("other", "其他（設定或資料來源變更）"),
    ]
    TICKET_REQUIRED = ("patched", "removed", "rebooted")
    TICKET_OPTIONAL = ("package_change",)

    run = models.ForeignKey(Run, on_delete=models.CASCADE, related_name="events")
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="events")
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="events")
    cve = models.CharField(max_length=40)
    package = models.CharField(max_length=200)
    location = models.CharField(max_length=20)
    priority = models.CharField(max_length=20, blank=True)
    kind = models.CharField(max_length=20, choices=KINDS)
    cause = models.CharField(max_length=20, choices=CAUSES)
    old = models.JSONField(null=True)
    new = models.JSONField(null=True)
    excepted = models.BooleanField(default=False)
    needs_ticket = models.BooleanField(default=False)
    ticket = models.ForeignKey(ChangeTicket, null=True, blank=True, on_delete=models.PROTECT, related_name="events")
    ticket_set_by = models.CharField(max_length=150, blank=True)
    ticket_set_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField()

    class Meta:
        ordering = ["-id"]
        indexes = [models.Index(fields=["run", "kind"], name="cvetrack_event_run"),
                   models.Index(fields=["host", "created_at"], name="cvetrack_event_host"),
                   models.Index(fields=["cve"], name="cvetrack_event_cve"),
                   models.Index(fields=["needs_ticket", "ticket"], name="cvetrack_event_ticket")]


class RiskException(models.Model):
    """例外／風險接受"""
    host_pattern = models.CharField("主機名稱（可用 *）", max_length=255)
    cve = models.CharField("CVE（可用 *）", max_length=40)
    reason = models.TextField("原因")
    expires_at = models.DateField("到期日", null=True, blank=True)
    created_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = verbose_name_plural = "例外"


class AuditLog(models.Model):
    ts = models.DateTimeField(auto_now_add=True)
    user = models.CharField(max_length=150, blank=True)
    ip = models.CharField(max_length=64, blank=True)
    action = models.CharField(max_length=50)
    detail = models.TextField(blank=True)

    class Meta:
        ordering = ["-id"]


def audit(user, action, detail="", ip=""):
    name = getattr(user, "get_username", lambda: str(user or ""))() if user else ""
    AuditLog.objects.create(user=name, ip=ip, action=action, detail=detail)

