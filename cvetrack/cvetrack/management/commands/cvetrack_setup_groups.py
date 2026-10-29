from django.contrib.auth.models import Group, Permission
from django.core.management.base import BaseCommand

GROUPS = {
    "cvetrack-viewer": ["view_cvetrack"],
    "cvetrack-operator": ["view_cvetrack", "operate_cvetrack"],
    "cvetrack-admin": ["view_cvetrack", "operate_cvetrack", "admin_cvetrack"],
}
# operator 另外可以在 Django Admin 管理變更單與例外
ADMIN_MODEL_PERMS = {
    "cvetrack-operator": ["view_changeticket", "add_changeticket", "change_changeticket",
                          "view_riskexception", "add_riskexception", "change_riskexception", "delete_riskexception"],
    "cvetrack-admin": ["view_changeticket", "add_changeticket", "change_changeticket", "delete_changeticket",
                       "view_riskexception", "add_riskexception", "change_riskexception", "delete_riskexception",
                       "view_host", "view_auditlog"],
}


class Command(BaseCommand):
    help = "建立 cvetrack 的三個群組（viewer／operator／admin）並設定權限；重複執行只會補齊，不會刪掉其他權限"

    def handle(self, **_):
        for name, codes in GROUPS.items():
            g, created = Group.objects.get_or_create(name=name)
            perms = Permission.objects.filter(content_type__app_label="cvetrack",
                                              codename__in=codes + ADMIN_MODEL_PERMS.get(name, []))
            g.permissions.add(*perms)
            self.stdout.write("%s %s：%d 個權限" % ("建立" if created else "更新", name, perms.count()))
        self.stdout.write("把使用者加進群組即可（Django Admin → 使用者 → 群組）。之後接 LDAP 時，把 AD 群組對應到這三個群組。")
