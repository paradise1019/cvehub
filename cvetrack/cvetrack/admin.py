from django.contrib import admin

from .models import AuditLog, ChangeTicket, Host, RiskException


@admin.register(ChangeTicket)
class ChangeTicketAdmin(admin.ModelAdmin):
    list_display = ("number", "title", "planned_start", "planned_end", "created_by", "created_at")
    search_fields = ("number", "title")
    filter_horizontal = ("hosts",)
    readonly_fields = ("created_by", "created_at")


@admin.register(RiskException)
class RiskExceptionAdmin(admin.ModelAdmin):
    list_display = ("host_pattern", "cve", "reason", "expires_at", "created_by", "created_at")
    search_fields = ("host_pattern", "cve", "reason")
    readonly_fields = ("created_by", "created_at")

    def save_model(self, request, obj, form, change):
        if not obj.created_by:
            obj.created_by = request.user.get_username()
        super().save_model(request, obj, form, change)


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("hostname", "ip", "release", "pro_attached", "kernel_status", "active", "last_seen")
    list_filter = ("release", "active", "kernel_status")
    search_fields = ("hostname", "ip")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("ts", "user", "ip", "action", "detail")
    list_filter = ("action",)
    search_fields = ("user", "detail")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
