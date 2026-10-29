from django.urls import path

from . import views

app_name = "cvetrack"
urlpatterns = [
    path("", views.index, name="index"),
    path("runs/", views.run_list, name="runs"),
    path("runs/<int:pk>/", views.run_detail, name="run"),
    path("events/", views.events, name="events"),
    path("osv/", views.osv_list, name="osv_list"),
    path("osv/<int:pk>/", views.osv_detail, name="osv"),
    path("findings/", views.findings, name="findings"),
    path("hosts/", views.host_list, name="hosts"),
    path("hosts/<int:pk>/", views.host_detail, name="host"),
    path("cve/<str:cve>/", views.cve_detail, name="cve"),
    path("unticketed/", views.unticketed, name="unticketed"),
    path("tickets/", views.ticket_list, name="tickets"),
    path("tickets/new/", views.ticket_edit, name="ticket_new"),
    path("tickets/<int:pk>/", views.ticket_detail, name="ticket"),
    path("tickets/<int:pk>/edit/", views.ticket_edit, name="ticket_edit"),
    path("tickets/assign/", views.ticket_assign, name="ticket_assign"),
    path("data/", views.data, name="data"),
    path("sync/", views.sync_now, name="sync"),
    path("audit/", views.audit_log, name="audit"),
]
