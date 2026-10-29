"""變更單：補單號、建議對應、報告"""
import datetime
import re

from django.db import transaction
from django.db.models import Count, Q
from django.utils import timezone

from ..conf import conf
from ..models import ChangeTicket, FindingEvent, audit

ASSIGNABLE = Q(needs_ticket=True) | Q(cause__in=FindingEvent.TICKET_OPTIONAL)


class TicketError(ValueError):
    pass


def clean_number(number):
    number = (number or "").strip()
    if not number:
        raise TicketError("請輸入單號")
    if len(number) > 100:
        raise TicketError("單號太長（最多 100 字）")
    pat = conf.TICKET_PATTERN
    if pat and not re.fullmatch(pat, number):
        raise TicketError("單號格式不符（%s）" % pat)
    return number


def get_or_create(number, user):
    number = clean_number(number)
    t, created = ChangeTicket.objects.get_or_create(number=number, defaults={"created_by": user.get_username()})
    if created:
        audit(user, "ticket_create", number)
    return t


def assign(events, ticket, user, ip=""):
    """把事件掛到變更單；只接受需要或可以掛單號的事件。回傳 (掛上筆數, 原本是其他單號的筆數)"""
    with transaction.atomic():
        qs = FindingEvent.objects.filter(pk__in=list(events.filter(ASSIGNABLE).values_list("pk", flat=True)))
        moved = qs.exclude(ticket=None).exclude(ticket=ticket)
        moved_detail = list(moved.values("ticket__number").annotate(n=Count("id")))
        n_moved = sum(m["n"] for m in moved_detail)
        n = qs.update(ticket=ticket, ticket_set_by=user.get_username(), ticket_set_at=timezone.now())
        detail = "%s：%d 筆" % (ticket.number, n)
        if moved_detail:
            detail += "（其中改單號：%s）" % "、".join("%s %d 筆" % (m["ticket__number"], m["n"]) for m in moved_detail)
        audit(user, "ticket_assign", detail, ip)
    return n, n_moved


def unassign(events, user, ip=""):
    with transaction.atomic():
        detail = list(events.exclude(ticket=None).values("ticket__number").annotate(n=Count("id")))
        n = events.exclude(ticket=None).update(ticket=None, ticket_set_by=user.get_username(), ticket_set_at=timezone.now())
        audit(user, "ticket_unassign", "、".join("%s %d 筆" % (d["ticket__number"], d["n"]) for d in detail), ip)
    return n


def unticketed():
    return FindingEvent.objects.filter(needs_ticket=True, ticket=None)


def overdue_unticketed():
    limit = timezone.now() - datetime.timedelta(days=conf.UNTICKETED_WARN_DAYS)
    return unticketed().filter(created_at__lt=limit)


def suggestions(ticket):
    """還沒有單號、發生在這張單的預計主機與預計時間內的修補事件（由人確認後才掛上）"""
    if not ticket.planned_start or not ticket.planned_end:
        return FindingEvent.objects.none()
    end = ticket.planned_end + datetime.timedelta(hours=conf.TICKET_SUGGEST_GRACE_HOURS)
    return unticketed().filter(host__in=ticket.hosts.all(), run__started_at__gte=ticket.planned_start, run__started_at__lte=end)


def tickets_without_events():
    """預計結束時間已過，卻沒有任何事件對應到的變更單"""
    return ChangeTicket.objects.filter(planned_end__lt=timezone.now()).annotate(n=Count("events")).filter(n=0)
