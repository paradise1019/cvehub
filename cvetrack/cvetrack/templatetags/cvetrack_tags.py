from django import template
from django.utils.http import urlencode

register = template.Library()


@register.filter
def lookup(d, key):
    try:
        return d.get(key, key)
    except AttributeError:
        return key


@register.simple_tag(takes_context=True)
def qs(context, **kw):
    """目前的查詢字串，改掉指定的參數（值為空字串＝移除）"""
    q = context["request"].GET.copy()
    q.pop("page", None)
    for k, v in kw.items():
        q.pop(k, None)
        if v not in ("", None):
            q[k] = v
    return "?" + urlencode(sorted(q.items())) if q else "?"


@register.filter
def ver(d, key):
    """事件的 old／new JSON 取欄位"""
    return (d or {}).get(key, "")
