"""CSV／Excel 匯出（含公式注入防護）"""
import csv
import io

from django.http import HttpResponse


def safe_cell(v):
    """開頭是 = + - @ 或 tab／CR 的字串，前面加 '，避免被試算表當成公式"""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _value(v):
    if hasattr(v, "tzinfo") and getattr(v, "tzinfo", None) is not None:
        from django.utils import timezone
        return timezone.localtime(v).replace(tzinfo=None)
    return v


def response(fmt, filename, headers, rows):
    rows = ([safe_cell(_value(v)) for v in r] for r in rows)
    if fmt == "xlsx":
        from openpyxl import Workbook
        wb = Workbook(write_only=True)
        ws = wb.create_sheet("data")
        ws.append(headers)
        for r in rows:
            ws.append(r)
        buf = io.BytesIO()
        wb.save(buf)
        resp = HttpResponse(buf.getvalue(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        resp["Content-Disposition"] = 'attachment; filename="%s.xlsx"' % filename
        return resp
    buf = io.StringIO()
    buf.write("﻿")          # Excel 開 UTF-8 CSV 需要 BOM
    w = csv.writer(buf)
    w.writerow(headers)
    w.writerows(rows)
    resp = HttpResponse(buf.getvalue(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="%s.csv"' % filename
    return resp
