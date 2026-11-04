"""主機名稱的儲存與比對（Landscape 同步與主機清單匯入共用），規則依 HOST_MATCH_KEY

  比對鍵 key()：shortname＝第一段，hostname／ip＝完整名稱（IP 會變，不拿來接續歷史）；一律不分大小寫
  （資料庫裡的主機名稱一向不分大小寫比對；HOST_MATCH_CASE_INSENSITIVE 只管對應 kernel API）
  同一台：比對鍵相同，而且名稱相同或其中一邊是短名稱（web01 ↔ web01.example.com）；
         兩個不同的完整名稱（web01.a.example.com ↔ web01.b.example.com）不算同一台
  完整名稱（來源回報的原樣）存在 host.fqdn，比對一律用它；host.hostname 是顯示用的名稱（refresh_names）：
  shortname 時存第一段，同一個比對鍵有兩台以上啟用中的主機時存完整名稱，畫面上才分得出來。例外規則兩個都比
"""
import ipaddress

from .config import Config


def short(name):
    """第一段（web01.example.com → web01）；名稱本身是 IP 位址時不切"""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        return name.split(".")[0]


def norm(name):
    """比對用：不分大小寫、不看結尾的點（web01.example.com. 與 web01.example.com 相同）"""
    return name.rstrip(".").lower()


def key(name):
    return norm(short(name) if Config.HOST_MATCH_KEY == "shortname" else name)


def stored(name, alone):
    """存進 host.hostname 的名稱；alone＝這個比對鍵只有這一台"""
    return short(name) if alone and Config.HOST_MATCH_KEY == "shortname" else name


def full(row):
    """主機紀錄的完整名稱（0.9.4 之前的紀錄 fqdn 由升級補上；保險起見沒有時用 hostname）"""
    return row["fqdn"] or row["hostname"]


def same_machine(a, b):
    """比對鍵相同的兩個完整名稱是不是同一台"""
    a, b = norm(a), norm(b)
    return a == b or "." not in a or "." not in b


def pick(rows):
    """從候選主機（新的在前）挑要沿用的那筆，回傳 (row, ambiguous)：
    啟用中的只有一筆＝它；兩筆以上＝分不出是哪一台（None, True）；都停用＝最新的一筆，
    但候選裡有兩個不同的完整名稱（不同台，例如 web01.a… 與 web01.b…）時不接續（None, False：另建一筆）；沒有＝(None, False)"""
    active = [r for r in rows if r["active"]]
    if len(active) > 1:
        return None, True
    if active:
        return active[0], False
    if any(not same_machine(full(a), full(b)) for i, a in enumerate(rows) for b in rows[:i]):
        return None, False
    return (rows or [None])[0], False


def choose(rows, name, exact_only=False):
    """rows＝比對鍵相同的既有主機（db.hosts_by_key，新的在前），找 name 要沿用的那筆，回傳 (row, ambiguous)
      只看同一台的（same_machine）；exact_only＝這次來源裡有別台的比對鍵相同，只認名稱完全相同的
      分不出來時（啟用中的有兩筆以上），名稱完全相同、啟用中的優先（有多筆同名時取最新的）；
      都停用時，名稱完全相同的優先（候選是不同台、pick 不接續時也一樣）"""
    exact = [r for r in rows if norm(full(r)) == norm(name)]
    row, ambiguous = pick(exact if exact_only else candidates(rows, name))
    if ambiguous:
        active = [r for r in exact if r["active"]]
        if active:
            return active[0], False
    elif (row is None or not row["active"]) and exact:
        return exact[0], False
    return row, ambiguous


def candidates(rows, name):
    """rows 裡和 name 是同一台的"""
    return [r for r in rows if same_machine(full(r), name)]


def refresh_names(con):
    """重新決定 host.hostname（同步、匯入寫完後在同一個交易裡呼叫；結果只看資料，不看處理順序）：
    啟用中、比對鍵只有這一台啟用中的＝stored(…, alone=True)；其他（兩台以上、已停用的）＝完整名稱，畫面上才不會同名"""
    groups = {}
    rows = con.execute("SELECT id, hostname, fqdn, active FROM host").fetchall()
    for r in rows:
        if r["active"]:
            groups.setdefault(key(full(r)), []).append(r)
    for r in rows:
        want = stored(full(r), r["active"] and len(groups[key(full(r))]) == 1)
        if want != r["hostname"]:
            con.execute("UPDATE host SET hostname=? WHERE id=?", (want, r["id"]))
