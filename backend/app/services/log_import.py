"""
DNS and proxy logs as a Shadow AI collector.

Most organizations already log every name their DNS servers resolve and every
site their web proxy serves. Those logs show who uses which AI service without
installing anything: this module reads them, keeps only the lines that reach
an AI service (the organization's AI Domain Catalog plus the built-in list),
and turns them into ordinary "domain_visit" events - one per service, person
and computer, with how many times and when - so they become sightings, show who
uses what, and raise incidents for blocked services exactly as the browser
extension's visits do.

Two ways in (app/api/shadow_ai.py):
- an administrator uploads a log file in the console (Shadow AI -> Import logs);
- a log forwarder posts new lines continuously with a Gateway ingestion key
  (POST /shadow-ai/ingest/logs).

Formats are recognized line by line, so one file may mix them:

  Squid access.log (native)     1730512345.123  150 10.0.0.5 TCP_TUNNEL/200 3456 CONNECT chatgpt.com:443 alice ...
  BIND query log                ... client @0x7f.. 10.0.0.5#53211 (chatgpt.com): query: chatgpt.com IN A + (10.0.0.1)
  dnsmasq / Pi-hole             Nov  2 10:00:00 dnsmasq[123]: query[A] chatgpt.com from 10.0.0.5
  Unbound (log-queries)         [1730512345] unbound[1:0] info: 10.0.0.5 chatgpt.com. A IN
  Windows DNS debug log         11/2/2026 10:00:00 AM 0E5C PACKET ... UDP Rcv 10.0.0.5 1234   Q [...] A (7)chatgpt(3)com(0)
  Zeek dns.log / http.log       TSV with a #fields header, or JSON lines
  JSON lines                    {"ts": ..., "query": "chatgpt.com", "client_ip": "10.0.0.5", "user": "alice"}
  CSV with a header             Cisco Umbrella, Zscaler, Netskope, Palo Alto, ... exports
  key=value (Fortinet, CEF ...) srcip=10.0.0.5 user="alice" hostname="chatgpt.com" action="blocked"

Any other line: the host names in it are still found (and its first IPv4
address taken as the computer), only the person is not. Nothing but the
host, the person, the computer, the time and blocked/allowed is kept: never a
URL path, a query or the rest of the line.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

# what the event says the line came from
DNS = "dns_log"
PROXY = "proxy_log"

_HOST_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])\.?(?![\w-])", re.I)
_IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")
_SQUID_RE = re.compile(
    r"^\s*(\d{9,11}(?:\.\d+)?)\s+\d+\s+(\S+)\s+([A-Z_]+)/(\d{3})\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)"
)
_BIND_RE = re.compile(r"client (?:@\S+ )?([0-9a-f.:]+)#\d+(?: \([^)]*\))?: (?:view \S+: )?query: (\S+) ", re.I)
_DNSMASQ_RE = re.compile(r"query\[\w+\] (\S+) from ([0-9a-f.:]+)", re.I)
_UNBOUND_RE = re.compile(r"info: ([0-9a-f.:]+) (\S+?)\.? [A-Z0-9]+ IN\b")
_WINDNS_RE = re.compile(r"\bRcv\s+([0-9a-f.:]+)\s+\S+\s+Q\s+\[[^\]]*\]\s+\w+\s+(\(\d+\)\S+)", re.I)
_EMAIL_IN = re.compile(r"[\w.%+'-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63})+")
_KV_RE = re.compile(r'([A-Za-z_][\w.-]{0,40})=("(?:[^"\\]|\\.)*"|\S*)')

# column / key names, lower case, without spaces, dashes and underscores
_HOST_KEYS = ("query", "qname", "domain", "hostname", "host", "dhost", "desthost", "destinationhost",
              "fqdn", "servername", "sni", "dstdomain", "site", "urlhost", "url", "request", "requesturl",
              "uri", "dsthost", "destination", "dest")
_USER_KEYS = ("user", "username", "suser", "srcuser", "login", "usrname", "mostgranularidentity",
              "identity", "identities", "useremail", "email", "account", "duser")
_CLIENT_KEYS = ("clientip", "client", "srcip", "src", "sourceip", "source", "internalip", "idorigh",
                "cip", "clientaddress", "srcaddr", "devicename", "hostip")
_TIME_KEYS = ("ts", "timestamp", "time", "datetime", "date", "eventtime", "receivetime", "start")
_ACTION_KEYS = ("action", "act", "verdict", "disposition", "policyaction", "status")
_BLOCKED_WORDS = {"blocked", "block", "deny", "denied", "drop", "dropped", "reset", "refused", "nxdomain-blocked"}
_NO_USER = {"", "-", "n/a", "na", "none", "null", "unknown", "anonymous"}


def _norm_key(k: str) -> str:
    return re.sub(r"[\s_\-.]+", "", k.strip().lower())


@dataclass
class Hit:
    host: str
    user: Optional[str]
    client: Optional[str]
    ts: Optional[datetime]
    blocked: bool
    kind: str  # DNS or PROXY


def host_of(value: str) -> Optional[str]:
    """The host name in a URL, "host:port", a DNS name with a trailing dot,
    or a Windows DNS label form "(7)chatgpt(3)com(0)"."""
    v = (value or "").strip().strip('"').lower()
    if not v:
        return None
    if v.startswith("(") and re.fullmatch(r"(\(\d+\)[^()]*)+", v):
        v = ".".join(p for p in re.split(r"\(\d+\)", v) if p)
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split("?", 1)[0].split("@")[-1]
    if v.startswith("["):  # [ipv6]:port
        return None
    v = v.rsplit(":", 1)[0] if v.count(":") == 1 else v
    v = v.rstrip(".")
    m = _HOST_RE.fullmatch(v)
    return m.group(1) if m else None


def _user(value) -> Optional[str]:
    """A person as the log names them (alice, CORP\\alice, alice@corp.com),
    without control characters; nothing for placeholders."""
    if value is None:
        return None
    v = str(value).strip().strip('"')
    if "," in v:  # Umbrella "Identities": several, the first is the most specific
        v = v.split(",", 1)[0].strip()
    v = "".join(c for c in v if c.isprintable())[:120]
    # "frank (frank@corp.com)": the address, as the browser extension reports it
    if (m := _EMAIL_IN.search(v)) and m.group(0) != v:
        v = m.group(0)
    return None if v.lower() in _NO_USER else v


def _client(value) -> Optional[str]:
    if value is None:
        return None
    v = "".join(c for c in str(value).strip().strip('"') if c.isprintable())[:100]
    return None if v.lower() in _NO_USER else v


def _ts(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        num = float(value)
    else:
        v = str(value).strip().strip('"').strip("[]")
        try:
            num = float(v)
        except ValueError:
            try:
                d = datetime.fromisoformat(v.replace("Z", "+00:00").replace(" UTC", "+00:00"))
            except ValueError:
                return None
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    if num > 1e12:  # milliseconds
        num /= 1000
    if not 946684800 <= num <= 4102444800:  # 2000 .. 2100
        return None
    return datetime.fromtimestamp(num, tz=timezone.utc)


def _blocked(value) -> bool:
    if value is None:
        return False
    v = str(value).strip().strip('"').lower()
    return v in _BLOCKED_WORDS or v.startswith("block") or v.startswith("den")


def _pick(record: Dict[str, str], keys: Tuple[str, ...]) -> Optional[str]:
    for k in keys:
        v = record.get(k)
        if v not in (None, ""):
            return v
    return None


def _from_record(record: Dict[str, object]) -> Optional[Hit]:
    """A JSON object, a CSV row or key=value pairs (keys normalized)."""
    host = None
    for k in _HOST_KEYS:
        v = record.get(k)
        if isinstance(v, str) and (host := host_of(v)):
            break
    if not host:
        return None
    kind = DNS if any(k in record for k in ("query", "qname", "qtype", "querytype", "rcode", "responsecode")) else PROXY
    return Hit(
        host=host,
        user=_user(_pick(record, _USER_KEYS)),
        client=_client(_pick(record, _CLIENT_KEYS)),
        ts=_ts(_pick(record, _TIME_KEYS)),
        blocked=_blocked(_pick(record, _ACTION_KEYS)),
        kind=kind,
    )


def _flatten(obj: dict, prefix: str = "") -> Dict[str, object]:
    out: Dict[str, object] = {}
    for k, v in obj.items():
        key = _norm_key(prefix + str(k))
        if isinstance(v, dict) and len(out) < 200:
            for fk, fv in _flatten(v, str(k)).items():
                out.setdefault(fk, fv)
        elif isinstance(v, list):
            if v and isinstance(v[0], (str, int, float)):
                out.setdefault(key, v[0])
        else:
            out.setdefault(key, v)
    return out


class LogParser:
    """Reads log lines of any of the formats above; feed() keeps the state a
    header line sets (CSV columns, Zeek #fields)."""

    def __init__(self) -> None:
        self.csv_columns: Optional[List[str]] = None
        self.csv_delimiter = ","
        self.zeek_fields: Optional[List[str]] = None
        self.formats: Dict[str, int] = {}

    def _count(self, fmt: str) -> None:
        self.formats[fmt] = self.formats.get(fmt, 0) + 1

    def feed(self, line: str) -> List[Hit]:
        line = line.strip("\r\n\ufeff")
        if not line.strip():
            return []
        if line.startswith("#"):
            if line.startswith("#fields"):
                self.zeek_fields = [_norm_key(f) for f in line.split("\t")[1:]]
                self.csv_columns = None
            elif line.startswith("#Fields:"):  # W3C extended (IIS, some proxies)
                self.csv_columns = [_norm_key(f) for f in line[8:].split()]
                self.csv_delimiter = " "
            return []

        if self.zeek_fields:
            values = line.split("\t")
            if len(values) == len(self.zeek_fields):
                hit = _from_record(dict(zip(self.zeek_fields, values)))
                if hit:
                    self._count("zeek")
                    return [hit]

        if line.lstrip().startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                hit = _from_record(_flatten(obj))
                if hit:
                    self._count("json")
                    return [hit]

        if (m := _SQUID_RE.match(line)) and (host := host_of(m.group(6))):
            self._count("squid")
            status, user = m.group(3), _user(m.group(7))
            return [Hit(host, user, _client(m.group(2)), _ts(m.group(1)), "DENIED" in status, PROXY)]
        for fmt, rx, h, c in (("bind", _BIND_RE, 2, 1), ("dnsmasq", _DNSMASQ_RE, 1, 2),
                              ("unbound", _UNBOUND_RE, 2, 1), ("windows_dns", _WINDNS_RE, 2, 1)):
            if (m := rx.search(line)) and (host := host_of(m.group(h))):
                self._count(fmt)
                return [Hit(host, None, _client(m.group(c)), None, False, DNS)]

        if self.csv_columns:
            row = self._csv_row(line)
            if row is not None and len(row) == len(self.csv_columns):
                hit = _from_record(dict(zip(self.csv_columns, row)))
                if hit:
                    self._count("csv")
                    return [hit]
        elif self._maybe_header(line):
            return []

        pairs = _KV_RE.findall(line)
        if len(pairs) >= 3:
            record = {_norm_key(k): v.strip('"') for k, v in pairs}
            hit = _from_record(record)
            if hit:
                self._count("key_value")
                return [hit]

        # anything else: the host names in it, the first IPv4 as the computer
        hosts = {h for h in (host_of(t) for t in _HOST_RE.findall(line)) if h}
        if not hosts:
            return []
        self._count("other")
        ip = _IPV4_RE.search(line)
        client = ip.group(1) if ip else None
        return [Hit(h, None, client, None, False, PROXY) for h in sorted(hosts)]

    def _csv_row(self, line: str) -> Optional[List[str]]:
        if self.csv_delimiter == " ":
            return line.split()
        try:
            return next(csv.reader([line], delimiter=self.csv_delimiter))
        except (csv.Error, StopIteration):
            return None

    def _maybe_header(self, line: str) -> bool:
        """A CSV header: a delimiter, a host-like column name, no host name."""
        for delim in (",", ";", "\t", "|"):
            if delim not in line:
                continue
            try:
                cols = next(csv.reader([line], delimiter=delim))
            except (csv.Error, StopIteration):
                continue
            names = [_norm_key(c) for c in cols]
            if len(names) >= 2 and any(n in _HOST_KEYS for n in names) and not any(host_of(c) for c in cols):
                self.csv_columns, self.csv_delimiter = names, delim
                return True
        return False


@dataclass
class Visit:
    """One AI service, person and computer: how often, when, blocked how often."""
    host: str
    user: Optional[str]
    client: Optional[str]
    kind: str
    hits: int = 0
    blocked: int = 0
    first: Optional[datetime] = None
    last: Optional[datetime] = None


@dataclass
class ImportResult:
    lines: int = 0
    recognized: int = 0       # lines with a host name in a known format
    ai_lines: int = 0         # of those, lines that reach an AI service
    visits: Dict[Tuple[str, Optional[str], Optional[str], str], Visit] = field(default_factory=dict)
    formats: Dict[str, int] = field(default_factory=dict)
    truncated: bool = False   # more distinct visits than MAX_VISITS: the rest was not counted

    def summary(self) -> dict:
        per_host: Dict[str, int] = {}
        for v in self.visits.values():
            per_host[v.host] = per_host.get(v.host, 0) + v.hits
        top = sorted(per_host.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
        return {
            "lines": self.lines,
            "recognized": self.recognized,
            "ai_lines": self.ai_lines,
            "services": len(per_host),
            "people": len({v.user for v in self.visits.values() if v.user}),
            "computers": len({v.client for v in self.visits.values() if v.client}),
            "formats": dict(sorted(self.formats.items(), key=lambda kv: -kv[1])),
            "top": [{"domain": d, "hits": n} for d, n in top],
            "truncated": self.truncated,
        }


MAX_VISITS = 20000


def import_lines(lines: Iterable[str], is_ai: Callable[[str], bool]) -> ImportResult:
    """Reads the lines, keeps the AI ones and folds them into visits."""
    parser = LogParser()
    result = ImportResult()
    ai_cache: Dict[str, bool] = {}
    for line in lines:
        result.lines += 1
        hits = parser.feed(line)
        if hits:
            result.recognized += 1
        counted = False
        for h in hits:
            ai = ai_cache.get(h.host)
            if ai is None:
                ai = ai_cache[h.host] = is_ai(h.host)
                if len(ai_cache) > 200000:
                    ai_cache.clear()
            if not ai:
                continue
            counted = True
            key = (h.host, h.user, h.client, h.kind)
            v = result.visits.get(key)
            if v is None:
                if len(result.visits) >= MAX_VISITS:
                    result.truncated = True
                    continue
                v = result.visits[key] = Visit(h.host, h.user, h.client, h.kind)
            v.hits += 1
            v.blocked += 1 if h.blocked else 0
            if h.ts:
                v.first = h.ts if v.first is None or h.ts < v.first else v.first
                v.last = h.ts if v.last is None or h.ts > v.last else v.last
        if counted:
            result.ai_lines += 1
    result.formats = parser.formats
    return result


def to_events(result: ImportResult, source_label: str) -> List[dict]:
    """The visits as domain_visit events (TelemetryEventIn, JSON form)."""
    now = datetime.now(timezone.utc)
    events = []
    for v in result.visits.values():
        when = v.last or now
        events.append({
            "event_type": "domain_visit",
            "domain": v.host,
            "agent_id": v.client or source_label,
            "user_id": v.user,
            "action_taken": "blocked" if v.blocked and v.blocked == v.hits else "monitored",
            "timestamp": when.isoformat(),
            "payload": {
                "source": v.kind,
                "hits": v.hits,
                "blocked_hits": v.blocked,
                "first_seen": (v.first or when).isoformat(),
                "last_seen": when.isoformat(),
            },
        })
    return events


def decode_lines(chunks: Iterable[bytes]) -> Iterator[str]:
    """Bytes (UTF-8, UTF-16 with a BOM - a Windows export - or Latin-1 when
    neither) to lines, without holding the whole file."""
    import codecs

    decoder = None
    pending = ""
    for chunk in chunks:
        if decoder is None:
            if chunk[:2] in (b"\xff\xfe", b"\xfe\xff"):
                decoder = codecs.getincrementaldecoder("utf-16")("replace")
            else:
                decoder = codecs.getincrementaldecoder("utf-8")("replace")
        pending += decoder.decode(chunk)
        *done, pending = pending.split("\n")
        yield from done
    if decoder is not None:
        pending += decoder.decode(b"", final=True)
    if pending:
        yield pending


def gunzip_chunks(chunks: Iterable[bytes], limit: int) -> Iterator[bytes]:
    """Decompresses a gzip stream on the fly; stops at limit bytes of output
    (a small file must not expand into gigabytes)."""
    import zlib

    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    for chunk in chunks:
        data = chunk
        while data:
            out = d.decompress(data, 1 << 20)
            total += len(out)
            if total > limit:
                raise ValueError("too_large")
            if out:
                yield out
            data = d.unconsumed_tail
    out = d.flush()
    if total + len(out) > limit:
        raise ValueError("too_large")
    if out:
        yield out
    if not d.eof:
        raise ValueError("unreadable")  # cut off before its end


def maybe_gunzip(chunks: Iterator[bytes], limit: int) -> Iterator[bytes]:
    """gzip when the stream starts with its magic bytes, else as it is."""
    first = next(chunks, b"")
    if not first:
        return iter(())

    def rest():
        yield first
        yield from chunks

    if first[:2] == b"\x1f\x8b":
        return gunzip_chunks(rest(), limit)
    return rest()


__all__ = [
    "DNS", "PROXY", "Hit", "LogParser", "ImportResult", "Visit", "import_lines", "to_events",
    "decode_lines", "maybe_gunzip", "host_of", "MAX_VISITS",
]



# ---------------------------------------------------------------- the import

def read_file(path: str, limit: int, is_ai: Callable[[str], bool]) -> ImportResult:
    """The whole import of one spooled upload (run in a worker thread)."""
    def chunks():
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                yield chunk

    return import_lines(decode_lines(maybe_gunzip(chunks(), limit)), is_ai)


async def spool(stream, limit: int) -> str:
    """The request body into a temporary file, refusing more than limit
    bytes; returns its path (the caller deletes it)."""
    import os
    import tempfile

    fd, path = tempfile.mkstemp(prefix="provenza-log-")
    total = 0
    try:
        with os.fdopen(fd, "wb") as f:
            async for chunk in stream:
                total += len(chunk)
                if total > limit:
                    raise ValueError("too_large")
                f.write(chunk)
    except BaseException:
        os.unlink(path)
        raise
    return path


async def run_import(db, org_id: int, source_id: int, stream, limit: int, label: str) -> dict:
    """Spools the body, reads it, sends the AI visits through the telemetry
    pipeline (sightings, people, incidents for blocked services) and returns
    what was found."""
    import os

    from starlette.concurrency import run_in_threadpool

    from app.services.domain_catalog_service import DomainCatalogService
    from app.workers.telemetry_tasks import process_telemetry_batch

    is_ai = await DomainCatalogService(db).ai_domains(org_id)
    path = await spool(stream, limit)
    try:
        result = await run_in_threadpool(read_file, path, limit, is_ai)
    finally:
        os.unlink(path)
    events = to_events(result, label)
    for i in range(0, len(events), 500):
        process_telemetry_batch.delay(org_id, source_id, events[i:i + 500], record_devices=False)
    out = result.summary()
    out["events"] = len(events)
    return out
