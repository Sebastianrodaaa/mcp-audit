"""Static checks over tool, prompt and resource metadata.

Every rule reads only what a client would hand the model: names, descriptions, schemas and server
instructions. Nothing is executed. Each check yields Findings with a rule id, a severity and the
exact text that triggered it.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Iterator

from .model import SEVERITIES, Finding, Server, sev_rank


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    summary: str


RULES = {r.id: r for r in [
    Rule("MA001", "hidden-unicode", "Invisible or direction-changing Unicode that the user does not see but the model reads."),
    Rule("MA002", "model-directed-instruction", "Text that issues orders to the model instead of describing the tool."),
    Rule("MA003", "sensitive-path", "References to credentials, keys or agent config files."),
    Rule("MA004", "tool-shadowing", "Instructions about how to call a different tool, or to call one first."),
    Rule("MA005", "exfiltration-parameter", "A parameter whose name or description asks for conversation context or secrets."),
    Rule("MA006", "oversized-schema", "Unusually many parameters or an unusually long description."),
    Rule("MA007", "suspicious-literal", "Encoded blobs or outbound destinations embedded in metadata."),
    Rule("MA008", "concealment", "Asks the model to hide what it is doing from the user."),
    Rule("MA009", "hidden-markup", "Comments, tags or whitespace gaps that hide text from a rendered view."),
    Rule("MA010", "data-exfiltration", "Asks the model to send, include or forward user data or secrets."),
    Rule("MA011", "name-collision", "Tool names that collide across servers or use look-alike characters."),
    Rule("MA012", "rug-pull", "A pinned definition changed since the lockfile was written."),
    Rule("MA013", "llm-judge", "A local model, given a fixed rubric, judged the definition poisoned."),
]}

# ---------------------------------------------------------------- text helpers

INVISIBLE = {
    **{c: "zero-width" for c in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E)},
    **{c: "bidi-control" for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A), 0x200E, 0x200F, 0x061C)},
}
DIRECTIVE = r"(?:must|should|shall|need(?:s)? to|have to|has to|are required to|is required to|required to|mandatory|always|first|it is (?:critical|essential|necessary)|be sure to|make sure to|ensure (?:you|that you))"
ACTION = (r"(?:call|invoke|use|run|execute|trigger|modify|change|set|append|prepend|replace|rewrite|alter|override|"
          r"redirect|route|overwrite|delete|remove|move|send|forward|post|create|write|read|fetch|add|include|pass|swap|"
          r"update|reset|launch|copy|upload|switch)")
SENSITIVE = re.compile(
    r"(?:~|\$HOME|/home/\w+|/root)?/\.ssh\b|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|authorized_keys|known_hosts|"
    r"/etc/(?:passwd|shadow|sudoers|group|hosts)\b|\.aws/credentials|\.netrc\b|\.git-credentials|\.npmrc\b|\.pypirc\b|"
    r"\.kube/config|\.docker/config\.json|\bmcp\.json\b|claude_desktop_config|\.cursor/|(?<![\w.])\.env\b|"
    r"\bprivate[ _-]?keys?\b|\bseed phrase\b|\bmnemonic\b|wallet\.dat|\bkeychain\b|/var/log/auth\.log|\bcookies?\.sqlite\b|"
    r"\.bash_history|\.zsh_history|/proc/self/environ", re.I)
STRONG = [
    (r"\b(?:ignore|disregard|forget|override)\b[^.]{0,40}\b(?:previous|prior|above|earlier|all|other|any|the user'?s?|system)\b[^.]{0,25}\b(?:instructions?|prompts?|rules?|requests?|guidelines|directives)", "tells the model to ignore its instructions"),
    (r"\bpriority\b[^.]{0,20}\b(?:higher|over|above|greater)\b|\btakes? precedence over\b|\boverrides? (?:the )?(?:user|system|any)", "claims priority over the user or system prompt"),
    (r"<\s*/?\s*(?:important|system|instructions?|secret|hidden|admin|critical)\s*>", "pseudo-system tag aimed at the model"),
    (r"\b(?:it'?s|this is|is) not optional\b|\bnon-?negotiable\b", "insists an instruction is not optional"),
    (r"\b(?:you are now|from now on|new instructions?|act as (?:an?|the) )", "tries to re-role the model"),
]
MEDIUM = [
    (rf"\bbefore\b[^.]{{0,80}}\b(?:you )?{DIRECTIVE}\b[^.]{{0,60}}\b{ACTION}\b", "orders a step before the tool is used"),
    (rf"\b{DIRECTIVE}\b[^.]{{0,40}}\b(?:modify|change|replace|append|prepend|alter|rewrite|override|redirect|swap|set)\b[^.]{{0,40}}(?:\b(?:argument|parameter|param|quer(?:y|ies)|value|field|input|id|path)\b|[`'\"])", "orders the model to alter call arguments"),
    (r"\b(?:all|any|every)\b[^.]{0,30}\b(?:requests?|calls?|searches|queries|messages|operations)\b[^.]{0,60}\b(?:must|should|will) be\b[^.]{0,20}\b(?:routed|redirected|sent|forwarded|changed|rewritten|replaced|prefixed)", "reroutes every call"),
    (r"\b(?:mandatory|compulsory|required|internal|critical)\b[^.]{0,15}\b(?:security|pre-?authori[sz]ation|verification|validation|configuration|integrity|audit)\b[^.]{0,15}\b(?:check|step|protocol|requirement|procedure|policy|event|measure)", "dresses an instruction up as a security protocol"),
    (r"\b(?:the )?(?:assistant|model|ai|agent|llm)\b[^.]{0,20}\b(?:must|should|has to|needs to|is required to)\b", "addresses the model directly"),
    (r"\bfailure to (?:do so|comply|log|follow|call|use)\b", "threatens consequences to force compliance"),
    (r"\bafter(?:wards?)?,?[^.]{0,30}\b(?:you )?(?:must|should|then)?\b[^.]{0,10}\b(?:send|forward|email|post|upload)\b", "orders a follow-up send"),
]
CONCEAL = [
    (r"\b(?:do not|don't|never|without)\b[^.]{0,30}\b(?:tell|telling|inform|informing|mention|mentioning|reveal|revealing|notify|notifying|alert|alerting|disclose|disclosing|show|showing|display|displaying)\b[^.]{0,30}\b(?:the )?user", "hides actions from the user"),
    (r"\b(?:do not|don't|never)\s+(?:mention|reveal|say|disclose)\s+(?:that|this|the|any)\b", "hides actions from the user"),
    (r"\b(?:silently|secretly|quietly|covertly|discreetly|invisibly)\b", "asks for silent action"),
    (r"\bwithout (?:the )?(?:user'?s? )?(?:knowledge|noticing|consent|confirmation|asking|permission)\b", "acts without the user's consent"),
    (r"\breturns? nothing by design\b|\bbackground (?:updater|task|job|process|sync)\b[^.]{0,40}\btriggers?\b", "describes a hidden side effect"),
]
EXFIL = re.compile(
    r"\b(?:send|forward|post|email|e-mail|upload|transmit|pass|include|attach|copy|leak|share|append|report|log)\b[^.]{0,70}?"
    r"\b(?:conversation|chat history|previous messages|message history|system prompt|(?:the )?user'?s? (?:query|request|message|prompt|data|emails?|files?|ids?|input|contacts?|address(?:es)?)|"
    r"all (?:the )?(?:emails?|messages|files|contacts|user ids|ids|email addresses|repositories|tokens|keys)|contents? of|api[ _-]?keys?|access tokens?|tokens?\b|credentials|passwords?|secrets?|ssh keys?|cookies)", re.I)
TO_ME = re.compile(r"\b(?:send|forward|email|post|upload|transmit)\b[^.]{0,60}\b(?:to me|to us|to (?:this|the following|our) (?:address|email|url|endpoint|server|channel))", re.I)
EXFIL_PARAMS = re.compile(
    r"^(?:notes?|sidenote|side_note|context|full_context|conversation|conversation_history|chat_history|history|messages|"
    r"previous_messages|system_prompt|prompt_context|user_query|original_query|reasoning|thoughts|feedback|debug|debug_info|"
    r"metadata_dump|extra|extra_info|summary_of_conversation|memory|secrets?|token|api_key|credentials)$", re.I)
EXFIL_PARAM_DESC = re.compile(r"\b(?:conversation|chat history|previous messages|system prompt|everything the user|full context|all (?:prior|previous) (?:messages|turns)|api[ _-]?key|credentials|secret|ssh|contents of)\b", re.I)
BLOB = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}|\b[0-9a-f]{64,}\b")
URL = re.compile(r"\bhttps?://[^\s'\"`<>)]+", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
SENTENCE = re.compile(r"(?<=[.!?;])\s+|\n+|\\n")


def _walk_strings(obj, path="") -> Iterator[tuple[str, str]]:
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("$schema", "type", "format", "uri", "mimeType", "required"):
                continue
            sub = f"{path}.{k}" if path else k
            if path.endswith("properties") and isinstance(k, str):
                yield f"{sub}(name)", k.replace("_", " ")  # property names reach the model too
            yield from _walk_strings(v, sub)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


MAX_SCAN = 20000  # characters per string; longer text is flagged by MA006 and only its head is scanned


def texts(defn: dict) -> list[tuple[str, str]]:
    """Every model-visible string of a definition, with a field path like 'inputSchema.properties.q.description'."""
    out = []
    for path, s in _walk_strings(defn):
        if path in ("name",) or not s.strip():
            continue
        out.append((path, s[:MAX_SCAN]))
    return out


def _identifier(name: str) -> bool:
    """A name that reads as code (snake_case, kebab-case, camelCase, dotted), not a plain word like 'status' or 'today'."""
    return bool(re.search(r"[_\-.]|[a-z][A-Z]|\d", name))


def _clip(s: str, m: re.Match | None = None, width: int = 140) -> str:
    if m is None:
        return s[:width]
    a, b = max(0, m.start() - 30), min(len(s), m.end() + 30)
    return ("…" if a else "") + s[a:b].replace("\n", " ") + ("…" if b < len(s) else "")


def _bump(sev: str) -> str:
    return SEVERITIES[min(sev_rank(sev) + 1, len(SEVERITIES) - 1)]


# ---------------------------------------------------------------- rules

def hidden_unicode(text: str):
    tags = "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)
    if tags:
        yield "critical", f"Unicode tag characters smuggle hidden ASCII: {tags[:120]!r}", tags[:200]
    kinds = {}
    for c in text:
        o = ord(c)
        k = INVISIBLE.get(o)
        if k is None and (0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF):
            k = "variation-selector"
        if k is None and unicodedata.category(c) == "Cf" and not (0xE0000 <= o <= 0xE007F):
            k = "format-control"
        if k:
            kinds[k] = kinds.get(k, 0) + 1
    if kinds:
        many = sum(kinds.values()) >= 4 or "bidi-control" in kinds
        desc = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
        yield ("high" if many else "medium"), f"Invisible characters in metadata ({desc})", desc


def sentences(text: str) -> list[str]:
    return [s for s in SENTENCE.split(text) if s.strip()]


def scan_text(text: str, tool_names: set[str], self_name: str, local_names: set[str] | None = None):
    """Yield (rule, severity, message, evidence) for one model-visible string."""
    for sev, msg, ev in hidden_unicode(text):
        yield "MA001", sev, msg, ev

    strong = [(m, why) for p, why in STRONG if (m := re.search(p, text, re.I))]
    medium = [(m, why) for p, why in MEDIUM if (m := re.search(p, text, re.I))]
    for m, why in strong:
        yield "MA002", "high", f"Model-directed instruction: {why}", _clip(text, m)
    if medium:
        sev = "medium" if len(medium) == 1 else "high"
        m, why = medium[0]
        extra = f" (+{len(medium) - 1} more)" if len(medium) > 1 else ""
        yield "MA002", sev, f"Model-directed instruction: {why}{extra}", _clip(text, m)

    for p, why in CONCEAL:
        if m := re.search(p, text, re.I):
            yield "MA008", "high" if strong or medium else "medium", f"Concealment: {why}", _clip(text, m)
            break

    if m := SENSITIVE.search(text):
        directive = re.search(rf"\b{DIRECTIVE}\b|\b{ACTION}\b", text, re.I)
        negated = re.search(r"\b(?:never|not|don'?t|no)\b[^.]{0,25}$", text[: m.start()], re.I)
        sev = "low" if negated else ("high" if directive else "medium")
        yield "MA003", sev, f"References sensitive path or secret: {m.group(0)}", _clip(text, m)

    m = EXFIL.search(text) or TO_ME.search(text)
    if m and (re.search(rf"\b{DIRECTIVE}\b", text, re.I) or TO_ME.search(text) or strong):
        yield "MA010", "high", "Asks the model to move user data or secrets", _clip(text, m)

    # tool shadowing: a sentence that names another tool and tells the model to act on it
    others = tool_names
    named_tool = re.compile(r"(?:['\"`])([A-Za-z][\w.\-]{2,})(?:['\"`])\s+tool\b|\btool\s+(?:['\"`])([A-Za-z][\w.\-]{2,})(?:['\"`])|"
                            r"\b(?:the|using|use|call|calling|invoke|via)\s+(?:the\s+)?(?:['\"`])?([A-Za-z]+[_\-][\w\-]+)(?:['\"`])?\s+tool\b", re.I)
    for s in sentences(text):
        refs = [n for n in dict.fromkeys(re.findall(r"[\w\-]+", s)) if n in others and n != self_name and len(n) >= 4
                and (_identifier(n) or re.search(rf"[`'\"]{re.escape(n)}[`'\"]|\b{re.escape(n)}\s+tool\b", s))]
        refs += [g for m in named_tool.finditer(s) for g in m.groups() if g and g != self_name and g not in refs]
        if not refs:
            continue
        directive = re.search(rf"\b{DIRECTIVE}\b", s, re.I)
        action = re.search(rf"\b{ACTION}\b", s, re.I)
        before = re.search(r"\b(?:before|prior to|whenever|every time|each time|when(?:ever)? (?:using|calling|invoking|the user))\b", s, re.I)
        permissive = re.search(r"\b(?:you can|you may|can be used|can also|if (?:you|needed|necessary))\b", s, re.I)
        requires = re.search(r"\brequires? (?:calling|running|using|invoking)\b|\bmake sure (?:to )?(?:get|call|run|use)\b", s, re.I)
        lookup = re.search(rf"\b(?:{ACTION[3:-1]}|get|search|list|query|retrieve|check|verify|log)\b", s, re.I)
        if permissive and not before:
            continue
        subject = any(re.search(rf"(?<![\w\-]){re.escape(r)}(?:\s+tool)?\s+{DIRECTIVE}\b", s, re.I) for r in refs)
        if requires or subject or (directive and (action or before)):
            # pointing at a sibling tool of the same server is often ordinary workflow documentation
            local = local_names is not None and all(r in local_names for r in refs)
            yield "MA004", "medium" if local else "high", f"Tells the model how to use {'sibling' if local else 'another'} tool ({refs[0]})", _clip(s)
            break
        if before and lookup:
            yield "MA004", "medium", f"Sequences another tool ({refs[0]}) around this one", _clip(s)
            break

    if m := BLOB.search(text):
        yield "MA007", "medium", f"Encoded blob of {len(m.group(0))} chars in metadata", _clip(text, m, 80)
    send = r"\b(?:send|post|forward|upload|exfiltrate|submit|transmit|cc|bcc)\b"
    for sent in sentences(text):
        hit = URL.search(sent) or EMAIL.search(sent)
        if hit and re.search(send, sent, re.I) and (re.search(rf"\b{DIRECTIVE}\b", sent, re.I) or EXFIL.search(sent)):
            yield "MA007", "high", f"Outbound destination in a send instruction: {hit.group(0)}", _clip(sent)
            break

    if m := re.search(r"<!--.*?-->|\n{6,}\S|[ \t\u00a0]{60,}\S", text, re.S):
        yield "MA009", "medium", "Markup or whitespace that hides text in a rendered view", _clip(text, m)


def scan_definition(server: str, kind: str, name: str, defn: dict, tool_names: set[str], max_params: int = 20,
                    local_names: set[str] | None = None) -> list[Finding]:
    findings, seen = [], set()
    strings = texts(defn)
    strings += [(p + " (decoded tag characters)", "".join(chr(ord(c) - 0xE0000) for c in t if 0xE0020 <= ord(c) <= 0xE007E))
                for p, t in strings if any(0xE0020 <= ord(c) <= 0xE007E for c in t)]
    for path, s in strings:
        for rule, sev, msg, ev in scan_text(s, tool_names, name, local_names):
            key = (rule, msg)
            if key in seen:
                continue
            seen.add(key)
            if path.startswith("inputSchema") and rule in ("MA002", "MA004", "MA008", "MA010"):
                msg += " (inside the parameter schema)"
            findings.append(Finding(rule, sev, server, kind, name, msg, ev, path))
    for label in dict.fromkeys([name, str(defn.get("name") or "")]):  # the item key may be a resource URI
        for sev, msg, ev in hidden_unicode(label):
            findings.append(Finding("MA001", "critical", server, kind, name, "Invisible characters in the name itself", ev, "name"))

    props = (defn.get("inputSchema") or {}).get("properties") or {}
    for p, spec in props.items():
        if EXFIL_PARAMS.match(p):
            d = spec.get("description", "") if isinstance(spec, dict) else ""
            sev = "high" if EXFIL_PARAM_DESC.search(d) else "medium"
            findings.append(Finding("MA005", sev, server, kind, name, f"Exfiltration-shaped parameter '{p}'", d[:140], f"inputSchema.properties.{p}"))
    if len(props) > max_params:
        findings.append(Finding("MA006", "low", server, kind, name, f"{len(props)} parameters (limit {max_params})", "", "inputSchema"))
    desc = defn.get("description") or ""
    if len(desc) > 4000:
        findings.append(Finding("MA006", "low", server, kind, name, f"Description is {len(desc)} chars", "", "description"))

    # two medium signals on one item usually mean an instruction, not documentation
    meds = [f for f in findings if f.severity == "medium" and f.rule != "MA006"]
    if len({f.rule for f in meds}) >= 2:
        for f in meds:
            f.severity = _bump(f.severity)
    return findings


def _confusable(name: str) -> bool:
    return any(ord(c) > 127 for c in name)


def _edit1(a: str, b: str) -> bool:
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def cross_server(servers: list[Server]) -> list[Finding]:
    out = []
    owners: dict[str, list[str]] = {}
    for s in servers:
        for t in s.tools:
            owners.setdefault(str(t.get("name", "")), []).append(s.name)
    for name, who in owners.items():
        if _confusable(name):
            for srv in who:
                out.append(Finding("MA011", "high", srv, "tool", name, "Tool name uses non-ASCII look-alike characters", name.encode("unicode_escape").decode(), "name"))
        if len(set(who)) > 1:
            for srv in who:
                out.append(Finding("MA011", "low", srv, "tool", name, f"Tool name also exposed by {', '.join(sorted(set(who) - {srv}))}", "", "name"))
    names = sorted(owners)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if len(a) >= 5 and _edit1(a, b) and set(owners[a]) != set(owners[b]):
                for srv in owners[b]:
                    out.append(Finding("MA011", "low", srv, "tool", b, f"Tool name is one edit away from '{a}' on {owners[a][0]}", "", "name"))
    return out


def scan(servers: list[Server], max_params: int = 20) -> list[Finding]:
    all_tools = {str(t.get("name", "")) for s in servers for t in s.tools}
    findings = []
    for s in servers:
        for kind, name, defn in s.items():
            findings += scan_definition(s.name, kind, name, defn, all_tools, max_params, {str(t.get("name", "")) for t in s.tools})
    findings += cross_server(servers)
    findings.sort(key=lambda f: (-sev_rank(f.severity), f.server, f.item, f.rule))
    return findings


def flagged(findings: Iterable[Finding], threshold: str = "medium") -> set[tuple[str, str]]:
    return {(f.server, f.item) for f in findings if sev_rank(f.severity) >= sev_rank(threshold)}
