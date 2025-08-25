# validator.py  (evalúa todos los namespaces)
import sys, json, re, pathlib, urllib.request, os
from pathlib import Path
import fnmatch

FLAGS = re.I | re.M | re.S

# -------- util: limpiar flags inline (?i)(?s)(?x) --------
def _strip_inline_flags(pat: str):
    if not pat:
        return "", 0
    mapping = {'i': re.I, 'm': re.M, 's': re.S, 'x': re.X, 'a': re.A, 'l': re.L, 'u': 0, 'U': 0, 't': 0}
    acc = 0
    def repl_scoped(m):
        nonlocal acc
        for ch in set(m.group(1)):
            acc |= mapping.get(ch.lower(), 0)
        return "(?:"
    pat = re.sub(r"\(\?([imxsaluULT]+):", repl_scoped, pat)
    def repl_global(m):
        nonlocal acc
        for ch in set(m.group(1)):
            acc |= mapping.get(ch.lower(), 0)
        return ""
    pat = re.sub(r"\(\?([imxsaluULT]+)\)", repl_global, pat)
    return pat, acc

def _compile_pat(pat: str, base_flags: int = FLAGS):
    src, add = _strip_inline_flags(pat or "")
    return re.compile(src, base_flags | add)

# ---------------- Heurísticas ----------------
SQL_TOKENS = r"\b(CREATE|ALTER|COMMENT|GRANT|REVOKE|DROP|SELECT|INSERT|UPDATE|DELETE)\b|\bPARTITION\s+BY\b"
IPC_TOKENS = r"^\s*\[Global\]\b|\$\$PM_|\$\$PW_"
PS_TOKENS  = r"^\s*(Clear-Host|param\(|Write-Output|Get-ChildItem|Set-Content)\b"
XML_TOKENS = r"<\?xml|<partition\s+name="

def looks_like_code(text: str) -> bool:
    return any(re.search(p, text or "", FLAGS) for p in (SQL_TOKENS, IPC_TOKENS, PS_TOKENS, XML_TOKENS))

def guess_inline_name(text: str) -> str:
    if re.search(XML_TOKENS, text or "", FLAGS): return "inline.xml"
    if re.search(PS_TOKENS,  text or "", FLAGS): return "inline.ps1"
    if re.search(IPC_TOKENS, text or "", FLAGS): return "inline.prm"
    return "inline.sql"

# ---------------- IO ----------------
def _read_text(path_or_url: str):
    if isinstance(path_or_url, str) and path_or_url.startswith(("http://", "https://")):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read().decode("utf-8", errors="ignore")
    p = pathlib.Path(path_or_url or "")
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore")
    if looks_like_code(path_or_url or ""):
        return path_or_url
    if path_or_url == "-":
        data = sys.stdin.read()
        if data:
            return data
    return None

def load_policy(path_or_url):
    data = json.loads(_read_text(path_or_url))
    return data, data.get("assist", {})

# ---------------- Contexto ORACLE ----------------
def parse_oracle_ctx(text: str, extractors: dict):
    ctx = {"schema": "<SCHEMA>", "table": "<TABLE>", "columns": []}
    oracle_ext = (extractors or {}).get("oracle", {}) if extractors else {}

    ct_pat = oracle_ext.get("create_table", "")
    if ct_pat:
        try:
            ct = _compile_pat(ct_pat).search(text or "")
        except re.error:
            ct = None
        if ct:
            schema, table, cols_block = ct.group(1), ct.group(2), ct.group(3)
            if schema: ctx["schema"] = schema
            if table:  ctx["table"]  = table
            col_pat = oracle_ext.get("column_def", "")
            if col_pat:
                try:
                    cols = _compile_pat(col_pat).findall(cols_block or "")
                except re.error:
                    cols = []
                ctx["columns"] = [c[0] if isinstance(c, tuple) else c for c in cols]

    pk_pat = oracle_ext.get("partition_key", "")
    if pk_pat:
        try:
            pk = _compile_pat(pk_pat).search(text or "")
        except re.error:
            pk = None
        if pk:
            ctx["partcol"] = pk.group(1)
    return ctx

# ---------------- Bindings para fixes ----------------
def binding_from_ctx(rule_id: str, ctx: dict, assist: dict):
    b = {}
    if rule_id == "ORC-SELECT-NO-STAR":
        b["table"] = ctx.get("table", "<TABLE>")
        b["columns_or_placeholder"] = ", ".join(ctx["columns"]) if ctx.get("columns") else "<col1, col2, ...>"
    elif rule_id == "ORC-PK-EXISTS":
        b["schema"] = ctx.get("schema", "<SCHEMA>")
        b["table"]  = ctx.get("table", "<TABLE>")
        b["pk_cols"] = "<PK_COL1, PK_COL2, ...>"
    elif rule_id == "ORC-TABLE-OPTIONS":
        tbs = (((assist.get("defaults") or {}).get("oracle") or {}).get("tablespace")) or "<TABLESPACE>"
        b["tablespace"] = tbs
    elif rule_id == "ORC-IDX-NAME":
        b["table"] = ctx.get("table", "<TABLE>")
        b["firstcol"] = ctx["columns"][0] if ctx.get("columns") else "<COL>"
    elif rule_id in ("ORC-PART-NAME", "XML-PART-NAME"):
        b["partcol"] = ctx.get("partcol", "<COL>")
        b["suffix"]  = "<SUFFIX>"
    elif rule_id == "ORC-GRANT-FQN":
        b["schema"]  = ctx.get("schema", "<SCHEMA>")
    return b

# ---------------- Render de fixes ----------------
def _sub_template_vars(tpl: str, bind: dict) -> str:
    out = tpl
    for k, v in bind.items():
        out = out.replace("${" + k + "}", v)
    return out

def render_fix(rule: dict, text: str, ctx: dict, assist: dict, first_match: re.Match | None):
    fx = rule.get("fix") or {}
    if not fx:
        return None
    bind = binding_from_ctx(rule.get("id",""), ctx, assist)
    if rule.get("id") in ("ORC-PART-NAME", "XML-PART-NAME") and first_match:
        offending = first_match.group(1)
        if offending and re.fullmatch(r"[A-Za-z0-9_]{1,30}", offending):
            bind["suffix"] = offending
    tpl = _sub_template_vars(fx.get("template", ""), bind)
    loc = fx.get("locator")
    if loc:
        m = _compile_pat(loc).search(text or "")
        if m:
            last = m.lastindex or 0
            for i in range(1, last + 1):
                gi = m.group(i)
                tpl = tpl.replace("${g" + str(i) + "}", gi if gi is not None else "")
            if last >= 1 and m.group(1) is not None:
                tpl = tpl.replace("${block}", m.group(1))
    return tpl.strip() if tpl else None

# ---------------- Evaluación de reglas ----------------
def eval_rules(text: str, ns: dict, ctx: dict, assist: dict):
    violations = []
    for r in ns.get("rules", []):
        try:
            flag_map = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A, "l": re.L, "u": 0}
            pat_src = r.get("pattern", "") or ""
            pat_src, inline_flags = _strip_inline_flags(pat_src)
            rflags = FLAGS | inline_flags
            for ch in (r.get("flags", "") or "").lower():
                rflags |= flag_map.get(ch, 0)
            pat = re.compile(pat_src, rflags)
        except re.error as e:
            print("Veredicto: NO CUMPLE")
            rid = r.get("id", "<sin-id>")
            print(f"- [error] BAD-PATTERN {rid}: {e}")
            print("  patrón:", pat_src)
            sys.exit(2)

        must = r.get("must_match", False)
        invert = r.get("invert", False)
        fx = r.get("fix", {}) or {}
        apply_global = (fx.get("apply") == "global") or (fx.get("multiple") is True)

        matches = list(pat.finditer(text or "")) if apply_global else [pat.search(text or "")]
        has_hit = any(bool(m) for m in matches if m)

        hit = has_hit
        if invert:
            hit = not hit
        violated = (not hit) if must else hit
        if not violated:
            continue

        if apply_global and matches:
            for m in matches:
                if not m:
                    continue
                fix = render_fix(r, text, ctx, assist, m)
                violations.append({
                    "id": r.get("id"),
                    "desc": r.get("desc"),
                    "severity": r.get("severity", "warn"),
                    "cite": r.get("cite"),
                    "quote": r.get("quote"),
                    "fix": fix
                })
        else:
            m = matches[0] if matches else None
            fix = render_fix(r, text, ctx, assist, m)
            violations.append({
                "id": r.get("id"),
                "desc": r.get("desc"),
                "severity": r.get("severity", "warn"),
                "cite": r.get("cite"),
                "quote": r.get("quote"),
                "fix": fix
            })
    return violations

# ---------------- MAIN ----------------
def main():
    if len(sys.argv) < 3:
        print("Veredicto: NO CUMPLE")
        print("- [error] INPUT-NO-CODE: Proporciona el artefacto en ```...``` o adjunta archivo.")
        sys.exit(1)

    policy_path, target = sys.argv[1], sys.argv[2]
    policy, assist = load_policy(policy_path)

    text = _read_text(target)
    if text is None or not text.strip():
        print("Veredicto: NO CUMPLE")
        print("- [error] INPUT-NO-CODE: Proporciona el artefacto en ```...``` o adjunta archivo.")
        sys.exit(2)

    if pathlib.Path(target).exists():
        name = os.path.basename(target)
    elif isinstance(target, str) and target.startswith(("http://", "https://")):
        name = os.path.basename(target.split("?")[0])
    else:
        name = guess_inline_name(text)  # p.ej. inline.sql

    ctx = parse_oracle_ctx(text, assist.get("extractors", {}))

    # Evalúa TODOS los namespaces; si no hay, usa reglas de raíz
    namespaces = policy.get("namespaces")
    if not namespaces:
        namespaces = [{"applies_to": ["*"], "rules": policy.get("rules", [])}]

    selected = [ns for ns in namespaces if ns.get("rules")]
    all_viol = []
    for ns in selected:
        all_viol.extend(eval_rules(text, ns, ctx, assist))

    prefix = policy.get("output", {}).get("prefix", "Veredicto: ")
    if all_viol:
        print(prefix + "NO CUMPLE")
        for v in all_viol:
            print(f"- [{v['severity']}] {v['id']}: {v['desc']}")
            if v.get("quote"):
                print(f"  Cita: {v['quote']}")
            if v.get("cite"):
                print(f"  Fuente: {v['cite']}")
            if v.get("fix"):
                print("  Recomendación (sentencia corregida):")
                print("  " + (v["fix"] or "").replace("\n", "\n  "))
        sys.exit(2)
    else:
        print(prefix + "CUMPLE")
        print("Listo. Ahora puedes validar en producción.")
        sys.exit(0)

if __name__ == "__main__":
    main()

