import sys, json, re, pathlib, urllib.request, os, fnmatch

FLAGS = re.I | re.M | re.S

# ---------- Heurísticas sin fences ----------
SQL_TOKENS = r"(?is)\b(CREATE|ALTER|COMMENT|GRANT|REVOKE|DROP|SELECT|INSERT|UPDATE|DELETE)\b|(?is)\bPARTITION\s+BY\b"
IPC_TOKENS = r"(?im)^\s*\[Global\]\b|(?s)\$\$PM_|(?s)\$\$PW_"
PS_TOKENS  = r"(?im)^\s*(Clear-Host|param\(|Write-Output|Get-ChildItem|Set-Content)\b"
XML_TOKENS = r"(?is)<\?xml|<partition\s+name="

def looks_like_code(text):
    return any(re.search(p, text) for p in (SQL_TOKENS, IPC_TOKENS, PS_TOKENS, XML_TOKENS))

def guess_inline_name(text):
    if re.search(XML_TOKENS, text): return "inline.xml"
    if re.search(PS_TOKENS,  text): return "inline.ps1"
    if re.search(IPC_TOKENS, text): return "inline.prm"
    return "inline.sql"

# ---------- IO ----------
def _read_text(path_or_url):
    if path_or_url.startswith(("http://", "https://")):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read().decode("utf-8")
    p = pathlib.Path(path_or_url)
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore")
    if looks_like_code(path_or_url):
        return path_or_url
    if path_or_url == "-":
        data = sys.stdin.read()
        if data:
            return data
    return None

def load_policy(path_or_url):
    data = json.loads(_read_text(path_or_url))
    return data, data.get("assist", {})

# ---------- CONTEXTO ORACLE ----------
def parse_oracle_ctx(text, extractors):
    ctx = {"schema": "<SCHEMA>", "table": "<TABLE>", "columns": []}
    oracle_ext = (extractors or {}).get("oracle", {}) if extractors else {}

    ct_pat = oracle_ext.get("create_table", "")
    if ct_pat:
        ct = re.search(ct_pat, text or "", FLAGS)
        if ct:
            schema, table, cols_block = ct.group(1), ct.group(2), ct.group(3)
            if schema: ctx["schema"] = schema
            if table:  ctx["table"]  = table
            col_pat = oracle_ext.get("column_def", "")
            if col_pat:
                cols = re.findall(col_pat, cols_block or "", FLAGS)
                ctx["columns"] = [c[0] for c in cols]

    pk_pat = oracle_ext.get("partition_key", "")
    if pk_pat:
        pk = re.search(pk_pat, text or "", FLAGS)
        if pk:
            ctx["partcol"] = pk.group(1)
    return ctx

# ---------- BINDINGS ----------
def binding_from_ctx(rule_id, ctx, assist):
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

# ---------- RENDER DEL FIX ----------
def _sub_template_vars(tpl, bind):
    out = tpl
    for k, v in bind.items():
        out = out.replace("${" + k + "}", v)
    return out

def render_fix(rule, text, ctx, assist, first_match):
    fx = rule.get("fix") or {}
    if not fx:
        return None

    bind = binding_from_ctx(rule["id"], ctx, assist)

    # particiones: usa token incumplido como sufijo
    if rule["id"] in ("ORC-PART-NAME", "XML-PART-NAME") and first_match:
        offending = first_match.group(1)
        if re.fullmatch(r"[A-Za-z0-9_]{1,30}", offending):
            bind["suffix"] = offending

    tpl = fx.get("template", "")
    tpl = _sub_template_vars(tpl, bind)

    loc = fx.get("locator")
    if loc:
        m = re.search(loc, text or "", FLAGS)
        if m:
            last = m.lastindex or 0
            for i in range(1, last + 1):
                tpl = tpl.replace("${g" + str(i) + "}", m.group(i))
            if last >= 1 and m.group(1) is not None:
                tpl = tpl.replace("${block}", m.group(1))
    return tpl.strip() if tpl else None

# ---------- APLICACIÓN DE FIXES ----------
def apply_rule(text, rule, ctx, assist, mode_all=False):
    fx = rule.get("fix") or {}
    if not fx:
        return text, 0
    if not (mode_all or rule.get("autofix_safe") is True):
        return text, 0

    loc = fx.get("locator")
    if not loc:
        return text, 0
    pat = re.compile(loc, FLAGS)

    def _sub(m):
        rep = render_fix(rule, text, ctx, assist, m)
        return rep if rep is not None else m.group(0)

    rtype = fx.get("type")
    count = 0
    if rtype in ("replace", "replace_token", "ensure_clause", "insert_after", "insert_before"):
        new_text, count = pat.subn(_sub, text)
        return new_text, count
    # tipos no aplicables (rename_suggest, etc.)
    return text, 0

def apply_all(text, policy, ctx, assist, mode_all=False):
    total = 0
    changed = True
    # iterar hasta estabilizar por si un fix habilita otro
    while changed:
        changed = False
        for ns in policy.get("namespaces", []):
            new_text = text
            for r in ns.get("rules", []):
                new_text, cnt = apply_rule(new_text, r, ctx, assist, mode_all=mode_all)
                if cnt:
                    total += cnt
                    changed = True
            text = new_text
    return text, total

# ---------- EVALUACIÓN ----------
def eval_rules(text, ns, ctx, assist):
    violations = []
    for r in ns.get("rules", []):
        pat = re.compile(r.get("pattern", ""), FLAGS)
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
                    "id": r["id"],
                    "desc": r["desc"],
                    "severity": r.get("severity", "warn"),
                    "cite": r.get("cite"),
                    "quote": r.get("quote"),
                    "fix": fix
                })
        else:
            m = matches[0] if matches else None
            fix = render_fix(r, text, ctx, assist, m)
            violations.append({
                "id": r["id"],
                "desc": r["desc"],
                "severity": r.get("severity", "warn"),
                "cite": r.get("cite"),
                "quote": r.get("quote"),
                "fix": fix
            })
    return violations

# ---------- MAIN ----------
def main():
    if len(sys.argv) < 3:
        print("Veredicto: NO CUMPLE")
        print("- [error] INPUT-NO-CODE: Proporciona el artefacto en ```...``` o adjunta archivo.")
        sys.exit(1)

    policy_path, target = sys.argv[1], sys.argv[2]
    mode = "validate"
    mode_all = False
    if len(sys.argv) >= 4:
        if sys.argv[3] in ("--apply", "--apply=safe"):
            mode = "apply"
        elif sys.argv[3] == "--apply=all":
            mode = "apply"; mode_all = True

    text = _read_text(target)
    if text is None:
        print("Veredicto: NO CUMPLE")
        print("- [error] INPUT-NO-CODE: Proporciona el artefacto en ```...``` o adjunta archivo.")
        sys.exit(2)

    policy, assist = load_policy(policy_path)

    # nombre/applies_to
    if pathlib.Path(target).exists():
        name = os.path.basename(target)
    elif target.startswith(("http://", "https://")):
        name = os.path.basename(target.split("?")[0])
    else:
        name = guess_inline_name(text)

    # contexto
    ctx = parse_oracle_ctx(text, assist.get("extractors", {}))

    # aplica fixes opcionalmente
    if mode == "apply":
        new_text, total = apply_all(text, policy, ctx, assist, mode_all=mode_all)
        if total > 0:
            text = new_text  # revalidar sobre el texto ajustado

    # eval
    all_viol = []
    for ns in policy.get("namespaces", []):
        pats = ns.get("applies_to")
        if pats and not any(fnmatch.fnmatch(name, pat) for pat in pats):
            continue
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
                print("  Sentencia corregida:")
                print("  " + v["fix"].replace("\n", "\n  "))
        sys.exit(2)
    else:
        print(prefix + "CUMPLE")
        print("Listo. Ahora puedes validar en producción.")
        sys.exit(0)

if __name__ == "__main__":
    main()
