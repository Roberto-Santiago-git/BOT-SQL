# validator/src/validator.py
import sys, json, re, pathlib, urllib.request

FLAGS = re.I | re.M | re.S

# --------- IO ---------
def _read_text(path_or_url):
    if path_or_url.startswith(("http://","https://")):
        with urllib.request.urlopen(path_or_url) as r:
            return r.read().decode("utf-8")
    return pathlib.Path(path_or_url).read_text(encoding="utf-8", errors="ignore")

def load_policy(path_or_url):
    data = json.loads(_read_text(path_or_url))
    return data, data.get("assist", {})

# --------- CONTEXTO ORACLE (no inventar) ---------
def parse_oracle_ctx(text, extractors):
    ctx = {"schema":"<SCHEMA>", "table":"<TABLE>", "columns":[]}
    ct_pat = extractors["oracle"].get("create_table","")
    if ct_pat:
        ct = re.search(ct_pat, text, FLAGS)
        if ct:
            schema, table, cols_block = ct.group(1), ct.group(2), ct.group(3)
            if schema: ctx["schema"] = schema
            if table:  ctx["table"]  = table
            col_pat = extractors["oracle"].get("column_def","")
            if col_pat:
                cols = re.findall(col_pat, cols_block, FLAGS)
                ctx["columns"] = [c[0] for c in cols]
    # clave de partición (para ORC-PART-NAME)
    pk_pat = extractors["oracle"].get("partition_key","")
    if pk_pat:
        pk = re.search(pk_pat, text, FLAGS)
        if pk:
            ctx["partcol"] = pk.group(1)
    return ctx

def binding_from_ctx(rule_id, ctx, assist):
    b = {}
    if rule_id == "ORC-SELECT-NO-STAR":
        b["table"] = ctx.get("table","<TABLE>")
        b["columns_or_placeholder"] = ", ".join(ctx["columns"]) if ctx.get("columns") else "<col1, col2, ...>"
    elif rule_id == "ORC-PK-EXISTS":
        b["schema"] = ctx.get("schema","<SCHEMA>")
        b["table"]  = ctx.get("table","<TABLE>")
        b["pk_cols"] = "<PK_COL1, PK_COL2, ...>"
    elif rule_id == "ORC-TABLE-OPTIONS":
        tbs = (((assist.get("defaults") or {}).get("oracle") or {}).get("tablespace")) or "<TABLESPACE>"
        b["tablespace"] = tbs
    elif rule_id == "ORC-IDX-NAME":
        b["table"] = ctx.get("table","<TABLE>")
        b["firstcol"] = ctx["columns"][0] if ctx.get("columns") else "<COL>"
    elif rule_id == "ORC-PART-NAME":
        b["partcol"] = ctx.get("partcol","<COL>")
        b["suffix"]  = "<SUFFIX>"
    return b

# --------- FIX RENDER ---------
def render_fix(rule, text, ctx, assist, first_match):
    fx = rule.get("fix") or {}
    if not fx: return None
    bind = binding_from_ctx(rule["id"], ctx, assist)

    # caso especial: usar token incumplido como sufijo en particiones
    if rule["id"] == "ORC-PART-NAME" and first_match:
        offending = first_match.group(1)
        if re.fullmatch(r"[A-Za-z0-9_]{1,30}", offending):
            bind["suffix"] = offending

    tpl = fx.get("template","")
    # sustituye ${var}
    for k, v in bind.items():
        tpl = tpl.replace("${"+k+"}", v)

    # soporta ${g1}... usando el locator
    loc = fx.get("locator")
    if loc:
        m = re.search(loc, text, FLAGS)
        if m:
            for i in range(1, m.lastindex+1 if m.lastindex else 1):
                tpl = tpl.replace("${g"+str(i)+"}", m.group(i))
            # ${block} si existe
            tpl = tpl.replace("${block}", m.group(1) if m.lastindex and m.group(1) else "${block}")
    return tpl.strip() if tpl else None

# --------- VALIDACIÓN ---------
def eval_rules(text, ns, ctx, assist):
    violations = []
    for r in ns.get("rules", []):
        pat = re.compile(r.get("pattern",""), FLAGS)
        must = r.get("must_match", False)
        invert = r.get("invert", False)
        m = pat.search(text)
        hit = bool(m)
        if invert: hit = not hit
        violated = (not hit) if must else hit
        if violated:
            fix = render_fix(r, text, ctx, assist, m)
            violations.append({
                "id": r["id"], "desc": r["desc"], "severity": r.get("severity","warn"),
                "cite": r.get("cite"), "quote": r.get("quote"), "fix": fix
            })
    return violations

def main():
    if len(sys.argv) < 3:
        print("Veredicto: NO CUMPLE"); print("Falta policy_ip.(json|txt) en Conocimiento"); sys.exit(1)

    policy_path, target = sys.argv[1], sys.argv[2]
    text = _read_text(target)
    policy, assist = load_policy(policy_path)

    # contexto por lenguaje (solo Oracle aquí)
    ctx = parse_oracle_ctx(text, assist.get("extractors", {}))

    all_viol = []
    for ns in policy.get("namespaces", []):
        all_viol += eval_rules(text, ns, ctx, assist)

    prefix = policy.get("output", {}).get("prefix", "Veredicto: ")
    if all_viol:
        print(prefix + "NO CUMPLE")
        for v in all_viol:
            print(f"- [{v['severity']}] {v['id']}: {v['desc']}")
            if v.get("quote"):  print(f"  Cita: {v['quote']}")
            if v.get("cite"):   print(f"  Fuente: {v['cite']}")
            if v.get("fix"):    print("  Sentencia corregida:\n  " + v["fix"].replace("\n", "\n  "))
        sys.exit(2)
    else:
        print(prefix + "CUMPLE"); sys.exit(0)

if __name__ == "__main__":
    main()
