#!/usr/bin/env python3
# validator.py — reporte de estándares Oracle (solo reporta, sin corregir código)

import sys, os, re, json, pathlib
from typing import List, Dict, Any

# ---------- Utilidades de E/S ----------
def read_text_utf8_nobom(path: str) -> str:
    # Tolera BOM si existe
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read()

def file_exists(path: str) -> bool:
    try:
        return pathlib.Path(path).exists()
    except Exception:
        return False

def line_no(text: str, idx: int) -> int:
    return text.count("\n", 0, max(0, idx)) + 1

# ---------- Carga de policy ----------
def load_policy(policy_path: str) -> Dict[str, Any]:
    data = json.loads(read_text_utf8_nobom(policy_path))
    return data

# ---------- Reglas base ----------
def check_insert_columns(text: str, require: bool) -> List[Dict[str, Any]]:
    issues = []
    if not require:
        return issues

    # Encuentra "INSERT INTO <objeto>" y valida que el próximo token no-espacio sea "("
    ins_iter = re.finditer(r"\binsert\s+into\s+([\"A-Z0-9_.]+)", text, flags=re.I)
    for m in ins_iter:
        start = m.end()  # posición después del nombre del objeto
        j = start
        # salta espacios y saltos de línea
        while j < len(text) and text[j] in (" ", "\t", "\r", "\n"):
            j += 1
        has_paren = (j < len(text) and text[j] == "(")
        if not has_paren:
            # ubicación desde "INSERT" hasta el fin de línea o hasta "VALUES"/"SELECT"
            ln1 = line_no(text, m.start())
            ln2 = ln1
            # intenta extender hasta VALUES/SELECT más cercano
            tail = text[m.start(): m.start() + 400]
            mv = re.search(r"\b(values|select)\b", tail, flags=re.I)
            if mv:
                ln2 = line_no(text, m.start() + mv.end())
            issues.append({
                "code": "INSERT-COLS",
                "desc": "INSERT debe declarar columnas destino",
                "ls": ln1, "le": ln2
            })
    return issues

def check_exception_prefix(text: str, prefix: str) -> List[Dict[str, Any]]:
    issues = []
    if not prefix:
        return issues
    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]*)\s+EXCEPTION\s*;", text, flags=re.M):
        name = m.group(1)
        if not name.startswith(prefix):
            issues.append({
                "code": "EXC-PREFIX",
                "desc": f"Excepciones deben iniciar con {prefix}",
                "ls": line_no(text, m.start()), "le": line_no(text, m.start())
            })
    return issues

def check_select_star(text: str, forbid: bool) -> List[Dict[str, Any]]:
    issues = []
    if not forbid:
        return issues
    for m in re.finditer(r"\bselect\s*\*\s*from\b", text, flags=re.I):
        ln = line_no(text, m.start())
        issues.append({
            "code": "SELECT-STAR",
            "desc": "Evitar SELECT *; lista columnas explícitas",
            "ls": ln, "le": ln
        })
    return issues

def check_forbidden_keywords(text: str, keywords: List[str]) -> List[Dict[str, Any]]:
    issues = []
    for kw in (keywords or []):
        kw_pat = r"\b" + re.escape(kw.strip()) + r"\b"
        for m in re.finditer(kw_pat, text, flags=re.I):
            ln = line_no(text, m.start())
            issues.append({
                "code": "KW-FORBIDDEN",
                "desc": f"Keyword prohibido: {kw.strip()}",
                "ls": ln, "le": ln
            })
    return issues

def check_bitacora(text: str, cfg: Dict[str, str]) -> List[Dict[str, Any]]:
    issues = []
    if not cfg:
        return issues
    reqs = [
        ("BITACORA", cfg.get("start", "")),
        ("BITACORA", cfg.get("finish_ok", "")),
        ("BITACORA", cfg.get("finish_err", "")),
    ]
    for code, needle in reqs:
        if not needle:
            continue
        if re.search(re.escape(needle), text, flags=re.I) is None:
            issues.append({
                "code": code,
                "desc": f"Falta llamada requerida: {needle}",
                "ls": 1, "le": 1
            })
    return issues

# ---------- Reporte ----------
def emit_report(all_issues: Dict[str, List[Dict[str, Any]]], policy: Dict[str, Any]) -> int:
    total = sum(len(v) for v in all_issues.values())
    prefix = (policy.get("output") or {}).get("prefix", "Veredicto: ")
    if total == 0:
        print(prefix + "CUMPLE")
        return 0

    print(f"{prefix}NO CUMPLE [{total} hallazgos]")

    doc_refs = policy.get("doc_refs", {})
    notes = policy.get("remediation_notes", {})

    for fname, items in all_issues.items():
        print(f"\n[{fname}]")
        for it in items:
            rng = f"L{it['ls']}" + (f"–{it['le']}" if it['le'] != it['ls'] else "")
            print(f"- Ubicación: {rng}")
            print(f"  Regla: {it['code']} — {it['desc']}")
            ref = doc_refs.get(it["code"]) or doc_refs.get(it["code"].split(":")[0], {})
            if ref:
                page = ref.get("page")
                section = ref.get("section")
                if page or section:
                    print(f"  Sustento: Estándares Oracle, p.{page} (\"{section}\")")
            note = notes.get(it["code"]) or notes.get(it["code"].split(":")[0], "")
            if note:
                print(f"  Cómo corregir: {note}")
    return 1

# ---------- MAIN ----------
def main():
    if len(sys.argv) < 3:
        print("Veredicto: NO CUMPLE")
        print("- [error] Uso: validator.py <policy.json> <archivo1.sql> [archivo2.sql ...]")
        sys.exit(2)

    policy_path = sys.argv[1]
    targets = sys.argv[2:]

    if not file_exists(policy_path):
        print("Veredicto: NO CUMPLE")
        print(f"- [error] Policy no encontrada: {policy_path}")
        sys.exit(2)

    try:
        policy = load_policy(policy_path)
    except Exception as e:
        print("Veredicto: NO CUMPLE")
        print(f"- [error] Policy inválida: {e}")
        sys.exit(2)

    all_issues: Dict[str, List[Dict[str, Any]]] = {}

    for target in targets:
        if not file_exists(target):
            print(f"- [warn] archivo no encontrado: {target}")
            continue
        try:
            text = read_text_utf8_nobom(target)
        except Exception as e:
            print(f"- [warn] no se pudo leer {target}: {e}")
            continue

        issues: List[Dict[str, Any]] = []

        # Reglas desde policy
        issues += check_insert_columns(text, policy.get("require_insert_column_list", False))
        issues += check_exception_prefix(text, policy.get("require_exception_prefix", ""))

        if policy.get("forbid_select_star", False):
            issues += check_select_star(text, True)

        fk = policy.get("forbid_keywords") or []
        if fk:
            issues += check_forbidden_keywords(text, fk)

        issues += check_bitacora(text, policy.get("require_bitacora_calls", {}))

        if issues:
            all_issues[os.path.basename(target)] = issues

    exit_code = emit_report(all_issues, policy)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

