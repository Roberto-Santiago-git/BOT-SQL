# validator_integration.py
import os
import glob
import subprocess
import re

# No mostrar bloques de "Script corregido..."
ALLOW_AUTOFIX = False

# Ocultar hallazgos por rule-id (ajusta según necesites)
DROP_RULES = {
    "CPPGS-SCHEMA",
    "CPPGS-OWNER",
    "SCHEMA-USE-DEV",
}

# Rutas (puedes sobreescribir con variables de entorno)
POLICY_PATH = os.getenv("POLICY_PATH", "policies/policy_oracle.json")
VALIDATOR_SCRIPT = os.getenv("VALIDATOR_SCRIPT", "validator/src/validator.py")


def _strip_autofix(text: str) -> str:
    """Elimina el bloque 'Script corregido ...' del final de la salida."""
    if ALLOW_AUTOFIX:
        return text
    return re.sub(r"(?is)\n*Script\s+corregido.*\Z", "", text).strip()


def _filter_rule_blocks(text: str) -> str:
    """Oculta hallazgos cuyos rule-id estén en DROP_RULES.
       Soporta:
         - 'Regla: <RULE>'
         - '[error] <RULE>:' / '[warn] <RULE>:'
       También quita una línea inmediata que empiece con 'Cita:' tras un hallazgo filtrado.
    """
    if not DROP_RULES:
        return text

    lines = text.splitlines()
    keep = []
    skip_next_cita = False

    for ln in lines:
        # si la línea siguiente a un hallazgo filtrado es 'Cita:', saltarla
        if skip_next_cita and ln.strip().lower().startswith(("cita:", "cita :")):
            skip_next_cita = False
            continue
        skip_next_cita = False

        rule = None
        m1 = re.search(r"Regla:\s*([A-Z0-9_\-:]+)", ln)
        if m1:
            rule = m1.group(1)
        else:
            m2 = re.search(r"\[(?:error|warn)\]\s*([A-Z0-9_\-:]+)\s*:", ln, flags=re.I)
            if m2:
                rule = m2.group(1)

        if rule and rule in DROP_RULES:
            skip_next_cita = True
            continue

        keep.append(ln)

    return "\n".join(keep).strip()


def _run_validator(files, policy_path: str | None = None) -> str:
    policy = policy_path or POLICY_PATH

    if not os.path.isfile(policy):
        return f"⚠️ Policy no encontrada: {policy}"
    if not os.path.isfile(VALIDATOR_SCRIPT):
        return f"⚠️ Script de validador no encontrado: {VALIDATOR_SCRIPT}"

    cmd = ["python", "-u", VALIDATOR_SCRIPT, policy, *files]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False)
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        out = _strip_autofix(out)
        out = _filter_rule_blocks(out)
        return out.strip() or "(sin salida)"
    except Exception as e:
        return f"❌ Error ejecutando validador: {e}"


def validate_sql_locally(policy_path: str | None = None) -> str:
    """Ejecuta el validador contra todos los .sql/.pkb/.pks/.pls/.txt versionados."""
    files = [
        f for f in glob.glob("**/*", recursive=True)
        if f.lower().endswith((".sql", ".pkb", ".pks", ".pls", ".txt"))
    ]
    if not files:
        return "No hay archivos a validar."
    return _run_validator(files, policy_path)


def handle_message(_message_text: str = "") -> str:
    """Puerta para que tu bot invoque la validación."""
    return validate_sql_locally()
