# validator/templates.py
TEMPLATE_HELP = """Veredicto: SIN-ANÁLISIS
Soy Validator CyGD. Valido SQL/PLSQL Oracle, SQL Server, PostgreSQL, PowerShell, XML e IPC.
Cómo usar:
1) Sube .sql/.pkb/.pks/.xml/.ps1 o pega código entre ```.
2) Opcional: engine/versión/tablespace/esquema destino.
3) Pide: /fix, /explain RULE_ID, /policy.

Ejemplo:
```sql
CREATE INDEX X ON T(A) TABLESPACE TBS_DESP_01_IDX;
```"""

TEMPLATE_WHOAMI = """Veredicto: SIN-ANÁLISIS
Soy Validator CyGD. Escaneo estático, aplico tus policies y regreso veredicto, razones y parches sugeridos."""

TEMPLATE_NO_CODE = """Veredicto: SIN-ANÁLISIS
No detecté código ni archivo. Sube .sql/.pkb/.ps1/.xml o pega entre ```.
Ejemplo:
```sql
CREATE TABLE T(...);
```"""

TEMPLATE_POLICY_QUERY = """Veredicto: SIN-ANÁLISIS
Puedo listar reglas y severidades o generar un JSON base para actualizar la policy. Indica la regla o bloque (/policy o /rules)."""

def render_template(intent: str) -> str:
    if intent == 'HELP':
        return TEMPLATE_HELP
    if intent == 'POLICY_QUERY':
        return TEMPLATE_POLICY_QUERY
    return TEMPLATE_WHOAMI
