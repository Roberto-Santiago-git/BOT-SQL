# validator/intent_router.py
import re

CODE_HINTS = [
    r'\bCREATE\s+(TABLE|INDEX|VIEW|OR\s+REPLACE|PACKAGE|TRIGGER)\b',
    r'\bSELECT\b.*\bFROM\b',
    r'\bDECLARE\b|\bBEGIN\b|\bEXCEPTION\b',                # PL/SQL
    r'Invoke-\w+|^\s*param\(|^\s*#requires',               # PowerShell
    r'<\?xml|</\w+>',                                      # XML
    r'^\s*--\s*POLICY_BUNDLE_JSON_START',                  # IPC
    r'^\s*import\s+\w+|def\s+\w+\(',                       # Python
    r'^\s*SET\s+ANSI_NULLS|^\s*GO\b',                      # T-SQL
]

HELP_HINTS = [
    r'\b(help|ayuda|cómo usar|como uso|guía|comandos)\b',
    r'quien eres|\bwho are you\b|\bwhat can you do\b|\bqué haces\b',
    r'¿a que me puedes ayudar\??|a que me puedes ayudar\??'
]

def has_code(text: str) -> bool:
    if not text:
        return False
    fenced = re.search(r'```.+?```', text, re.S | re.I) is not None
    hints  = any(re.search(p, text, re.S | re.I | re.M) for p in CODE_HINTS)
    return fenced or hints

def detect_intent(text: str) -> str:
    if not text:
        return 'HELP'
    t = text.strip()
    if t.startswith('/'):
        cmd = t.split()[0].lower()
        if cmd in ['/help','/policy','/rules','/fix']:
            return 'HELP'
        return 'POLICY_QUERY'
    if re.search('|'.join(HELP_HINTS), t, re.I):
        return 'HELP'
    if re.search(r'\b(policy|política|regla|rule|severidad|severity|INPUT-NO-CODE)\b', t, re.I):
        return 'POLICY_QUERY'
    if has_code(t):
        return 'VALIDATE_CODE'
    return 'SMALL_TALK'
