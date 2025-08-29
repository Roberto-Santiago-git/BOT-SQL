# bot_main.py
import argparse
from validator_integration import handle_mensaje

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", help="SQL en texto")
    ap.add_argument("--file", help="Ruta a archivo SQL")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
        print(handle_mensaje(adjunto_bytes=data, adjunto_nombre=args.file))
    else:
        print(handle_mensaje(usuario_texto=args.text or ""))
