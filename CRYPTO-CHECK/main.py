#!/usr/bin/env python3
"""
Crypto-Check — main.py
=====================
Auditoría defensiva SSL/TLS desde la terminal.

Uso:
    python main.py <host> [puerto]
    python main.py google.com
    python main.py example.com 8443
"""

from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from scanner import CryptoCheckAuditor
from ui import CryptoTUI

console = Console()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="crypto-check",
        description="Crypto-Check by 057 — Auditor defensivo de certificados SSL/TLS y configuración de cifrado.",
        epilog="Herramienta de auditoría Blue Team: úsala solo sobre sistemas propios o con autorización explícita.",
    )
    parser.add_argument("host", help="Hostname o IP del objetivo")
    parser.add_argument("port", nargs="?", type=int, default=443, help="Puerto TCP (defecto: 443)")
    parser.add_argument("--timeout", type=float, default=8.0, help="Timeout de red en segundos (defecto: 8)")
    return parser.parse_args(argv)


def print_error(message: str, kind: str | None = None) -> None:
    """Muestra un error controlado, sin traceback crudo."""
    body = Text(message, style="bright_red")
    if kind:
        body = Text.assemble(body, Text(f"\nTipo de fallo: {kind}", style="dim"))
    console.print(Panel(body, title="[bold bright_red] ERROR [/]", border_style="bright_red"))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    with console.status("[bright_cyan]Conectando y analizando el objetivo...", spinner="dots"):
        try:
            auditor = CryptoCheckAuditor(host=args.host, port=args.port, timeout=args.timeout)
            result = auditor.run()
        except KeyboardInterrupt:
            print_error("Auditoría interrumpida por el usuario (Ctrl+C).", "KEYBOARD")
            return 130
        except Exception as exc:  # noqa: BLE001 — última línea de defensa anti-traceback
            print_error(f"Fallo inesperado controlado: {exc}", "INTERNAL")
            return 2

    try:
        CryptoTUI(result).render()
    except Exception as exc:  # noqa: BLE001 - proteger el render ante terminales raras
        print_error(f"No se pudo dibujar la interfaz: {exc}", "TUI")
        return 2
    return 0 if not result.error else 1


if __name__ == "__main__":
    sys.exit(main())
