"""
Crypto-Check — ui.py
===================
Renderizado de la interfaz de texto (TUI) con Rich.

Clase principal: :class:`CryptoTUI`. Recibe un :class:`AuditResult` del scanner
y pinta el panel completo: objetivo, certificado, cifrado/cabeceras y score.
"""

from __future__ import annotations

from io import StringIO

from rich.align import Align
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.rule import Rule
from rich.style import Style
from rich.table import Table
from rich.text import Text

from scanner import AuditResult, CertificateInfo, HeaderInfo, TLSInfo

# --------------------------------------------------------------------------
# Banner ASCII (fuente estilo figlet 'standard', 68 columnas — cabe en 80)
# --------------------------------------------------------------------------

BANNER = r"""
  ____ ______   ______ _____ ___         ____ _   _ _____ ____ _  __
 / ___|  _ \ \ / /  _ \_   _/ _ \       / ___| | | | ____/ ___| |/ /
| |   | |_) \ V /| |_) || || | | |_____| |   | |_| |  _|| |   | ' /
| |___|  _ < | | |  __/ | || |_| |_____| |___|  _  | |__| |___| . \
 \____|_| \_\|_| |_|    |_| \___/       \____|_| |_|_____\____|_|\_\
"""

SUBTITLE = "b y   0 5 7   —   T L S / S S L   S e c u r i t y   A u d i t o r"

GREEN = "bright_green"
YELLOW = "bright_yellow"
RED = "bright_red"
DIM = "dim"
CYAN = "bright_cyan"

# Umbral de días para colores de expiración
WARN_DAYS = 30
CRIT_DAYS = 7


# --------------------------------------------------------------------------
# TUI
# --------------------------------------------------------------------------


class CryptoTUI:
    """Renderiza la auditoría completa en un layout de cuadrícula Rich."""

    def __init__(self, result: AuditResult) -> None:
        self.result = result
        self.console = Console()

    # ------------------------------------------------------------------
    # Punto de entrada
    # ------------------------------------------------------------------

    def render(self) -> None:
        """Pinta el dashboard completo, adaptando las alturas al contenido."""
        r = self.result
        width = self.console.width

        # --- Renderables base -------------------------------------------------
        banner_panel = self._banner_panel()
        target_panel = self._target_panel()
        score_panel = self._score_panel()

        h_banner = self._measure(banner_panel, width)
        h_target = self._measure(target_panel, width)
        h_score = self._measure(score_panel, width)

        # --- Caso de error fatal: sin paneles de datos -------------------------
        if r.error:
            layout = Layout()
            layout.split_column(
                Layout(name="header", size=h_banner),
                Layout(name="target", size=h_target),
                Layout(name="footer", size=h_score),
            )
            layout["header"].update(banner_panel)
            layout["target"].update(target_panel)
            layout["footer"].update(score_panel)
            total_h = h_banner + h_target + h_score
            self._print_layout(layout, total_h)
            return

        cert_panel = self._certificate_panel(r.certificate)
        analysis_panel = self._analysis_panel(r.tls, r.headers)

        # --- Medición de alturas reales (evita recortes del Layout) -----------
        left_w = width // 2
        right_w = width - left_w
        h_left = self._measure(cert_panel, left_w)
        h_right = self._measure(analysis_panel, right_w)
        body_h = max(h_left, h_right)

        # --- Layout de cuadrícula ---------------------------------------------
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=h_banner),
            Layout(name="target", size=h_target),
            Layout(name="body", size=body_h),
            Layout(name="footer", size=h_score),
        )
        layout["body"].split_row(Layout(name="left", ratio=1), Layout(name="right", ratio=1))

        layout["header"].update(banner_panel)
        layout["target"].update(target_panel)
        layout["left"].update(cert_panel)
        layout["right"].update(analysis_panel)
        layout["footer"].update(score_panel)

        self._print_layout(layout, h_banner + h_target + body_h + h_score)

    def _print_layout(self, layout: Layout, total_h: int) -> None:
        """Imprime el layout con altura total = suma de secciones (sin recortes)."""
        previous_height = self.console.height
        self.console.height = total_h
        try:
            self.console.print(layout)
        finally:
            self.console.height = previous_height

    @staticmethod
    def _measure(renderable, width: int) -> int:
        """Número de líneas que ocupa un renderable a una anchura dada."""
        probe = Console(width=width, height=10_000, file=StringIO())
        lines = probe.render_lines(renderable, pad=False)
        return len(lines)

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------

    def _banner_panel(self) -> Panel:
        banner = Text(BANNER.strip("\n"), style=Style(color="bright_cyan", bold=True))
        subtitle = Text(SUBTITLE, style=Style(color="bright_magenta", italic=True))
        return Panel(
            Group(Align.center(banner), Align.center(subtitle)),
            border_style="bright_cyan",
            title="[bold bright_cyan]CRYPTO-CHECK[/]",
            subtitle=f"[dim]Escaneo: {self.result.host}:{self.result.port}[/]",
        )

    # ------------------------------------------------------------------
    # Panel superior: objetivo
    # ------------------------------------------------------------------

    def _target_panel(self) -> Panel:
        r = self.result
        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style=DIM)
        grid.add_column()
        grid.add_row("Host", Text(r.host, style="bold white"))
        grid.add_row("IP", Text(r.ip or "—", style=CYAN))
        grid.add_row("Puerto", Text(str(r.port), style="bold white"))
        grid.add_row("DNS", Text("RESUELTO" if r.resolved else "FALLO", style=GREEN if r.resolved else RED))
        return Panel(grid, title="[bold] OBJETIVO [/]", border_style=CYAN)

    # ------------------------------------------------------------------
    # Panel izquierdo: certificado X.509
    # ------------------------------------------------------------------

    @staticmethod
    def _expiry_visual(cert: CertificateInfo) -> Text:
        """Barra de progreso visual para la vida restante del certificado."""
        if cert.days_remaining is None:
            return Text("N/D", style=YELLOW)
        if cert.is_expired:
            return Text("EXPIRADO", style=f"bold {RED}")
        days = cert.days_remaining
        color = GREEN if days > WARN_DAYS else (YELLOW if days > CRIT_DAYS else RED)
        ratio = max(0.0, min(1.0, days / 90.0))  # barra normalizada a 90 días
        width = 20
        filled = int(width * ratio)
        bar = Text("█" * filled, style=color) + Text("░" * (width - filled), style=DIM)
        return Text.assemble(bar, Text(f"  {days} días", style=f"bold {color}"))

    @staticmethod
    def _key_color(algo: str) -> str:
        strong = ("RSA 2048", "RSA 3072", "RSA 4096", "ECC", "Ed25519", "Ed448")
        weak = ("RSA 512", "RSA 768", "RSA 1024")
        if any(w in algo for w in weak):
            return RED
        if any(s in algo for s in strong):
            return GREEN
        return YELLOW

    def _certificate_panel(self, cert: CertificateInfo) -> Panel:
        if cert.subject_cn == "N/D" and cert.error:
            body = Group(Align.center(Text(cert.error, style=RED)))
            return Panel(body, title="[bold] CERTIFICADO X.509 [/]", border_style=RED)

        days = cert.days_remaining
        if cert.is_expired or days is None:
            days_color = RED
        elif days > WARN_DAYS:
            days_color = GREEN
        elif days > CRIT_DAYS:
            days_color = YELLOW
        else:
            days_color = RED

        sig = cert.signature_algo or ""
        sig_lower = sig.lower()
        sig_color = GREEN if any(h in sig_lower for h in ("sha256", "sha384", "sha512", "ed25519", "ed448")) else RED

        grid = Table.grid(padding=(0, 1))
        grid.add_column(justify="right", style=DIM, no_wrap=True)
        grid.add_column(overflow="fold")

        grid.add_row("Subject (CN)", Text(cert.subject_cn, style="bold white"))
        grid.add_row("Issuer (CA)", Text(cert.issuer, style=CYAN))
        grid.add_row("SANs", Text(", ".join(cert.sans) if cert.sans else "—", style="white"))
        grid.add_row("Clave pública", Text(cert.public_key_algo, style=self._key_color(cert.public_key_algo)))
        grid.add_row("Firma", Text(sig, style=sig_color))
        grid.add_row("Serial", Text(cert.serial_number, style=DIM))
        grid.add_row("Válido desde", Text(cert.not_before.strftime("%Y-%m-%d %H:%M UTC") if cert.not_before else "—", style="white"))
        grid.add_row("Expira", Text(cert.not_after.strftime("%Y-%m-%d %H:%M UTC") if cert.not_after else "—", style=days_color))
        grid.add_row("Restante", self._expiry_visual(cert))
        grid.add_row("Estado", Text("EXPIRADO" if cert.is_expired else "VÁLIDO", style=f"bold {RED if cert.is_expired else GREEN}"))
        grid.add_row("Autofirmado", Text("SÍ" if cert.is_self_signed else "NO", style=f"bold {RED if cert.is_self_signed else GREEN}"))
        grid.add_row("Wildcard", Text("SÍ" if cert.is_wildcard else "NO", style=CYAN))

        if cert.error:
            grid.add_row("Nota", Text(cert.error, style=YELLOW))

        if cert.is_expired or cert.is_self_signed:
            border = RED
        elif days is not None and days <= WARN_DAYS:
            border = YELLOW
        else:
            border = GREEN
        return Panel(grid, title="[bold] CERTIFICADO X.509 [/]", border_style=border)

    # ------------------------------------------------------------------
    # Panel derecho: cifrado + cabeceras
    # ------------------------------------------------------------------

    @staticmethod
    def _protocol_row(label: str, supported) -> Text:
        if supported is True:
            status = "SOPORTADO"
            style = RED if label in ("TLS 1.0", "TLS 1.1", "SSL 3.0") else GREEN
        elif supported is False:
            status, style = "no soportado", DIM
        else:
            status, style = "no comprobable", YELLOW
        return Text.assemble((f"{label:<10}", "white"), (status, style))

    def _analysis_panel(self, tls: TLSInfo, hdr: HeaderInfo) -> Panel:
        stack: list = []

        # --- Protocolos -----------------------------------------------------
        proto_table = Table.grid(padding=(0, 1))
        proto_table.add_column(justify="right", style=DIM, no_wrap=True)
        proto_table.add_column(overflow="fold")
        proto_table.add_row("Máx. TLS", Text(tls.max_tls_version, style=GREEN if tls.max_tls_version in ("TLS 1.3", "TLS 1.2") else RED))
        for label in ("TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0"):
            if label in tls.supported_versions:
                proto_table.add_row("", self._protocol_row(label, tls.supported_versions[label]))
        if tls.insecure_protocols:
            proto_table.add_row("ALERTA", Text("Protocolos inseguros: " + ", ".join(tls.insecure_protocols), style=RED))
        stack.append(Panel(proto_table, title="[bold] PROTOCOLOS [/]", border_style=CYAN))

        # --- Cipher suite ------------------------------------------------------
        cipher_color = RED if tls.weak_cipher else (GREEN if tls.strong_cipher else YELLOW)
        cipher_table = Table.grid(padding=(0, 1))
        cipher_table.add_column(justify="right", style=DIM, no_wrap=True)
        cipher_table.add_column(overflow="fold")
        cipher_table.add_row("Negociado", Text(f"{tls.negotiated_cipher} ({tls.cipher_bits} bits, {tls.cipher_protocol})", style=cipher_color))
        cipher_table.add_row("Key Exchange", Text(tls.key_exchange, style=GREEN if tls.has_pfs else RED))
        cipher_table.add_row("Cifrado", Text(tls.symmetric_cipher, style=cipher_color))
        mac_style = RED if tls.mac_algo in ("SHA-1 (obsoleto)", "MD5 (roto)", "NULL") else GREEN
        cipher_table.add_row("MAC", Text(tls.mac_algo, style=mac_style))
        cipher_table.add_row("PFS", Text("SÍ (Forward Secrecy)" if tls.has_pfs else "NO — sin PFS", style=GREEN if tls.has_pfs else RED))
        if tls.weak_cipher:
            cipher_table.add_row("ALERTA", Text(f"Cipher débil: {tls.weak_cipher}", style=RED))
        for note in tls.notes[:3]:
            cipher_table.add_row("Nota", Text(note, style=DIM))
        stack.append(Panel(cipher_table, title="[bold] CIPHER SUITE [/]", border_style=CYAN))

        # --- HSTS -----------------------------------------------------------
        hsts_table = Table.grid(padding=(0, 1))
        hsts_table.add_column(justify="right", style=DIM, no_wrap=True)
        hsts_table.add_column(overflow="fold")
        if hdr.error:
            hsts_table.add_row("HSTS", Text(f"Error al consultar: {hdr.error}", style=YELLOW))
        else:
            hsts_style = f"bold {GREEN}" if hdr.hsts_present else f"bold {RED}"
            hsts_table.add_row("HSTS", Text("PRESENTE" if hdr.hsts_present else "AUSENTE", style=hsts_style))
            if hdr.hsts_present:
                age = hdr.hsts_max_age
                hsts_table.add_row("max-age", Text(str(age) if age is not None else "?", style=GREEN if (age or 0) >= 15552000 else YELLOW))
                hsts_table.add_row("subdomains", Text("SÍ" if hdr.hsts_include_subdomains else "NO", style=CYAN))
                hsts_table.add_row("preload", Text("SÍ" if hdr.hsts_preload else "NO", style=CYAN))
                if hdr.hsts_via_redirect:
                    hsts_table.add_row("Origen", Text(f"Redirect -> {hdr.final_url}", style=YELLOW))
            if hdr.server_header:
                hsts_table.add_row("Server", Text(hdr.server_header, style=DIM))
        stack.append(Panel(hsts_table, title="[bold] CABECERAS (HSTS) [/]", border_style=CYAN))

        group = Group(*stack)
        return Panel(group, title="[bold] ANÁLISIS DE CIFRADO Y CABECERAS [/]", border_style=CYAN)

    # ------------------------------------------------------------------
    # Panel inferior: score global
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_score(r: AuditResult) -> tuple[str, str, list[str]]:
        """Devuelve (letra, color, razones) según la matriz A/B/C/F."""
        cert, tls, hdr = r.certificate, r.tls, r.headers
        reasons: list[str] = []

        fatal = cert.is_expired or cert.is_self_signed or bool(tls.insecure_protocols)
        if fatal:
            if cert.is_expired:
                reasons.append("Certificado caducado")
            if cert.is_self_signed:
                reasons.append("Certificado autofirmado")
            if tls.insecure_protocols:
                reasons.append("Protocolos inseguros activos: " + ", ".join(tls.insecure_protocols))
            return "F", RED, reasons

        weak = tls.weak_cipher is not None or not tls.has_pfs or "SHA-1" in cert.signature_algo or "MD5" in cert.signature_algo
        if weak:
            if tls.weak_cipher:
                reasons.append(f"Cipher débil en uso ({tls.weak_cipher})")
            if not tls.has_pfs:
                reasons.append("Sin Forward Secrecy (PFS)")
            if "SHA-1" in cert.signature_algo or "MD5" in cert.signature_algo:
                reasons.append("Algoritmo de firma débil")
            return "C", YELLOW, reasons

        modern = tls.max_tls_version in ("TLS 1.3", "TLS 1.2")
        cert_ok = (cert.days_remaining or 0) > WARN_DAYS
        hsts_ok = hdr.hsts_present

        if not modern:
            reasons.append(f"Versión TLS insuficiente ({tls.max_tls_version})")
            return "C", YELLOW, reasons
        if cert_ok and hsts_ok:
            reasons.append("TLS 1.2/1.3 + ciphers fuertes, certificado válido > 30 días, HSTS activo")
            return "A", GREEN, reasons

        if not cert_ok:
            reasons.append(f"Certificado caduca pronto ({cert.days_remaining} días)")
        if not hsts_ok:
            reasons.append("Cabecera HSTS ausente")
        return "B", YELLOW, reasons

    def _score_panel(self) -> Panel:
        r = self.result

        # Error fatal de auditoría ----------------------------------------
        if r.error:
            body = Group(
                Text(r.error, style=RED),
                Text(f"Tipo de fallo: {r.error_kind}", style=DIM),
                Text("La auditoría no pudo completarse. Revisa host/puerto y conectividad.", style=YELLOW),
            )
            return Panel(Align.center(body), title="[bold] RESULTADO [/]", border_style=RED)

        grade, color, reasons = self._compute_score(r)

        grade_text = Text(f"  {grade}  ", style=Style(color="black", bgcolor=color, bold=True))
        verdict = {
            "A": "Configuración sólida — continúa con el monitoreo.",
            "B": "Aceptable con reservas — refuerza HSTS/renovación de certificado.",
            "C": "Advertencias de cifrado — plan de remediación recomendado.",
            "F": "CRÍTICO — remediación inmediata requerida.",
        }[grade]

        table = Table.grid(padding=(0, 2))
        table.add_column(justify="center")
        table.add_column()
        table.add_row(grade_text, Text(verdict, style=f"bold {color}" if color != GREEN else color))

        rows: list = [Text(f"• {reason}", style=color) for reason in reasons] or [Text("Sin observaciones.", style=DIM)]
        if r.warnings:
            rows.append(Text(""))
            rows.append(Text("Advertencias adicionales:", style=DIM))
            rows.extend(Text(f"  ! {w}", style=YELLOW) for w in r.warnings)

        body = Group(table, Rule(style=DIM), *rows)
        return Panel(Align.center(body), title="[bold] CALIFICACIÓN GLOBAL [/]", border_style=color)
