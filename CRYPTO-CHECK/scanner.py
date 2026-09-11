"""
Crypto-Check — scanner.py
========================
Lógica de red y análisis criptográfico.

Clase principal: :class:`CryptoCheckAuditor`
Modelos de datos: :class:`CertificateInfo`, :class:`TLSInfo`, :class:`HeaderInfo`,
:class:`AuditResult`.

Diseñado como herramienta de auditoría defensiva (Blue Team): solo realiza
conexiones de lectura y análisis pasivo de la configuración TLS/TLS del objetivo.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

# --------------------------------------------------------------------------
# Modelos de datos (resultados estructurados para la TUI)
# --------------------------------------------------------------------------


@dataclass
class CertificateInfo:
    """Datos extraídos del certificado X.509 del servidor."""

    subject_cn: str = "N/D"
    issuer: str = "N/D"
    sans: list[str] = field(default_factory=list)
    public_key_algo: str = "N/D"
    signature_algo: str = "N/D"
    serial_number: str = "N/D"
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_remaining: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    is_wildcard: bool = False
    error: Optional[str] = None


@dataclass
class TLSInfo:
    """Resultado del sondeo de protocolos y cipher suites."""

    max_tls_version: str = "N/D"
    supported_versions: dict[str, Optional[bool]] = field(default_factory=dict)
    negotiated_cipher: str = "N/D"
    cipher_protocol: str = "N/D"
    cipher_bits: int = 0
    key_exchange: str = "N/D"
    symmetric_cipher: str = "N/D"
    mac_algo: str = "N/D"
    has_pfs: bool = False
    weak_cipher: Optional[str] = None
    strong_cipher: bool = False
    insecure_protocols: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class HeaderInfo:
    """Resultado de la auditoría de cabeceras HTTP de seguridad."""

    hsts_present: bool = False
    hsts_value: Optional[str] = None
    hsts_max_age: Optional[int] = None
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    hsts_via_redirect: bool = False
    final_url: Optional[str] = None
    server_header: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AuditResult:
    """Resultados consolidados de la auditoría."""

    host: str
    port: int
    ip: Optional[str] = None
    resolved: bool = False
    certificate: CertificateInfo = field(default_factory=CertificateInfo)
    tls: TLSInfo = field(default_factory=TLSInfo)
    headers: HeaderInfo = field(default_factory=HeaderInfo)
    error: Optional[str] = None
    error_kind: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Utilidades internas
# --------------------------------------------------------------------------

# Ciphers / protocolos considerados débiles (nist deprecation + known attacks)
WEAK_CIPHER_PATTERNS = ("RC4", "3DES", "DES40", "DES-CBC", "MD5", "NULL", "EXPORT", "anon")
STRONG_CIPHER_PATTERNS = ("AESGCM", "AES_256_GCM", "AES_128_GCM", "CHACHA20", "AES256-GCM", "AES128-GCM")

TLS_VERSION_LABELS = {
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
    ssl.TLSVersion.TLSv1_2: "TLS 1.2",
    ssl.TLSVersion.TLSv1_3: "TLS 1.3",
}

INSECURE_VERSIONS = {"TLS 1.0", "TLS 1.1", "SSL 3.0"}


def _utc(dt: datetime) -> datetime:
    """Normaliza un datetime a timezone-aware UTC (compatible con cryptography>=42)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _decompose_cipher(name: str) -> tuple[str, str, str]:
    """
    Descompone (best-effort) un nombre de cipher suite OpenSSL en
    (key_exchange, symmetric_cipher, mac).

    Nombres IANA/TLS1.3 puros (p. ej. TLS_AES_256_GCM_SHA384) llevan tratamiento
    separado porque no incluyen el intercambio de claves.
    """
    n = name.strip()
    if n.startswith("TLS_") and "ECDHE" not in n and "RSA" not in n:
        # Suite TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256...
        parts = n.split("_")
        return ("KeySchedule TLS1.3", "_".join(parts[1:-1]), parts[-1])

    key_exchange, sym, mac = "N/D", "N/D", "N/D"
    upper = n.upper()

    if "ECDHE" in upper:
        key_exchange = "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
    elif "DHE" in upper:
        key_exchange = "DHE (Diffie-Hellman Ephemeral)"
    elif "ECDH" in upper:
        key_exchange = "ECDH (estático, sin PFS)"
    elif "DH" in upper:
        key_exchange = "DH (estático, sin PFS)"
    elif "RSA" in upper:
        key_exchange = "RSA (intercambio estático, sin PFS)"

    if "CHACHA20" in upper:
        sym = "CHACHA20"
    elif "3DES" in upper:
        sym = "3DES (débil)"
    elif "RC4" in upper:
        sym = "RC4 (débil)"
    elif "AES256" in upper or "AES_256" in upper:
        sym = "AES-256"
    elif "AES128" in upper or "AES_128" in upper:
        sym = "AES-128"
    elif "DES" in upper:
        sym = "DES (débil)"
    elif "NULL" in upper:
        sym = "NULL (sin cifrado)"

    if "GCM" in upper or "POLY1305" in upper:
        mac = "AEAD (GCM/Poly1305)"
    elif "SHA384" in upper:
        mac = "SHA-384"
    elif "SHA256" in upper or "SHA_256" in upper:
        mac = "SHA-256"
    elif "SHA" in upper:
        mac = "SHA-1 (obsoleto)"
    elif "MD5" in upper:
        mac = "MD5 (roto)"
    elif "NULL" in upper:
        mac = "NULL"

    return key_exchange, sym, mac


# --------------------------------------------------------------------------
# Auditor
# --------------------------------------------------------------------------


class CryptoCheckAuditor:
    """
    Motor de auditoría TLS/SSL (solo lectura, defensivo).

    Parámetros
    ----------
    host : str           Hostname o IP objetivo.
    port : int           Puerto TCP (por defecto 443).
    timeout : float      Timeout de socket en segundos.
    """

    def __init__(self, host: str, port: int = 443, timeout: float = 8.0) -> None:
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------

    def run(self) -> AuditResult:
        """Ejecuta la auditoría completa y devuelve un :class:`AuditResult`."""
        result = AuditResult(host=self.host, port=self.port)

        # 1. Resolución DNS -------------------------------------------------
        try:
            infos = socket.getaddrinfo(self.host, self.port, proto=socket.IPPROTO_TCP)
            result.ip = infos[0][4][0]
            result.resolved = True
        except socket.gaierror as exc:
            result.error = f"No se pudo resolver el dominio '{self.host}': {exc}"
            result.error_kind = "DNS"
            return result
        except OSError as exc:
            result.error = f"Error de red al resolver '{self.host}': {exc}"
            result.error_kind = "DNS"
            return result

        # 2. Certificado X.509 ---------------------------------------------
        try:
            result.certificate = self._fetch_certificate()
        except (socket.timeout, TimeoutError):
            result.error = f"Tiempo de espera agotado ({self.timeout}s) contactando {self.host}:{self.port}."
            result.error_kind = "TIMEOUT"
            return result
        except ssl.SSLError as exc:
            result.error = f"Fallo en el handshake SSL/TLS: {exc.reason or exc}"
            result.error_kind = "SSL"
            return result
        except ConnectionRefusedError:
            result.error = f"Conexión rechazada por {self.host}:{self.port}. ¿Está el puerto abierto?"
            result.error_kind = "CONNECTION"
            return result
        except (ConnectionResetError, BrokenPipeError):
            result.error = "La conexión fue reiniciada por el servidor durante el handshake."
            result.error_kind = "CONNECTION"
            return result
        except OSError as exc:
            result.error = f"Error de socket inesperado: {exc}"
            result.error_kind = "SOCKET"
            return result

        # 3. Sondeo TLS + cabeceras HTTP (en paralelo para no bloquear) ----
        with ThreadPoolExecutor(max_workers=4) as pool:
            fut_tls = pool.submit(self._probe_tls)
            fut_headers = pool.submit(self._check_hsts)
            result.tls = fut_tls.result()
            result.headers = fut_headers.result()

        # 4. Advertencias consolidadas ---------------------------------------
        self._collect_warnings(result)
        return result

    # ------------------------------------------------------------------
    # Certificado
    # ------------------------------------------------------------------

    def _unverified_context(self, *, pinned: Optional[ssl.TLSVersion] = None,
                            seclevel0: bool = False) -> ssl.SSLContext:
        """
        Crea un contexto TLS SIN validación local (CERT_NONE, check_hostname off)
        para poder inspeccionar certificados autofirmados o caducados.

        ``pinned`` fija minimum=maximum para sondear una versión concreta.
        ``seclevel0`` baja el nivel de seguridad de OpenSSL para hablar con
        servidores legacy (solo sondeo, nunca tráfico real sensible).
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if pinned is not None:
            ctx.minimum_version = pinned
            ctx.maximum_version = pinned
        if seclevel0:
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass  # El runtime no permite bajar SECLEVEL; se registra en notas.
        return ctx

    def _connect_tls(self, ctx: ssl.SSLContext) -> ssl.SSLSocket:
        """Abre una conexión TCP y la envuelve en TLS con el contexto dado."""
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=self.host if not _is_ip(self.host) else None)
        return ssock

    def _fetch_certificate(self) -> CertificateInfo:
        """Conecta, captura el certificado DER y lo parsea con `cryptography`."""
        info = CertificateInfo()
        ctx = self._unverified_context()
        ssock = self._connect_tls(ctx)
        try:
            der = ssock.getpeercert(binary_form=True)
        finally:
            ssock.close()
        if not der:
            info.error = "El servidor no devolvió certificado."
            return info

        cert = x509.load_der_x509_certificate(der)

        # Subject CN -----------------------------------------------------
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info.subject_cn = attrs[0].value if attrs else cert.subject.rfc4514_string()

        # Issuer ---------------------------------------------------------
        info.issuer = cert.issuer.rfc4514_string()

        # SANs -------------------------------------------------------------
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            info.sans = list(ext.value.get_values_for_type(x509.DNSName))
            info.sans += [f"IP:{ip}" for ip in ext.value.get_values_for_type(x509.IPAddress)]
        except (x509.ExtensionNotFound, Exception):  # noqa: BLE001 - extensión opcional
            info.sans = []

        # Algoritmo de clave pública ----------------------------------------
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            size = key.key_size
            info.public_key_algo = f"RSA {size} bits"
        elif isinstance(key, ec.EllipticCurvePublicKey):
            info.public_key_algo = f"ECC {key.curve.name} ({key.curve.key_size} bits)"
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            info.public_key_algo = key.__class__.__name__.replace("PublicKey", "")
        else:
            info.public_key_algo = key.__class__.__name__

        # Algoritmo de firma --------------------------------------------------
        try:
            sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
        except Exception:  # noqa: BLE001 - algoritmo desconocido para la librería
            sig_hash = ""
        try:
            sig_oid = cert.signature_algorithm_oid._name
        except Exception:  # noqa: BLE001
            sig_oid = "Unknown"
        if sig_hash and sig_hash.lower() not in sig_oid.lower():
            info.signature_algo = f"{sig_oid} (hash {sig_hash})"
        else:
            info.signature_algo = sig_oid

        # Validez ----------------------------------------------------------------
        info.serial_number = f"{cert.serial_number:X}"
        info.not_before = _utc(cert.not_valid_before_utc) if hasattr(cert, "not_valid_before_utc") else _utc(cert.not_valid_before)
        info.not_after = _utc(cert.not_valid_after_utc) if hasattr(cert, "not_valid_after_utc") else _utc(cert.not_valid_after)

        now = _now()
        info.is_expired = now > info.not_after
        if info.not_before > now:
            info.days_remaining = (info.not_after - now).days
            info.error = "Certificado AÚN NO VÁLIDO (notBefore en el futuro)."
        else:
            info.days_remaining = (info.not_after - now).days

        # Autofirmado: subject == issuer (validación de cadena fuera de alcance)
        info.is_self_signed = cert.subject == cert.issuer
        info.is_wildcard = info.subject_cn.startswith("*.") or any(s.startswith("*.") for s in info.sans)

        return info

    # ------------------------------------------------------------------
    # Protocolos / ciphers
    # ------------------------------------------------------------------

    @staticmethod
    def _peer_serial(ssock: ssl.SSLSocket) -> Optional[int]:
        """Serial del certificado presentado en un handshake (None si no disponible)."""
        try:
            der = ssock.getpeercert(binary_form=True)
            if not der:
                return None
            return x509.load_der_x509_certificate(der).serial_number
        except Exception:  # noqa: BLE001 - diagnóstico secundario, nunca crítico
            return None

    def _probe_tls(self) -> TLSInfo:
        """Determina versión máxima, soporte por versión y cipher negociado."""
        info = TLSInfo()

        # --- Cipher negociado + versión máxima (handshake normal) ---------
        reference_serial: Optional[int] = None
        try:
            ssock = self._connect_tls(self._unverified_context())
            try:
                name, proto, bits = ssock.cipher()
                info.negotiated_cipher = name or "N/D"
                info.cipher_protocol = proto or "N/D"
                info.cipher_bits = bits or 0
                info.max_tls_version = ssock.version() or "N/D"
                reference_serial = self._peer_serial(ssock)
            finally:
                ssock.close()
        except (socket.timeout, TimeoutError):
            info.error = "Timeout durante el handshake TLS."
            return info
        except ssl.SSLError as exc:
            info.error = f"Handshake TLS fallido: {exc.reason or exc}"
            return info
        except OSError as exc:
            info.error = f"Error de socket: {exc}"
            return info

        # --- Descomposición del cipher ------------------------------------
        info.key_exchange, info.symmetric_cipher, info.mac_algo = _decompose_cipher(info.negotiated_cipher)
        upper = info.negotiated_cipher.upper()
        info.has_pfs = ("ECDHE" in upper) or ("DHE" in upper) or (info.cipher_protocol.startswith("TLSv1.3"))
        info.weak_cipher = next((p for p in WEAK_CIPHER_PATTERNS if p.upper() in upper), None)
        info.strong_cipher = any(p in upper for p in STRONG_CIPHER_PATTERNS) and info.weak_cipher is None

        # --- Sondeo por versión ----------------------------------------------
        for version, label in TLS_VERSION_LABELS.items():
            legacy = version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1)
            supported, note = self._test_version(
                version, legacy=legacy, reference_serial=reference_serial
            )
            info.supported_versions[label] = supported
            if note:
                info.notes.append(note)
            if supported and label in INSECURE_VERSIONS:
                info.insecure_protocols.append(label)

        # SSLv3: eliminado de OpenSSL moderno; se informa como no comprobable.
        info.supported_versions["SSL 3.0"] = None
        info.notes.append("SSLv3: no comprobable con OpenSSL moderno (deprecado en runtime).")

        # Ajuste de max_tls_version con lo realmente observado
        observed = [lbl for ver, lbl in TLS_VERSION_LABELS.items() if info.supported_versions.get(lbl)]
        if observed:
            order = ["TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]
            info.max_tls_version = max(observed, key=order.index)
        return info

    def _test_version(
        self, version: ssl.TLSVersion, *, legacy: bool, reference_serial: Optional[int] = None
    ) -> tuple[Optional[bool], Optional[str]]:
        """
        Intenta un handshake fijado a ``version``.

        Devuelve (True, None) si soportado, (False, None) si rechazado,
        (None, nota) si no se puede afirmar (política OpenSSL local o proxy
        TLS intermedio detectado mediante comparación de certificados).
        """
        for seclevel0 in ((True, False) if legacy else (False,)):
            try:
                ssock = self._connect_tls(self._unverified_context(pinned=version, seclevel0=seclevel0))
                serial = self._peer_serial(ssock)
                ssock.close()
                # Observación (no bloqueante): un certificado distinto en el
                # handshake legacy puede indicar proxy TLS intermedio, CDN o
                # selección alternativa de certificado. Se reporta el soporte
                # (un handshake completado ES soporte de esa versión) pero se
                # deja constancia en las notas para el analista.
                if legacy and reference_serial is not None and serial is not None and serial != reference_serial:
                    return True, (
                        f"{TLS_VERSION_LABELS[version]}: soportado; el certificado difiere del "
                        "handshake moderno (posible proxy TLS, CDN o selección alternativa de certificado)."
                    )
                return True, None
            except ssl.SSLError as exc:
                reason = (getattr(exc, "reason", "") or "").lower()
                if "no protocols available" in reason or "unsupported protocol" in reason:
                    # El runtime local bloquea la versión, no el servidor.
                    if not seclevel0 and legacy:
                        continue  # reintenta con SECLEVEL=0
                    return None, f"{TLS_VERSION_LABELS[version]}: bloqueado por política local de OpenSSL."
                return False, None
            except (socket.timeout, TimeoutError):
                return None, f"{TLS_VERSION_LABELS[version]}: timeout durante el sondeo."
            except OSError:
                return False, None
        return False, None

    # ------------------------------------------------------------------
    # Cabeceras HTTP (HSTS)
    # ------------------------------------------------------------------

    def _check_hsts(self) -> HeaderInfo:
        """Petición GET por HTTPS y verificación de HSTS (sin bloquear la TUI)."""
        info = HeaderInfo()
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            resp = requests.get(
                f"https://{self.host}:{self.port}/",
                timeout=self.timeout,
                verify=False,           # auditoría: ya analizamos el certificado aparte
                allow_redirects=True,
                headers={"User-Agent": "Crypto-Check/1.0 (TLS Security Auditor)"},
            )
        except requests.exceptions.SSLError as exc:
            info.error = f"HTTPS no disponible para petición HTTP: {exc}"
            return info
        except requests.exceptions.ConnectionError as exc:
            info.error = f"Conexión HTTP fallida: {exc.__cause__ or exc}"
            return info
        except requests.exceptions.Timeout:
            info.error = "Timeout en la petición HTTP."
            return info
        except requests.exceptions.RequestException as exc:
            info.error = f"Error HTTP: {exc}"
            return info

        # HSTS emitido por el host original; si solo aparece tras un redirect
        # (p. ej. example.com -> www.example.com), se registra su origen real.
        chain = list(resp.history) + [resp]
        origin_resp = chain[0]
        hsts = origin_resp.headers.get("Strict-Transport-Security")
        if not hsts and len(chain) > 1:
            for r in chain[1:]:
                hsts = r.headers.get("Strict-Transport-Security")
                if hsts:
                    info.hsts_via_redirect = True
                    break
        if hsts:
            info.hsts_present = True
            info.hsts_value = hsts
            for part in hsts.split(";"):
                part = part.strip()
                if part.upper().startswith("MAX-AGE"):
                    try:
                        info.hsts_max_age = int(part.split("=")[1])
                    except (IndexError, ValueError):
                        pass
                elif part.lower() == "includesubdomains":
                    info.hsts_include_subdomains = True
                elif part.lower() == "preload":
                    info.hsts_preload = True
        if len(chain) > 1:
            info.final_url = str(resp.url)
        info.server_header = resp.headers.get("Server")
        return info

    # ------------------------------------------------------------------
    # Consolidación
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_warnings(result: AuditResult) -> None:
        cert, tls, hdr = result.certificate, result.tls, result.headers
        w = result.warnings

        if cert.is_expired:
            w.append("CERTIFICADO CADUCADO — crítico.")
        elif cert.days_remaining is not None and cert.days_remaining < 30:
            w.append(f"Certificado caduca en {cert.days_remaining} días (< 30).")
        if cert.is_self_signed:
            w.append("Certificado autofirmado (subject == issuer) — no apto para producción.")
        if "SHA-1" in (cert.signature_algo or "") or "MD5" in (cert.signature_algo or ""):
            w.append(f"Algoritmo de firma débil: {cert.signature_algo}.")
        if tls.insecure_protocols:
            w.append(f"Protocolos inseguros activos: {', '.join(tls.insecure_protocols)}.")
        if tls.weak_cipher:
            w.append(f"Cipher débil en uso ({tls.weak_cipher}).")
        if not tls.has_pfs and tls.error is None:
            w.append("Sin Forward Secrecy (PFS) en el cipher negociado.")
        if not hdr.hsts_present and hdr.error is None:
            w.append("Cabecera HSTS ausente.")
        elif hdr.hsts_present and (hdr.hsts_max_age or 0) < 15552000:
            w.append("HSTS presente pero max-age < 180 días (recomendado: >= 15552000).")
        if hdr.hsts_via_redirect:
            w.append(f"HSTS no emitido por el host original; proviene de: {hdr.final_url}")


def _is_ip(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False
