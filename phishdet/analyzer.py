"""Análise heurística de URLs para detecção de phishing.

Cada heurística contribui com pontos para um score final de risco (0-100).
As checagens de rede (SSL, idade de domínio, redirecionamentos) são opcionais
e desativadas por padrão para permitir análise offline e testes determinísticos.
"""

from __future__ import annotations

import ipaddress
import math
import re
import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

# Marcas frequentemente alvo de typosquatting.
_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "bank", "banco", "itau", "bradesco", "nubank",
    "santander", "caixa", "mercadolivre", "steam", "binance", "coinbase",
]

# TLDs frequentemente abusados por phishing.
_SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work", "party",
    "gq", "ml", "cf", "tk", "ga", "xyz", "top", "click", "link", "buzz",
}

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at",
}

_SENSITIVE_WORDS = [
    "login", "signin", "verify", "account", "update", "secure", "confirm",
    "webscr", "password", "senha", "banking", "wallet", "recover", "unlock",
]


@dataclass
class Signal:
    name: str
    weight: int
    detail: str


@dataclass
class PhishResult:
    url: str
    domain: str
    score: int = 0
    risk: str = ""
    signals: list[Signal] = field(default_factory=list)

    def add(self, name: str, weight: int, detail: str) -> None:
        self.signals.append(Signal(name, weight, detail))
        self.score += weight


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(url: str, check_network: bool = False,
                timeout: float = 5.0) -> PhishResult:
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    res = PhishResult(url=url, domain=host)

    # 1. HTTP sem TLS
    if parsed.scheme != "https":
        res.add("no_https", 15, "URL não usa HTTPS")

    # 2. IP no lugar de domínio
    if _is_ip(host):
        res.add("ip_as_host", 25, "Usa endereço IP em vez de domínio")

    # 3. Presença de '@' na URL (redireciona credenciais)
    if "@" in parsed.netloc:
        res.add("at_symbol", 20, "Contém '@' no netloc (ofuscação de destino)")

    # 4. Muitos subdomínios
    labels = host.split(".")
    if len(labels) >= 5:
        res.add("many_subdomains", 12, f"{len(labels)} rótulos no domínio")

    # 5. Hífens em excesso / punycode
    if host.count("-") >= 3:
        res.add("many_hyphens", 8, "Muitos hífens no domínio")
    if "xn--" in host:
        res.add("punycode", 15, "Domínio punycode (possível homógrafo)")

    # 6. TLD suspeito
    tld = labels[-1].lower() if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        res.add("suspicious_tld", 12, f"TLD frequentemente abusado: .{tld}")

    # 7. Encurtador
    if host.lower() in _SHORTENERS:
        res.add("url_shortener", 10, "Serviço encurtador de URL")

    # 8. Marca no subdomínio/caminho mas não no domínio registrável
    registrable = ".".join(labels[-2:]) if len(labels) >= 2 else host
    full = (host + parsed.path).lower()
    for brand in _BRANDS:
        if brand in full and brand not in registrable.lower():
            res.add("brand_in_subdomain", 22,
                    f"Marca '{brand}' fora do domínio registrável ({registrable})")
            break

    # 9. Typosquatting (distância pequena de uma marca)
    dom_no_tld = labels[-2].lower() if len(labels) >= 2 else host.lower()
    for brand in _BRANDS:
        d = _levenshtein(dom_no_tld, brand)
        if 0 < d <= 2 and abs(len(dom_no_tld) - len(brand)) <= 2:
            res.add("typosquatting", 25,
                    f"Domínio '{dom_no_tld}' parecido com '{brand}' (distância {d})")
            break

    # 10. Palavras sensíveis
    hits = [w for w in _SENSITIVE_WORDS if w in full]
    if hits:
        res.add("sensitive_words", min(4 * len(hits), 15),
                f"Palavras sensíveis: {', '.join(hits[:5])}")

    # 11. URL muito longa
    if len(url) > 90:
        res.add("long_url", 8, f"URL longa ({len(url)} caracteres)")

    # 12. Alta entropia no domínio (geração automática)
    ent = _shannon_entropy(dom_no_tld)
    if ent > 3.6 and len(dom_no_tld) > 10:
        res.add("high_entropy", 10, f"Domínio com alta entropia ({ent:.2f})")

    # 13. Checagens de rede (opcionais)
    if check_network and host and not _is_ip(host):
        _network_checks(res, host, timeout)

    res.score = min(res.score, 100)
    res.risk = _risk_label(res.score)
    return res


def _network_checks(res: PhishResult, host: str, timeout: float) -> None:
    # SSL: tenta validar certificado
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                res.add("expired_cert", 20, "Certificado SSL expirado")
    except ssl.SSLError:
        res.add("ssl_error", 18, "Erro/validação de certificado SSL falhou")
    except (OSError, ValueError):
        res.add("no_ssl", 15, "Não foi possível estabelecer TLS na 443")


def _risk_label(score: int) -> str:
    if score >= 60:
        return "ALTO"
    if score >= 30:
        return "MÉDIO"
    if score >= 10:
        return "BAIXO"
    return "MÍNIMO"
