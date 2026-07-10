"""CLI do Detector de Phishing."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from .analyzer import analyze_url

_COLORS = {"ALTO": "\033[91m", "MÉDIO": "\033[93m", "BAIXO": "\033[93m",
           "MÍNIMO": "\033[92m"}
_RESET = "\033[0m"


def _render(res, plain=False):
    c = "" if plain else _COLORS.get(res.risk, "")
    r = "" if plain else _RESET
    out = [
        f"URL:     {res.url}",
        f"Domínio: {res.domain}",
        f"Score:   {c}{res.score}/100 — RISCO {res.risk}{r}",
        "",
        "Sinais detectados:" if res.signals else "Nenhum sinal suspeito.",
    ]
    for s in sorted(res.signals, key=lambda x: -x.weight):
        out.append(f"  [+{s.weight:>2}] {s.name}: {s.detail}")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(description="Detector de phishing por análise heurística de URL.")
    p.add_argument("url", help="URL a analisar")
    p.add_argument("--network", action="store_true", help="fazer checagens de rede (SSL)")
    p.add_argument("--json", action="store_true", help="saída JSON")
    p.add_argument("--plain", action="store_true", help="sem cores")
    args = p.parse_args(argv)

    res = analyze_url(args.url, check_network=args.network)
    if args.json:
        print(json.dumps(asdict(res), ensure_ascii=False, indent=2))
    else:
        print(_render(res, plain=args.plain))
    return 0 if res.score < 30 else 2


if __name__ == "__main__":
    raise SystemExit(main())
