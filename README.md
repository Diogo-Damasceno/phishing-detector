# Phishing Detector 🎣

Analisa uma **URL** e produz uma **pontuação de risco (0–100)** com base em heurísticas de phishing — sem depender de listas negras externas. Funciona totalmente offline, com checagens de rede (SSL) opcionais.

> ⚠️ Ferramenta educacional/defensiva. Um score baixo **não garante** que um site é seguro; um score alto indica sinais suspeitos que merecem atenção.

## Heurísticas avaliadas

| Sinal | Descrição |
|-------|-----------|
| `no_https` | URL sem TLS |
| `ip_as_host` | IP em vez de domínio |
| `at_symbol` | `@` no netloc (ofuscação) |
| `many_subdomains` | excesso de rótulos |
| `punycode` | domínio homógrafo (`xn--`) |
| `suspicious_tld` | TLD abusado (.tk, .xyz, .zip…) |
| `url_shortener` | encurtador de URL |
| `brand_in_subdomain` | marca fora do domínio registrável |
| `typosquatting` | domínio parecido com marca conhecida |
| `sensitive_words` | login/verify/secure/senha… |
| `long_url` | URL muito longa |
| `high_entropy` | domínio gerado automaticamente |
| `ssl_error` / `expired_cert` | (com `--network`) |

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/phishing-detector.git
cd phishing-detector
pip install -e .
```

## Uso

```bash
phishdet https://www.google.com
phishdet "http://paypal.secure-login.xyz/account"
phishdet --network https://exemplo.com     # inclui checagem de SSL
phishdet --json "http://paypa1.com"          # saída JSON
```

### Exemplo

```
URL:     http://paypal.secure-login.xyz/account
Domínio: paypal.secure-login.xyz
Score:   46/100 — RISCO MÉDIO

Sinais detectados:
  [+22] brand_in_subdomain: Marca 'paypal' fora do domínio registrável (secure-login.xyz)
  [+15] no_https: URL não usa HTTPS
  [+12] suspicious_tld: TLD frequentemente abusado: .xyz
```

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Licença

MIT
