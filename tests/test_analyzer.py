from phishdet.analyzer import analyze_url, _levenshtein, _shannon_entropy


def test_legit_url_low_score():
    res = analyze_url("https://www.google.com")
    assert res.score < 30
    assert res.risk in ("MÍNIMO", "BAIXO")


def test_ip_host_flagged():
    res = analyze_url("http://192.168.1.1/login")
    names = {s.name for s in res.signals}
    assert "ip_as_host" in names
    assert "no_https" in names


def test_typosquatting_detected():
    res = analyze_url("http://paypa1.com")  # 1 no lugar de l
    names = {s.name for s in res.signals}
    assert "typosquatting" in names or "brand_in_subdomain" in names
    assert res.score >= 30


def test_brand_in_subdomain():
    res = analyze_url("http://paypal.secure-login.xyz/account")
    names = {s.name for s in res.signals}
    assert "brand_in_subdomain" in names
    assert res.risk in ("MÉDIO", "ALTO")


def test_at_symbol_obfuscation():
    res = analyze_url("http://legit.com@evil.com/")
    names = {s.name for s in res.signals}
    assert "at_symbol" in names


def test_suspicious_tld():
    res = analyze_url("http://freegift.tk")
    names = {s.name for s in res.signals}
    assert "suspicious_tld" in names


def test_levenshtein():
    assert _levenshtein("paypal", "paypa1") == 1
    assert _levenshtein("abc", "abc") == 0


def test_entropy_positive():
    assert _shannon_entropy("aaaa") == 0.0
    assert _shannon_entropy("abcd") > 1.9


def test_score_capped():
    res = analyze_url("http://paypal-login.secure-verify-account.tk@1.2.3.4/webscr")
    assert res.score <= 100
