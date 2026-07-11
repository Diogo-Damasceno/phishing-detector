# phishing-detector

Analisa uma **URL** e produz uma **pontuação de risco (0–100)** com base em
heurísticas de phishing — sem depender de listas negras externas. Funciona
totalmente offline, com checagens de rede (SSL) opcionais.

> ⚠️ Ferramenta educacional/defensiva. Um score baixo **não garante** que um site
> é seguro; um score alto indica sinais suspeitos que merecem atenção.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/phishing-detector.git
cd phishing-detector
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/phishdet" ~/.local/bin/phishdet
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# analisa uma URL (offline)
phishdet "http://exemplo-login.xyz/secure"

# com checagem de rede (certificado SSL) e saida JSON
phishdet "https://site.com" --network --json
```

## Licença

MIT — veja `LICENSE`.
