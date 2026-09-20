# AlvSafe

Antivírus e proteção de endpoint em Python, com linha de comando e interface gráfica.

Projeto educacional e de pesquisa em segurança defensiva. Não substitui um antivírus comercial.

| Sistema | CLI | Interface gráfica |
|---|---|---|
| Linux | ✅ | em reformulação |
| macOS | ✅ | em reformulação |
| Windows | planejado | planejado |

## O que ele faz

- **Scan sob demanda** de arquivos e pastas, combinando hash conhecido, heurística por palavras-chave, regras YARA e entropia numa pontuação de ameaça.
- **Proteção em tempo real** nas pastas monitoradas (por padrão Downloads, Desktop e Documents), com debounce para não escanear arquivos pela metade.
- **Detecção de comportamento de ransomware**: rajadas de escrita e arquivos criados ou renomeados com extensões como `.locked` e `.encrypted`.
- **Quarentena neutralizada**: o arquivo é embaralhado, perde a permissão de execução e pode ser restaurado com verificação de integridade.
- **Monitores de processos e conexões** que apenas alertam; o AlvSafe nunca encerra processos por conta própria.
- **Diagnóstico** do ambiente com `alvsafe doctor`.

## Instalação

Requer Python 3.10 a 3.13.

```bash
git clone https://github.com/Alvaromra/AlvSafe.git
cd AlvSafe
python3 -m venv venv
source venv/bin/activate
pip install -e ".[yara]"
alvsafe doctor
```

O extra `yara` é opcional: sem ele, o scan funciona sem a camada de regras YARA.

## Uso

```bash
alvsafe scan ~/Downloads                 # escaneia e põe ameaças em quarentena
alvsafe scan ~/Downloads --no-quarantine # só relata
alvsafe scan arquivo.sh --json           # saída para scripts

alvsafe watch                            # proteção em tempo real (Ctrl+C encerra)
alvsafe watch --processes --network --notify

alvsafe quarantine list
alvsafe quarantine restore <ID> [--to DESTINO]
alvsafe quarantine delete <ID>

alvsafe logs -n 50
alvsafe config init                      # cria settings.json com os padrões
alvsafe config show
alvsafe doctor
```

Códigos de saída: `0` sem problemas, `1` ameaça encontrada (ou falha no `doctor`), `2` erro.

No macOS, o monitor de conexões exige administrador (`sudo`), e o terminal pode precisar de permissão para acessar Downloads, Desktop e Documents em Ajustes do Sistema > Privacidade e Segurança > Arquivos e Pastas. O `alvsafe doctor` aponta os dois casos.

## Onde ficam os dados

| Sistema | Dados (log, quarentena, regras extras) | Configuração |
|---|---|---|
| macOS | `~/Library/Application Support/AlvSafe` | mesma pasta |
| Linux | `~/.local/share/alvsafe` | `~/.config/alvsafe/settings.json` |

A variável `ALVSAFE_HOME` redireciona tudo para outra pasta. Hashes extras vão em `malware_hashes.txt` e regras extras em `rules/*.yar`, dentro da pasta de dados.

## Interface gráfica

A interface atual (`gui/`) é a versão anterior adaptada ao novo núcleo e está sendo reescrita. Para testá-la no Linux:

```bash
pip install -e ".[yara,gui]"
python -m gui.gui
```

## Desenvolvimento

```bash
pip install -e ".[yara,dev]"
pytest
```

Os testes usam uma pasta de dados temporária e montam o arquivo de teste EICAR em tempo de execução, sem nenhum arquivo malicioso no repositório.

```
alvsafe/
├── cli.py          linha de comando
├── doctor.py       diagnóstico do ambiente
├── config.py       settings.json com valores padrão
├── paths.py        pastas de dados por sistema
├── system.py       diferenças entre sistemas (notificações, pastas padrão)
├── events.py       barramento de eventos entre núcleo e interfaces
├── core/           scanner, quarentena, tempo real, monitores, log
└── data/           assinaturas e regras YARA do pacote
gui/                interface gráfica (em reformulação)
tests/
```

## Roadmap

- Detecção: banco de hashes SHA-256 e heurística restrita a scripts, com pontuação recalibrada
- Interface gráfica reescrita sobre o núcleo, com bandeja e notificações no macOS e no Linux
- Serviço em segundo plano (systemd e LaunchAgent) e CI em Linux e macOS
- Suporte a Windows

## Autor

**Alvaro Marcal de Araujo**, Engenharia de Redes de Comunicação (UnB)

GitHub: https://github.com/Alvaromra
