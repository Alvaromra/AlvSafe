# AlvSafe

[![CI](https://github.com/Alvaromra/AlvSafe/actions/workflows/ci.yml/badge.svg)](https://github.com/Alvaromra/AlvSafe/actions/workflows/ci.yml)

Antivírus e proteção de endpoint em Python, com linha de comando e interface gráfica.

Projeto educacional e de pesquisa em segurança defensiva. Não substitui um antivírus comercial.

| Sistema | CLI | Interface gráfica |
|---|---|---|
| Linux | ✅ | ✅ |
| macOS | ✅ | ✅ |
| Windows | planejado | planejado |

## O que ele faz

- **Scan sob demanda** de arquivos e pastas, combinando hash SHA-256 conhecido, heurística, regras YARA, entropia e (opcionalmente) VirusTotal numa pontuação de ameaça.
- **Proteção em tempo real** nas pastas monitoradas (por padrão Downloads, Desktop e Documents), com debounce para não escanear arquivos pela metade.
- **Detecção de comportamento de ransomware**: rajadas de escrita e arquivos criados ou renomeados com extensões como `.locked` e `.encrypted`.
- **Quarentena neutralizada**: o arquivo é embaralhado, perde a permissão de execução e pode ser restaurado com verificação de integridade.
- **Monitores de processos e conexões** que apenas alertam; o AlvSafe nunca encerra processos por conta própria.
- **Diagnóstico** do ambiente com `alvsafe doctor`.

## Como a detecção pontua

Cada indicador vale pontos conforme a confiança que merece. A soma decide: 30 é suspeito, 60 põe em quarentena, 100 é malware.

| Indicador | Pontos |
|---|---|
| Hash SHA-256 conhecido, EICAR, VirusTotal acima do limite | 100 |
| Extensão de ransomware | 70 |
| Regra YARA, APIs de injeção em processo | 60 |
| Palavra-chave forte (`powershell -enc`, `Invoke-Expression`, `mimikatz`) | 40, mais 20 por palavra extra |
| Entropia alta | 20 |
| Indício fraco (`curl`, `base64`, `wget`), teto de 20 | 10 cada |
| Execução em pasta temporária | 10 |

Dois cuidados evitam falso positivo: a heurística por palavras-chave **só roda em arquivos de texto**, porque procurar `curl` dentro de um `.exe` acusa qualquer instalador legítimo, e nenhum indicador fraco sozinho chega aos 60.

### Suas próprias assinaturas

```bash
alvsafe hash arquivo-suspeito.exe >> "$(alvsafe config path | xargs dirname)/malware_hashes.txt"
```

O arquivo aceita um SHA-256 por linha, com comentários após `#`. MD5 e SHA-1 são ignorados, e o `alvsafe doctor` avisa quando encontra algum.

### VirusTotal (opcional)

Desligado por padrão. Para ativar, exporte a chave e mude a configuração:

```bash
export VT_API_KEY="sua-chave"
alvsafe config init      # depois troque "virustotal" para true
```

Só o hash do arquivo é enviado, nunca o conteúdo, e só para arquivos que já pontuaram pelo menos 30, para não gastar a cota da API gratuita.

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

alvsafe hash arquivo.exe                 # SHA-256 no formato do banco de assinaturas
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

## Proteção em segundo plano

Para a proteção subir sozinha e continuar rodando sem terminal aberto:

```bash
alvsafe service install     # LaunchAgent no macOS, systemd de usuário no Linux
alvsafe service status
alvsafe service logs -n 50
alvsafe service stop
alvsafe service uninstall
```

É serviço de **usuário**, não de sistema: nada roda como root, e ele enxerga a sessão gráfica, o que as notificações exigem. O serviço executa `alvsafe watch --notify`, gravando em `service.log` na pasta de dados, com rotação a cada 5 MB.

No Linux, para o serviço continuar rodando mesmo sem sessão aberta:

```bash
loginctl enable-linger "$USER"
```

Se você usa o VirusTotal, lembre que a variável `VT_API_KEY` do seu shell não chega ao serviço. Coloque-a no arquivo da unidade (`Environment=` no systemd, `EnvironmentVariables` no plist), cujo caminho o `alvsafe service status` mostra.

## Interface gráfica

```bash
pip install -e ".[yara,gui]"
alvsafe-gui
```

No macOS, o Tkinter não vem com o Python do Homebrew:

```bash
brew install python-tk@3.13
```

A janela tem abas de atividade, quarentena (com restaurar e apagar), logs, diagnóstico e configurações, além de um interruptor para a proteção em tempo real. Opções: `--scan PASTA` já abre escaneando, `--no-notify` desliga as notificações e `--theme dark|light|system` escolhe o tema.

Ela usa o mesmo núcleo da CLI. Como o Tkinter só aceita mudanças de tela na thread principal, o scanner e o monitor rodam em threads e se comunicam com a janela por uma fila, lida a cada 200 ms.

Não há ícone na bandeja. O `pystray` exige a thread principal no macOS, a mesma que o Tkinter ocupa, e os dois não coexistem. Como as notificações do sistema já cobrem o aviso em segundo plano, preferi não ter uma funcionalidade que só funcionaria no Linux. Para deixar a proteção rodando sem janela, use `alvsafe watch --notify`, que na parte 6 vira serviço.

## Desenvolvimento

```bash
pip install -e ".[yara,gui,dev]"
pytest
ruff check .
```

O CI roda os testes em Ubuntu e macOS, com Python 3.11 e 3.13, mais um job com display virtual para a interface gráfica e outro de lint.

Os testes usam uma pasta de dados temporária e montam o arquivo de teste EICAR em tempo de execução, sem nenhum arquivo malicioso no repositório.

```
alvsafe/
├── cli.py          linha de comando
├── service.py      launchd (macOS) e systemd (Linux)
├── doctor.py       diagnóstico do ambiente
├── config.py       settings.json com valores padrão
├── paths.py        pastas de dados por sistema
├── system.py       diferenças entre sistemas (notificações, pastas padrão)
├── events.py       barramento de eventos entre núcleo e interfaces
├── core/           scanner, quarentena, tempo real, monitores, log
├── gui/            interface gráfica (controller.py faz a ponte com o núcleo)
└── data/           assinaturas e regras YARA do pacote
tests/
```

## Roadmap

- Suporte a Windows

## Autor

**Alvaro Marcal de Araujo**, Engenharia de Redes de Comunicação (UnB)

GitHub: https://github.com/Alvaromra
