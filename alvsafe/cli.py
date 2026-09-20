"""Interface de linha de comando: `alvsafe <comando>`.

Códigos de saída:
  0  tudo certo
  1  ameaça encontrada (scan) ou falha no diagnóstico (doctor)
  2  erro de uso ou de execução
"""

import argparse
import json
import sys
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from alvsafe import __version__, paths, system
from alvsafe.config import ConfigError, Settings, load_settings, save_settings
from alvsafe.events import CRITICAL, DEBUG, WARNING, EventBus

console = Console()
err = Console(stderr=True)

_STYLE = {CRITICAL: "bold red", WARNING: "yellow", DEBUG: "dim"}


def _printer(verbose):
    def show(event):
        if event.level == DEBUG and not verbose:
            return
        line = Text()
        line.append(time.strftime("%H:%M:%S ", time.localtime(event.timestamp)), style="dim")
        line.append(f"[{event.data.get('category') or event.kind}] ", style=_STYLE.get(event.level, "bold"))
        line.append(event.message)  # Text puro: nomes de arquivo com [] não viram markup
        console.print(line)
    return show


class _FileLogger:
    """Escreve os eventos num arquivo, com rotação simples por tamanho."""

    def __init__(self, path, max_bytes=5 * 1024 * 1024):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes

    def __call__(self, event):
        if event.level == DEBUG:
            return
        self._rotate()   # antes de escrever, para o arquivo atual nunca sumir
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.timestamp))
        tag = event.data.get("category") or event.kind
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"{stamp} [{tag}] {event.message}\n")

    def _rotate(self):
        try:
            if self.path.stat().st_size > self.max_bytes:
                self.path.replace(self.path.with_suffix(self.path.suffix + ".1"))
        except OSError:
            pass


def _notifier(event):
    if event.kind == "threat" or (event.kind == "alert" and event.level in (WARNING, CRITICAL)):
        system.notify("AlvSafe", event.message)


def _settings(args):
    return load_settings(args.config)  # ConfigError é tratado em main()


# ---------- comandos ----------

def cmd_scan(args):
    from alvsafe.core.scanner import Scanner

    settings = _settings(args)
    bus = EventBus()
    if not args.json:
        bus.subscribe(_printer(args.verbose))
    scanner = Scanner(settings, bus=bus, auto_quarantine=not args.no_quarantine)

    results = []
    try:
        for target in args.paths:
            try:
                results.append((target, scanner.scan_path(target, workers=args.workers)))
            except FileNotFoundError:
                err.print(f"[red]Não encontrado:[/red] {target}")
                return 2
    except KeyboardInterrupt:
        scanner.cancel()
        err.print("\n[yellow]Scan interrompido[/yellow]")
        return 2

    threats = [t for _, s in results for t in s.threats]

    if args.json:
        print(json.dumps({
            "scanned": sum(s.scanned for _, s in results),
            "skipped": sum(s.skipped for _, s in results),
            "errors": sum(s.errors for _, s in results),
            "threats": [
                {"path": t.path, "score": t.score, "classification": t.classification,
                 "reasons": t.reasons, "sha256": t.sha256, "quarantine_id": t.quarantine_id}
                for t in threats
            ],
        }, indent=2, ensure_ascii=False))
    elif threats:
        table = Table(title="Ameaças encontradas")
        table.add_column("Arquivo", overflow="fold")
        table.add_column("Score", justify="right")
        table.add_column("Motivos")
        table.add_column("Quarentena")
        for t in threats:
            table.add_row(escape(t.path), f"{t.score} {t.classification}", escape("\n".join(t.reasons)),
                          t.quarantine_id or "não")
        console.print(table)
    else:
        console.print("[green]Nenhuma ameaça encontrada.[/green]")

    return 1 if threats else 0


def cmd_watch(args):
    from alvsafe.core.network import monitor_connections, monitor_web
    from alvsafe.core.processes import monitor_processes
    from alvsafe.core.realtime import Watcher

    settings = _settings(args)
    bus = EventBus()
    bus.subscribe(_printer(args.verbose))
    if args.notify:
        bus.subscribe(_notifier)

    if args.log:
        bus.subscribe(_FileLogger(args.log))

    watcher = Watcher(settings, bus=bus, folders=args.folder or None)
    watcher.start()

    if not watcher.watching:
        err.print("[red]Nenhuma pasta pôde ser monitorada.[/red] Rode `alvsafe doctor`.")
        watcher.stop()
        return 2

    monitors = []
    if args.processes:
        monitors.append(monitor_processes)
    if args.network:
        monitors += [monitor_connections, monitor_web]

    def poll():
        while not watcher.sleep(args.interval):
            for monitor in monitors:
                monitor(bus=bus)

    if monitors:
        for monitor in monitors:
            monitor(bus=bus)
        threading.Thread(target=poll, daemon=True).start()

    console.print("[dim]Ctrl+C para encerrar[/dim]")
    watcher.wait()
    console.print("Proteção encerrada.")
    return 0


def cmd_quarantine(args):
    from alvsafe.core.quarantine import Quarantine

    q = Quarantine()

    if args.action == "list":
        entries = q.list()
        if not entries:
            console.print("Quarentena vazia.")
            return 0
        table = Table()
        table.add_column("ID", no_wrap=True)  # inteiro, para poder copiar
        table.add_column("Arquivo original", overflow="fold")
        for col in ("Tamanho", "Data", "Motivo"):
            table.add_column(col)
        for e in entries:
            table.add_row(e.id, escape(e.original_path), f"{e.size:,} B", e.quarantined_at, escape(e.reason))
        console.print(table)
        return 0

    try:
        if args.action == "restore":
            dest = q.restore(args.id, destination=args.to, overwrite=args.force)
            console.print(f"Restaurado em [bold]{escape(str(dest))}[/bold]")
        elif args.action == "delete":
            q.delete(args.id)
            console.print(f"Removido da quarentena: {args.id}")
    except KeyError:
        err.print(f"[red]ID não encontrado:[/red] {args.id}")
        return 2
    except FileExistsError as e:
        err.print(f"[red]Já existe:[/red] {e} (use --force para sobrescrever ou --to para outro destino)")
        return 2
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        return 2
    return 0


def cmd_hash(args):
    """Imprime o SHA-256 no formato do arquivo de assinaturas."""
    from alvsafe.core.virustotal import sha256_of

    code = 0
    for target in args.paths:
        path = Path(target).expanduser()
        try:
            print(f"{sha256_of(path)}  # {path.name}")
        except OSError as e:
            err.print(f"[red]{escape(str(e))}[/red]")
            code = 2
    if code == 0 and not args.quiet:
        console.print(f"[dim]Acrescente ao arquivo de assinaturas: {paths.user_signatures_file()}[/dim]")
    return code


def cmd_logs(args):
    from alvsafe.core.eventlog import recent

    rows = recent(args.n)
    if not rows:
        console.print("Nenhum evento registrado.")
        return 0
    table = Table()
    for col in ("Data", "Evento", "Detalhe"):
        table.add_column(col)
    for _, event, detail, stamp in reversed(rows):
        table.add_row(stamp, escape(str(event)), escape(str(detail)))
    console.print(table)
    return 0


def cmd_doctor(args):
    from alvsafe.doctor import FAIL, OK, run_checks

    icons = {OK: "[green]✔[/green]", "aviso": "[yellow]![/yellow]", FAIL: "[red]✘[/red]"}
    checks = run_checks()
    for c in checks:
        console.print(f"{icons[c.status]} [bold]{c.name}[/bold]: {c.detail}", highlight=False)
        if c.hint and c.status != OK:
            console.print(f"   [dim]→ {c.hint}[/dim]", highlight=False)
    return 1 if any(c.status == FAIL for c in checks) else 0


def cmd_service(args):
    from alvsafe.service import ServiceError, get_manager

    manager = get_manager()
    if manager is None:
        err.print(f"[red]Sem suporte a serviço em {system.os_name()}.[/red] "
                  "Use `alvsafe watch` em segundo plano.")
        return 2

    try:
        if args.action == "install":
            unit = manager.install()
            console.print(f"Serviço instalado ({manager.name}): {unit}")
            console.print(f"[dim]Log: {manager.log_file}[/dim]")
            if system.os_name() == "linux":
                console.print("[dim]Para rodar sem sessão aberta: "
                              "loginctl enable-linger $USER[/dim]")
        elif args.action == "uninstall":
            manager.uninstall()
            console.print("Serviço removido.")
        elif args.action == "start":
            manager.start()
            console.print("Serviço iniciado.")
        elif args.action == "stop":
            manager.stop()
            console.print("Serviço parado.")
        elif args.action == "status":
            ativo, detalhe = manager.status()
            cor = "green" if ativo else "yellow"
            console.print(f"{manager.name}: [{cor}]{escape(detalhe)}[/{cor}]")
            console.print(f"[dim]Unidade: {manager.unit_path}[/dim]")
            return 0 if ativo else 1
        elif args.action == "logs":
            linhas = manager.logs(args.n)
            console.print("\n".join(escape(linha) for linha in linhas) or "Sem registros do serviço.")
    except ServiceError as e:
        err.print(f"[red]{escape(str(e))}[/red]")
        return 2
    except OSError as e:
        err.print(f"[red]{escape(str(e))}[/red]")
        return 2
    return 0


def cmd_config(args):
    path = Path(args.config) if args.config else paths.config_file()
    if args.action == "path":
        print(path)
    elif args.action == "show":
        print(json.dumps(_settings(args).to_dict(), indent=4, ensure_ascii=False))
    elif args.action == "init":
        if path.exists() and not args.force:
            err.print(f"[red]Já existe:[/red] {path} (use --force para sobrescrever)")
            return 2
        save_settings(Settings(), path)
        console.print(f"Configuração criada em {path}")
    return 0


# ---------- parser ----------

def build_parser():
    parser = argparse.ArgumentParser(prog="alvsafe", description="AlvSafe: antivírus em Python")
    parser.add_argument("--version", action="version", version=f"alvsafe {__version__}")
    parser.add_argument("--config", help="caminho de um settings.json alternativo")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="escaneia arquivos ou pastas")
    p.add_argument("paths", nargs="+", help="arquivos ou pastas")
    p.add_argument("--no-quarantine", action="store_true", help="só relata, não move nada")
    p.add_argument("--workers", type=int, help="threads de scan (padrão: automático)")
    p.add_argument("--json", action="store_true", help="saída em JSON")
    p.add_argument("-v", "--verbose", action="store_true", help="mostra cada arquivo analisado")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("watch", help="proteção em tempo real")
    p.add_argument("--folder", action="append", help="pasta a monitorar (pode repetir)")
    p.add_argument("--processes", action="store_true", help="também monitora processos")
    p.add_argument("--network", action="store_true", help="também monitora conexões")
    p.add_argument("--interval", type=float, default=10, help="segundos entre checagens de processos/rede")
    p.add_argument("--notify", action="store_true", help="notificações do sistema")
    p.add_argument("--log", help="também grava os eventos neste arquivo (rotaciona em 5 MB)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("quarantine", help="gerencia a quarentena")
    qs = p.add_subparsers(dest="action", required=True)
    qs.add_parser("list", help="lista os arquivos em quarentena")
    r = qs.add_parser("restore", help="restaura um arquivo")
    r.add_argument("id")
    r.add_argument("--to", help="destino (padrão: caminho original)")
    r.add_argument("--force", action="store_true", help="sobrescreve se já existir")
    d = qs.add_parser("delete", help="apaga definitivamente")
    d.add_argument("id")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("hash", help="SHA-256 de arquivos, no formato do banco de assinaturas")
    p.add_argument("paths", nargs="+")
    p.add_argument("-q", "--quiet", action="store_true", help="só os hashes")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("logs", help="últimos eventos registrados")
    p.add_argument("-n", type=int, default=20, help="quantidade (padrão: 20)")
    p.set_defaults(func=cmd_logs)

    p = sub.add_parser("doctor", help="diagnóstico do ambiente")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("service", help="proteção em segundo plano (launchd/systemd)")
    p.add_argument("action", choices=["install", "uninstall", "start", "stop", "status", "logs"])
    p.add_argument("-n", type=int, default=30, help="linhas em `service logs`")
    p.set_defaults(func=cmd_service)

    p = sub.add_parser("config", help="configuração")
    p.add_argument("action", choices=["show", "path", "init"])
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_config)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as e:
        err.print("[red]Configuração inválida:[/red]", escape(str(e)))
        return 2
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
