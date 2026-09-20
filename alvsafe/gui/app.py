"""Janela principal do AlvSafe.

A estrutura é a de um app de monitoramento: navegação fixa à esquerda,
uma tela por vez à direita e uma barra de estado embaixo. O painel
responde a "estou protegido agora?" antes de qualquer outra coisa.

Regra que vale para o arquivo inteiro: widget só é tocado na thread
principal. Tudo que vem do núcleo chega pela fila do Controller, lida
por `_pump()`, e nenhum callback de thread mexe na tela diretamente.
"""

import argparse
import sys
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from alvsafe import __version__
from alvsafe.events import DEBUG
from alvsafe.gui import theme as t
from alvsafe.gui.controller import Controller
from alvsafe.gui.views import VIEWS, label

REFRESH_MS = 200


class AlvSafeApp(ctk.CTk):

    def __init__(self, controller):
        super().__init__()
        self.controller = controller

        self.title(f"AlvSafe {__version__}")
        self.geometry("1080x720")
        self.minsize(900, 620)
        self.configure(fg_color=t.BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.views = {}
        self.nav_buttons = {}
        self.current = None

        self._build_sidebar()
        self._build_main()
        self._bind_shortcuts()

        self.show(VIEWS[0].title)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._pump_id = self.after(REFRESH_MS, self._pump)

    # ------------------------------------------------------------------
    # Estrutura
    # ------------------------------------------------------------------

    def _build_sidebar(self):
        side = ctk.CTkFrame(self, width=t.SIDEBAR_WIDTH, corner_radius=0, fg_color=t.SIDEBAR)
        side.grid(row=0, column=0, rowspan=2, sticky="nsew")
        side.grid_propagate(False)
        side.grid_rowconfigure(2, weight=1)

        marca = ctk.CTkFrame(side, fg_color="transparent")
        marca.grid(row=0, column=0, sticky="ew", padx=t.PAD, pady=(t.PAD_LG, t.PAD))
        label(marca, "AlvSafe", size=t.SIZE_DISPLAY - 4, weight="bold").pack(anchor="w")
        label(marca, "proteção de endpoint", size=t.SIZE_SMALL, color=t.TEXT_FAINT).pack(anchor="w")

        nav = ctk.CTkFrame(side, fg_color="transparent")
        nav.grid(row=1, column=0, sticky="ew", padx=t.GAP)
        for view in VIEWS:
            botao = ctk.CTkButton(
                nav, text=view.title, anchor="w", height=36, corner_radius=t.RADIUS - 2,
                fg_color="transparent", hover_color=t.GHOST_HOVER, text_color=t.TEXT_MUTED,
                font=t.font(ctk), command=lambda titulo=view.title: self.show(titulo))
            botao.pack(fill="x", pady=2)
            self.nav_buttons[view.title] = botao

        rodape = ctk.CTkFrame(side, fg_color="transparent")
        rodape.grid(row=3, column=0, sticky="ew", padx=t.PAD, pady=t.PAD)
        self.protection_switch = ctk.CTkSwitch(
            rodape, text="Tempo real", font=t.font(ctk), progress_color=t.ACCENT,
            command=self.toggle_protection)
        self.protection_switch.pack(anchor="w")
        self.service_label = label(rodape, "", size=t.SIZE_SMALL, color=t.TEXT_FAINT)
        self.service_label.pack(anchor="w", pady=(t.GAP, 0))

    def _build_main(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=1, sticky="new", padx=t.PAD_LG, pady=(t.PAD_LG, 0))
        header.grid_columnconfigure(0, weight=1)
        self.view_title = label(header, "", size=t.SIZE_TITLE + 3, weight="bold")
        self.view_title.grid(row=0, column=0, sticky="w")
        self.view_subtitle = label(header, "", size=t.SIZE_SMALL, color=t.TEXT_MUTED)
        self.view_subtitle.grid(row=1, column=0, sticky="w", pady=(2, 0))

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=0, column=1, sticky="nsew", padx=t.PAD_LG, pady=(t.PAD_LG + 62, 0))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        for view_cls in VIEWS:
            view = view_cls(container, self)
            view.grid(row=0, column=0, sticky="nsew")
            view.grid_remove()
            self.views[view_cls.title] = view

        status = ctk.CTkFrame(self, height=30, corner_radius=0, fg_color=t.SIDEBAR)
        status.grid(row=1, column=1, sticky="ew")
        status.grid_columnconfigure(1, weight=1)
        self.status_left = label(status, "", size=t.SIZE_SMALL, color=t.TEXT_MUTED)
        self.status_left.grid(row=0, column=0, padx=t.PAD_LG, pady=6, sticky="w")
        self.status_right = label(status, "", size=t.SIZE_SMALL, color=t.TEXT_FAINT)
        self.status_right.grid(row=0, column=2, padx=t.PAD_LG, sticky="e")

    def _bind_shortcuts(self):
        mod = "Command" if sys.platform == "darwin" else "Control"
        self.bind(f"<{mod}-o>", lambda _: self.choose_and_scan())
        self.bind(f"<{mod}-r>", lambda _: self.views[self.current].refresh())
        self.bind("<Escape>", lambda _: self.controller.cancel_scan())
        for indice, view in enumerate(VIEWS, start=1):
            self.bind(f"<{mod}-Key-{indice}>", lambda _, titulo=view.title: self.show(titulo))

    # ------------------------------------------------------------------
    # Navegação
    # ------------------------------------------------------------------

    def show(self, titulo):
        if self.current == titulo:
            return
        if self.current:
            self.views[self.current].grid_remove()
            self.nav_buttons[self.current].configure(fg_color="transparent", text_color=t.TEXT_MUTED)

        self.current = titulo
        view = self.views[titulo]
        view.grid()
        view.refresh()
        self.nav_buttons[titulo].configure(fg_color=t.SURFACE, text_color=t.TEXT)
        self.view_title.configure(text=view.title)
        self.view_subtitle.configure(text=view.subtitle)

    def flash(self, mensagem):
        """Mensagem passageira na barra de estado."""
        self.status_right.configure(text=mensagem)
        self.after(4000, lambda: self.status_right.configure(text=""))

    # ------------------------------------------------------------------
    # Laço de atualização
    # ------------------------------------------------------------------

    def _pump(self):
        eventos = [e for e in self.controller.drain() if e.level != DEBUG]
        painel = self.views[VIEWS[0].title]
        painel.tick(eventos)

        if any(e.kind == "quarantine" for e in eventos) and self.current == "Quarentena":
            self.views["Quarentena"].refresh()

        for tipo, valor in self.controller.drain_results():
            if tipo == "scan":
                self._scan_done(valor)
            elif tipo == "doctor":
                self.views["Diagnóstico"].show(valor)

        self._update_status()
        self._pump_id = self.after(REFRESH_MS, self._pump)

    def _update_status(self):
        if self.controller.scanning:
            _, contagem = self.controller.progress
            self.status_left.configure(text=f"escaneando · {contagem}", text_color=t.TEXT)
        elif self.controller.protection_active and self.controller.watched_folders():
            self.status_left.configure(text="proteção em tempo real ativa", text_color=t.ACCENT)
        else:
            self.status_left.configure(text="ocioso", text_color=t.TEXT_MUTED)

        if self.controller.dropped:
            self.status_right.configure(text=f"{self.controller.dropped} eventos descartados")

    def _scan_done(self, summary):
        painel = self.views[VIEWS[0].title]
        painel.tick([])
        painel.refresh()
        if summary and summary.threats:
            self.show("Quarentena")
            self.views["Quarentena"].refresh()
            self.flash(f"{len(summary.threats)} ameaça(s) isolada(s)")
        elif summary:
            self.flash(f"{summary.scanned} arquivos analisados, nada encontrado")

    # ------------------------------------------------------------------
    # Ações
    # ------------------------------------------------------------------

    def choose_and_scan(self):
        pasta = filedialog.askdirectory(title="Pasta para escanear", initialdir=str(Path.home()))
        if pasta:
            self.start_scan(pasta)

    def start_scan(self, pasta):
        if not self.controller.start_scan(pasta):
            return False
        self.show(VIEWS[0].title)
        self.flash(f"escaneando {pasta}")
        return True

    def toggle_protection(self):
        """Serve ao interruptor da barra lateral e ao botão do painel."""
        if self.controller.protection_active:
            self.controller.stop_protection()
            self.protection_switch.deselect()
        else:
            self.controller.start_protection()
            self.protection_switch.select()

        self.views[VIEWS[0].title].refresh()
        self._update_status()

    def refresh_service(self):
        estado = self.controller.service_status()
        if estado is None:
            self.service_label.configure(text="")
            return
        nome, ativo, detalhe = estado
        self.service_label.configure(text=f"serviço {nome}: {detalhe}",
                                     text_color=t.ACCENT if ativo else t.TEXT_FAINT)

    def on_close(self):
        if self._pump_id:
            self.after_cancel(self._pump_id)
            self._pump_id = None
        self.controller.shutdown()
        self.destroy()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="alvsafe-gui", description="AlvSafe: interface gráfica")
    parser.add_argument("--no-notify", action="store_true", help="sem notificações do sistema")
    parser.add_argument("--scan", help="já abre escaneando esta pasta")
    parser.add_argument("--theme", choices=["dark", "light", "system"], default="system")
    args = parser.parse_args(argv)

    ctk.set_appearance_mode(args.theme)
    ctk.set_default_color_theme("blue")   # base dos widgets; as cores vêm de theme.py

    controller = Controller(notifications=not args.no_notify)
    app = AlvSafeApp(controller)
    app.refresh_service()

    if controller.settings.realtime_protection:
        app.toggle_protection()
    if args.scan:
        app.start_scan(args.scan)

    app.mainloop()
    return 0
