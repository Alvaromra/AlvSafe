"""As cinco telas da janela.

Cada tela é um CTkFrame que sabe se redesenhar (`refresh`) e, quando
precisa, acompanhar o que está acontecendo (`tick`, chamado pelo laço
da janela). Nenhuma delas fala com o núcleo direto: tudo passa pelo
Controller, que já entrega os dados prontos e na thread certa.
"""

import os
import time
from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk

from alvsafe import paths
from alvsafe.config import ConfigError, Settings, save_settings
from alvsafe.gui import theme as t

MAX_LINES = 500


def elide(caminho, limite=58):
    """Encurta o caminho pelo meio, preservando início e nome do arquivo."""
    texto = str(caminho)
    if len(texto) <= limite:
        return texto
    metade = (limite - 3) // 2
    return f"{texto[:metade]}...{texto[-metade:]}"


def humano(tamanho):
    for unidade in ("B", "KB", "MB", "GB"):
        if tamanho < 1024 or unidade == "GB":
            return f"{tamanho:.0f} {unidade}" if unidade == "B" else f"{tamanho:.1f} {unidade}"
        tamanho /= 1024


def quando(iso):
    try:
        momento = time.mktime(time.strptime(iso, "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return iso
    minutos = (time.time() - momento) / 60
    if minutos < 1:
        return "agora"
    if minutos < 60:
        return f"há {minutos:.0f} min"
    if minutos < 1440:
        return f"há {minutos / 60:.0f} h"
    return time.strftime("%d/%m %H:%M", time.localtime(momento))


def card(parent, **kwargs):
    kwargs.setdefault("fg_color", t.SURFACE)
    kwargs.setdefault("corner_radius", t.RADIUS)
    kwargs.setdefault("border_width", 1)
    kwargs.setdefault("border_color", t.BORDER)
    return ctk.CTkFrame(parent, **kwargs)


def label(parent, texto, size=t.SIZE_BODY, weight="normal", color=t.TEXT, mono=False, **kwargs):
    return ctk.CTkLabel(parent, text=texto, font=t.font(ctk, size, weight, mono),
                        text_color=color, **kwargs)


def primary_button(parent, texto, command, width=150):
    return ctk.CTkButton(parent, text=texto, command=command, width=width, height=34,
                         corner_radius=t.RADIUS - 2, fg_color=t.ACCENT, hover_color=t.ACCENT_HOVER,
                         text_color=("#FFFFFF", "#0C1014"), font=t.font(ctk, weight="bold"))


def ghost_button(parent, texto, command, width=120, danger=False):
    return ctk.CTkButton(parent, text=texto, command=command, width=width, height=34,
                         corner_radius=t.RADIUS - 2,
                         fg_color=t.GHOST, hover_color=t.GHOST_HOVER,
                         text_color=t.DANGER if danger else t.TEXT, font=t.font(ctk))


def console(parent, height=200):
    box = ctk.CTkTextbox(parent, height=height, wrap="none", fg_color=t.SURFACE_2,
                         border_width=0, corner_radius=t.RADIUS - 2,
                         font=t.font(ctk, t.SIZE_SMALL + 1, mono=True), text_color=t.TEXT)
    box.configure(state="disabled")
    escuro = ctk.get_appearance_mode().lower() == "dark"
    for nivel, cor in t.SEVERITY.items():
        box.tag_config(nivel, foreground=cor[1] if escuro else cor[0])
    return box


def write(box, texto, tag="info", append=True):
    box.configure(state="normal")
    if not append:
        box.delete("1.0", "end")
    box.insert("end", texto + "\n", tag)
    linhas = int(box.index("end-1c").split(".")[0])
    if linhas > MAX_LINES:
        box.delete("1.0", f"{linhas - MAX_LINES}.0")
    box.configure(state="disabled")


class View(ctk.CTkFrame):
    title = ""
    subtitle = ""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.controller = app.controller
        self.build()

    def build(self):
        pass

    def refresh(self):
        pass

    def tick(self, events):
        pass


# ---------------------------------------------------------------- painel

class DashboardView(View):
    title = "Painel"
    subtitle = "estado da proteção e verificação sob demanda"

    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Cartão de estado: a informação mais importante, legível de longe
        estado = card(self)
        estado.grid(row=0, column=0, sticky="ew")
        estado.grid_columnconfigure(1, weight=1)

        self.dot = label(estado, "●", size=22, color=t.NEUTRAL)
        self.dot.grid(row=0, column=0, rowspan=2, padx=(t.PAD, t.GAP), pady=t.PAD)

        self.estado_titulo = label(estado, "Sem proteção ativa", size=t.SIZE_TITLE, weight="bold")
        self.estado_titulo.grid(row=0, column=1, sticky="w", pady=(t.PAD, 0))

        self.estado_detalhe = label(estado, "", color=t.TEXT_MUTED, size=t.SIZE_SMALL)
        self.estado_detalhe.grid(row=1, column=1, sticky="w", pady=(0, t.PAD))

        self.estado_botao = ghost_button(estado, "Ativar", self.app.toggle_protection, width=110)
        self.estado_botao.grid(row=0, column=2, rowspan=2, padx=t.PAD)

        # Ações
        acoes = ctk.CTkFrame(self, fg_color="transparent")
        acoes.grid(row=1, column=0, sticky="ew", pady=(t.PAD, 0))

        self.scan_button = primary_button(acoes, "Escanear pasta...", self.app.choose_and_scan)
        self.scan_button.pack(side="left")
        self.downloads_button = ghost_button(acoes, "Downloads", self.scan_downloads, width=118)
        self.downloads_button.pack(side="left", padx=t.GAP)
        self.cancel_button = ghost_button(acoes, "Cancelar", self.controller.cancel_scan, width=110)
        self.cancel_button.pack(side="left")
        self.cancel_button.configure(state="disabled")

        # Progresso: só aparece durante o scan
        self.progresso_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.progresso_frame.grid_columnconfigure(0, weight=1)
        self.progress = ctk.CTkProgressBar(self.progresso_frame, height=6, corner_radius=3,
                                           progress_color=t.ACCENT)
        self.progress.grid(row=0, column=0, sticky="ew")
        self.progress.set(0)
        self.progresso_texto = label(self.progresso_frame, "", size=t.SIZE_SMALL, color=t.TEXT_MUTED)
        self.progresso_texto.grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Atividade
        atividade = card(self)
        atividade.grid(row=3, column=0, sticky="nsew", pady=(t.PAD, 0))
        atividade.grid_columnconfigure(0, weight=1)
        atividade.grid_rowconfigure(1, weight=1)
        label(atividade, "Atividade", size=t.SIZE_SMALL, color=t.TEXT_MUTED) \
            .grid(row=0, column=0, sticky="w", padx=t.PAD, pady=(t.GAP + 2, 0))
        self.activity = console(atividade)
        self.activity.grid(row=1, column=0, sticky="nsew", padx=t.PAD, pady=(4, t.PAD))

        # Números
        numeros = ctk.CTkFrame(self, fg_color="transparent")
        numeros.grid(row=4, column=0, sticky="ew", pady=(t.PAD, 0))
        for i in range(3):
            numeros.grid_columnconfigure(i, weight=1)

        self.tiles = {}
        for coluna, (chave, titulo) in enumerate(
                [("scanned", "analisados"), ("threats", "ameaças"), ("quarantine", "em quarentena")]):
            tile = card(numeros)
            tile.grid(row=0, column=coluna, sticky="ew", padx=(0 if coluna == 0 else t.GAP, 0))
            valor = label(tile, "0", size=t.SIZE_DISPLAY - 4, weight="bold")
            valor.pack(anchor="w", padx=t.PAD, pady=(t.GAP + 2, 0))
            label(tile, titulo, size=t.SIZE_SMALL, color=t.TEXT_MUTED) \
                .pack(anchor="w", padx=t.PAD, pady=(0, t.GAP + 2))
            self.tiles[chave] = valor

    def scan_downloads(self):
        destino = Path.home() / "Downloads"
        if destino.is_dir():
            self.app.start_scan(destino)
        else:
            messagebox.showinfo("Escanear", "Não encontrei a pasta Downloads.")

    def refresh(self):
        ativa = self.controller.protection_active
        pastas = self.controller.watched_folders()

        if ativa and pastas:
            nomes = ", ".join(p.name for p in pastas)
            self.dot.configure(text_color=t.ACCENT)
            self.estado_titulo.configure(text="Protegido")
            self.estado_detalhe.configure(text=f"monitorando {nomes}")
            self.estado_botao.configure(text="Desativar")
        elif ativa:
            self.dot.configure(text_color=t.DANGER)
            self.estado_titulo.configure(text="Proteção sem pastas")
            self.estado_detalhe.configure(text="nenhuma pasta acessível; veja o Diagnóstico")
            self.estado_botao.configure(text="Desativar")
        else:
            self.dot.configure(text_color=t.NEUTRAL)
            self.estado_titulo.configure(text="Sem proteção ativa")
            self.estado_detalhe.configure(text="arquivos novos não são verificados automaticamente")
            self.estado_botao.configure(text="Ativar")

        self.tiles["quarantine"].configure(text=str(len(self.controller.quarantine_entries())))

    def tick(self, events):
        for event in events:
            cor = "critical" if event.kind == "threat" else event.level
            hora = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            write(self.activity, f"{hora}  {event.message}", cor)
        if events:
            self.activity.see("end")

        self.tiles["scanned"].configure(text=str(self.controller.scanned))
        self.tiles["threats"].configure(text=str(self.controller.threats))
        self.tiles["threats"].configure(text_color=t.DANGER if self.controller.threats else t.TEXT)

        escaneando = self.controller.scanning
        self.scan_button.configure(state="disabled" if escaneando else "normal")
        self.downloads_button.configure(state="disabled" if escaneando else "normal")
        self.cancel_button.configure(state="normal" if escaneando else "disabled")

        if escaneando:
            if not self.progresso_frame.winfo_ismapped():
                self.progresso_frame.grid(row=2, column=0, sticky="ew", pady=(t.PAD, 0))
            fracao, contagem = self.controller.progress
            if fracao is None:
                self.progress.configure(mode="indeterminate")
                self.progress.start()
                detalhe = "contando arquivos..."
            else:
                self.progress.stop()
                self.progress.configure(mode="determinate")
                self.progress.set(fracao)
                atual = elide(self.controller.current, 46)
                detalhe = f"{contagem}   {self.controller.elapsed:.0f}s   {atual}"
            self.progresso_texto.configure(text=detalhe)
        elif self.progresso_frame.winfo_ismapped():
            self.progress.stop()
            self.progresso_frame.grid_forget()


# ------------------------------------------------------------ quarentena

class QuarantineView(View):
    title = "Quarentena"
    subtitle = "arquivos isolados, embaralhados e sem permissão de execução"

    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.lista = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.lista.grid(row=0, column=0, sticky="nsew")
        self.lista.grid_columnconfigure(0, weight=1)

    def refresh(self):
        for widget in self.lista.winfo_children():
            widget.destroy()

        entradas = self.controller.quarantine_entries()
        if not entradas:
            vazio = card(self.lista)
            vazio.grid(row=0, column=0, sticky="ew")
            label(vazio, "Nada em quarentena", size=t.SIZE_TITLE, weight="bold") \
                .pack(anchor="w", padx=t.PAD, pady=(t.PAD, 2))
            label(vazio, "Arquivos isolados por um scan ou pela proteção em tempo real aparecem aqui.",
                  color=t.TEXT_MUTED, size=t.SIZE_SMALL).pack(anchor="w", padx=t.PAD, pady=(0, t.PAD))
            return

        for linha, entrada in enumerate(reversed(entradas)):
            item = card(self.lista)
            item.grid(row=linha, column=0, sticky="ew", pady=(0, t.GAP))
            item.grid_columnconfigure(0, weight=1)

            cabecalho = ctk.CTkFrame(item, fg_color="transparent")
            cabecalho.grid(row=0, column=0, sticky="ew", padx=t.PAD, pady=(t.GAP + 2, 0))
            label(cabecalho, "●", color=t.DANGER, size=t.SIZE_SMALL).pack(side="left", padx=(0, 6))
            label(cabecalho, Path(entrada.original_path).name, weight="bold").pack(side="left")
            label(cabecalho, f"  {humano(entrada.size)}  ·  {quando(entrada.quarantined_at)}",
                  size=t.SIZE_SMALL, color=t.TEXT_MUTED).pack(side="left")

            label(item, elide(Path(entrada.original_path).parent, 72),
                  size=t.SIZE_SMALL, color=t.TEXT_FAINT, mono=True, anchor="w") \
                .grid(row=1, column=0, sticky="ew", padx=t.PAD)
            label(item, elide(entrada.reason or "sem motivo registrado", 86),
                  size=t.SIZE_SMALL, color=t.TEXT_MUTED, anchor="w") \
                .grid(row=2, column=0, sticky="ew", padx=t.PAD, pady=(2, t.GAP + 2))

            botoes = ctk.CTkFrame(item, fg_color="transparent")
            botoes.grid(row=0, column=1, rowspan=3, padx=(0, t.PAD))
            ghost_button(botoes, "Restaurar", lambda e=entrada: self.restore(e), width=96) \
                .pack(side="left", padx=(0, 6))
            ghost_button(botoes, "Apagar", lambda e=entrada: self.delete(e), width=84, danger=True) \
                .pack(side="left")

    def restore(self, entrada):
        try:
            self.controller.restore(entrada.id)
        except FileExistsError:
            if not messagebox.askyesno("Restaurar", f"{entrada.original_path}\n\njá existe. Sobrescrever?"):
                return
            self.controller.restore(entrada.id, overwrite=True)
        except (KeyError, ValueError, OSError) as e:
            messagebox.showerror("Restaurar", str(e))
        self.refresh()
        self.app.flash(f"Restaurado: {Path(entrada.original_path).name}")

    def delete(self, entrada):
        nome = Path(entrada.original_path).name
        if messagebox.askyesno("Apagar", f"Apagar {nome} definitivamente?\nNão há como desfazer."):
            self.controller.delete(entrada.id)
            self.refresh()
            self.app.flash(f"Apagado: {nome}")


# -------------------------------------------------------------- registro

class LogView(View):
    title = "Registro"
    subtitle = "histórico gravado no banco de eventos"

    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        barra = ctk.CTkFrame(self, fg_color="transparent")
        barra.grid(row=0, column=0, sticky="ew", pady=(0, t.GAP))

        self.filtro = ctk.CTkSegmentedButton(
            barra, values=["Tudo", "Só ameaças"], command=lambda _: self.refresh(),
            font=t.font(ctk, t.SIZE_SMALL), selected_color=t.ACCENT,
            selected_hover_color=t.ACCENT_HOVER)
        self.filtro.set("Tudo")
        self.filtro.pack(side="left")
        ghost_button(barra, "Atualizar", self.refresh, width=104).pack(side="left", padx=t.GAP)

        self.box = console(self, height=420)
        self.box.grid(row=1, column=0, sticky="nsew")

    def refresh(self):
        so_ameacas = self.filtro.get() == "Só ameaças"
        linhas = self.controller.recent_logs(300)
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.configure(state="disabled")

        mostrados = 0
        for _, evento, detalhe, carimbo in reversed(linhas):
            if so_ameacas and evento in ("QUARENTENA", "SAFE"):
                continue
            if so_ameacas and evento not in ("MALWARE", "DANGEROUS", "RANSOMWARE"):
                continue
            tag = "critical" if evento in ("MALWARE", "DANGEROUS", "RANSOMWARE") else "info"
            write(self.box, f"{carimbo}  {evento:<14} {detalhe}", tag)
            mostrados += 1

        if not mostrados:
            write(self.box, "Nenhum evento registrado ainda.", "debug")
        self.box.see("end")


# ----------------------------------------------------------- diagnóstico

class DoctorView(View):
    title = "Diagnóstico"
    subtitle = "o que funciona neste computador e o que precisa de ajuste"

    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        barra = ctk.CTkFrame(self, fg_color="transparent")
        barra.grid(row=0, column=0, sticky="ew", pady=(0, t.GAP))
        self.botao = primary_button(barra, "Rodar diagnóstico", self.run, width=170)
        self.botao.pack(side="left")
        self.status = label(barra, "", color=t.TEXT_MUTED, size=t.SIZE_SMALL)
        self.status.pack(side="left", padx=t.PAD)

        self.lista = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.lista.grid(row=1, column=0, sticky="nsew")
        self.lista.grid_columnconfigure(0, weight=1)

    def run(self):
        self.botao.configure(state="disabled")
        self.status.configure(text="rodando...")
        self.controller.run_doctor()

    def show(self, checagens):
        for widget in self.lista.winfo_children():
            widget.destroy()

        cores = {"ok": t.ACCENT, "aviso": t.WARNING, "falha": t.DANGER}
        for linha, checagem in enumerate(checagens):
            item = card(self.lista)
            item.grid(row=linha, column=0, sticky="ew", pady=(0, 4))
            item.grid_columnconfigure(1, weight=1)

            label(item, "●", color=cores[checagem.status], size=t.SIZE_SMALL) \
                .grid(row=0, column=0, rowspan=2, padx=(t.PAD, t.GAP), pady=6)
            label(item, checagem.name, weight="bold").grid(row=0, column=1, sticky="w", pady=(6, 0))
            label(item, checagem.detail, size=t.SIZE_SMALL, color=t.TEXT_MUTED, anchor="w",
                  justify="left").grid(row=1, column=1, sticky="ew", pady=(0, 6))
            if checagem.hint and checagem.status != "ok":
                label(item, checagem.hint, size=t.SIZE_SMALL, color=cores[checagem.status],
                      anchor="w", justify="left", wraplength=620) \
                    .grid(row=2, column=1, sticky="ew", padx=(0, t.PAD), pady=(0, t.GAP))

        falhas = sum(1 for c in checagens if c.status == "falha")
        avisos = sum(1 for c in checagens if c.status == "aviso")
        self.status.configure(text=f"{len(checagens)} itens · {falhas} falhas · {avisos} avisos")
        self.botao.configure(state="normal")


# --------------------------------------------------------------- ajustes

class SettingsView(View):
    title = "Ajustes"
    subtitle = "o que é verificado, como e onde"

    CAMPOS = [
        ("realtime_protection", "Ativar proteção em tempo real ao abrir"),
        ("heuristic_detection", "Detecção heurística em scripts"),
        ("yara_detection", "Regras YARA"),
        ("quarantine_enabled", "Quarentena automática"),
        ("virustotal", "Consultar VirusTotal (exige VT_API_KEY)"),
    ]

    def build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        area = ctk.CTkScrollableFrame(self, fg_color="transparent")
        area.grid(row=0, column=0, sticky="nsew")
        area.grid_columnconfigure(0, weight=1)

        deteccao = card(area)
        deteccao.grid(row=0, column=0, sticky="ew")
        label(deteccao, "Detecção", size=t.SIZE_SMALL, color=t.TEXT_MUTED) \
            .pack(anchor="w", padx=t.PAD, pady=(t.GAP + 2, t.GAP))

        self.switches = {}
        for campo, texto in self.CAMPOS:
            sw = ctk.CTkSwitch(deteccao, text=texto, font=t.font(ctk), progress_color=t.ACCENT)
            sw.select() if getattr(self.controller.settings, campo) else sw.deselect()
            sw.pack(anchor="w", padx=t.PAD, pady=6)
            self.switches[campo] = sw

        limite = ctk.CTkFrame(deteccao, fg_color="transparent")
        limite.pack(anchor="w", padx=t.PAD, pady=(t.GAP, 0))
        label(limite, "Pontuação para quarentena").pack(side="left", padx=(0, t.GAP))
        self.threshold = ctk.CTkEntry(limite, width=64, height=30, font=t.font(ctk))
        self.threshold.insert(0, str(self.controller.settings.threat_threshold))
        self.threshold.pack(side="left")
        label(limite, "  60 é o padrão: nenhum indício fraco sozinho chega lá",
              size=t.SIZE_SMALL, color=t.TEXT_FAINT).pack(side="left")

        self.notificacoes = ctk.CTkSwitch(deteccao, text="Notificações do sistema",
                                          font=t.font(ctk), progress_color=t.ACCENT)
        self.notificacoes.select() if self.controller.notifications else None
        self.notificacoes.pack(anchor="w", padx=t.PAD, pady=(t.PAD, t.GAP))

        acoes = ctk.CTkFrame(deteccao, fg_color="transparent")
        acoes.pack(anchor="w", padx=t.PAD, pady=(0, t.PAD))
        primary_button(acoes, "Salvar", self.save, width=110).pack(side="left")
        ghost_button(acoes, "Restaurar padrões", self.reset, width=160).pack(side="left", padx=t.GAP)
        self.feedback = label(acoes, "", size=t.SIZE_SMALL, color=t.ACCENT)
        self.feedback.pack(side="left", padx=t.GAP)

        servico = card(area)
        servico.grid(row=1, column=0, sticky="ew", pady=(t.PAD, 0))
        label(servico, "Serviço em segundo plano", size=t.SIZE_SMALL, color=t.TEXT_MUTED) \
            .pack(anchor="w", padx=t.PAD, pady=(t.GAP + 2, 4))
        self.servico_estado = label(servico, "", color=t.TEXT_MUTED, size=t.SIZE_SMALL)
        self.servico_estado.pack(anchor="w", padx=t.PAD)
        label(servico, "Com o serviço instalado, a proteção continua rodando com a janela fechada.",
              size=t.SIZE_SMALL, color=t.TEXT_FAINT).pack(anchor="w", padx=t.PAD, pady=(2, t.GAP))
        botoes = ctk.CTkFrame(servico, fg_color="transparent")
        botoes.pack(anchor="w", padx=t.PAD, pady=(0, t.PAD))
        ghost_button(botoes, "Instalar", lambda: self.service("install"), width=104).pack(side="left")
        ghost_button(botoes, "Parar", lambda: self.service("stop"), width=90).pack(side="left", padx=t.GAP)
        ghost_button(botoes, "Remover", lambda: self.service("uninstall"),
                     width=104, danger=True).pack(side="left")

        caminhos = card(area)
        caminhos.grid(row=2, column=0, sticky="ew", pady=(t.PAD, 0))
        label(caminhos, "Arquivos", size=t.SIZE_SMALL, color=t.TEXT_MUTED) \
            .pack(anchor="w", padx=t.PAD, pady=(t.GAP + 2, 4))
        for titulo, caminho in (("configuração", paths.config_file()),
                                ("dados e quarentena", paths.data_dir()),
                                ("assinaturas do usuário", paths.user_signatures_file())):
            label(caminhos, f"{titulo}: {caminho}", size=t.SIZE_SMALL, color=t.TEXT_FAINT,
                  mono=True, anchor="w").pack(anchor="w", padx=t.PAD, pady=1)
        label(caminhos, "", size=t.SIZE_SMALL).pack(pady=2)

    def refresh(self):
        estado = self.controller.service_status()
        if estado is None:
            self.servico_estado.configure(text=f"sem suporte em {os.name}", text_color=t.TEXT_MUTED)
            return
        nome, ativo, detalhe = estado
        self.servico_estado.configure(text=f"{nome}: {detalhe}",
                                      text_color=t.ACCENT if ativo else t.TEXT_MUTED)

    def save(self):
        settings = self.controller.settings
        for campo, switch in self.switches.items():
            setattr(settings, campo, bool(switch.get()))
        try:
            valor = int(self.threshold.get())
            if not 1 <= valor <= 200:
                raise ValueError
        except ValueError:
            self.feedback.configure(text="pontuação deve ser um número de 1 a 200", text_color=t.DANGER)
            return
        settings.threat_threshold = valor
        self.controller.notifications = bool(self.notificacoes.get())

        try:
            save_settings(settings)
        except (OSError, ConfigError) as e:
            self.feedback.configure(text=str(e), text_color=t.DANGER)
            return
        self.feedback.configure(text="salvo", text_color=t.ACCENT)
        self.after(2500, lambda: self.feedback.configure(text=""))

    def reset(self):
        if not messagebox.askyesno("Ajustes", "Voltar todas as opções ao padrão?"):
            return
        padrao = Settings()
        for campo, _ in self.CAMPOS:
            switch = self.switches[campo]
            switch.select() if getattr(padrao, campo) else switch.deselect()
        self.threshold.delete(0, "end")
        self.threshold.insert(0, str(padrao.threat_threshold))
        self.save()

    def service(self, acao):
        from alvsafe.service import ServiceError, get_manager

        manager = get_manager()
        if manager is None:
            messagebox.showinfo("Serviço", "Sem suporte a serviço neste sistema.")
            return
        try:
            getattr(manager, acao)()
        except (ServiceError, OSError) as e:
            messagebox.showerror("Serviço", str(e))
        self.refresh()


VIEWS = [DashboardView, QuarantineView, LogView, DoctorView, SettingsView]
