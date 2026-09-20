"""Janela principal do AlvSafe.

Regra que vale para o arquivo inteiro: widget só é tocado na thread
principal. Tudo que vem do núcleo chega pela fila do Controller, lida
por `_pump()`, e os callbacks de threads voltam via `self.after(0, ...)`.
"""

import argparse
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from alvsafe import __version__, paths
from alvsafe.config import ConfigError, save_settings
from alvsafe.events import CRITICAL, DEBUG, WARNING
from alvsafe.gui.controller import Controller

REFRESH_MS = 200
MAX_LINES = 600

LEVEL_COLORS = {
    CRITICAL: "#ff5c5c",
    WARNING: "#e8a33d",
    DEBUG: "#7a7a7a",
}


class AlvSafeApp(ctk.CTk):

    def __init__(self, controller):
        super().__init__()
        self.controller = controller

        self.title(f"AlvSafe {__version__}")
        self.geometry("1000x660")
        self.minsize(820, 560)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabs()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._pump_id = self.after(REFRESH_MS, self._pump)

    # ------------------------------------------------------------------
    # Construção da interface
    # ------------------------------------------------------------------

    def _build_header(self):
        header = ctk.CTkFrame(self, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(header, text="AlvSafe", font=ctk.CTkFont(size=24, weight="bold")) \
            .grid(row=0, column=0, padx=20, pady=16, sticky="w")

        self.stats_label = ctk.CTkLabel(header, text="", font=ctk.CTkFont(size=13))
        self.stats_label.grid(row=0, column=1, sticky="w")

        self.protection_switch = ctk.CTkSwitch(
            header, text="Proteção em tempo real", command=self.toggle_protection)
        self.protection_switch.grid(row=0, column=2, padx=20)

        self.status_label = ctk.CTkLabel(header, text="parada", text_color="#9a9a9a")
        self.status_label.grid(row=0, column=3, padx=(0, 20))

    def _build_tabs(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=16, pady=(8, 16))
        for name in ("Atividade", "Quarentena", "Logs", "Diagnóstico", "Configurações"):
            self.tabs.add(name)
            self.tabs.tab(name).grid_columnconfigure(0, weight=1)

        self._build_activity(self.tabs.tab("Atividade"))
        self._build_quarantine(self.tabs.tab("Quarentena"))
        self._build_logs(self.tabs.tab("Logs"))
        self._build_doctor(self.tabs.tab("Diagnóstico"))
        self._build_settings(self.tabs.tab("Configurações"))

    def _build_activity(self, tab):
        tab.grid_rowconfigure(2, weight=1)

        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, sticky="ew", pady=(8, 4))

        self.scan_button = ctk.CTkButton(bar, text="Escanear pasta", command=self.choose_and_scan)
        self.scan_button.pack(side="left", padx=(0, 8))

        self.cancel_button = ctk.CTkButton(bar, text="Cancelar", width=100,
                                           fg_color="gray30", command=self.controller.cancel_scan,
                                           state="disabled")
        self.cancel_button.pack(side="left", padx=(0, 8))

        ctk.CTkButton(bar, text="Limpar", width=90, fg_color="gray30",
                      command=self.clear_activity).pack(side="left")

        self.progress = ctk.CTkProgressBar(tab, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=4)
        self.progress.set(0)

        self.activity = self._textbox(tab)
        self.activity.grid(row=2, column=0, sticky="nsew", pady=(4, 8))

    def _build_quarantine(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        ctk.CTkButton(tab, text="Atualizar", width=110, command=self.refresh_quarantine) \
            .grid(row=0, column=0, sticky="w", pady=8)
        self.quarantine_list = ctk.CTkScrollableFrame(tab, label_text="Arquivos em quarentena")
        self.quarantine_list.grid(row=1, column=0, sticky="nsew", pady=(0, 8))
        self.quarantine_list.grid_columnconfigure(0, weight=1)

    def _build_logs(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        ctk.CTkButton(tab, text="Atualizar", width=110, command=self.refresh_logs) \
            .grid(row=0, column=0, sticky="w", pady=8)
        self.logs_box = self._textbox(tab)
        self.logs_box.grid(row=1, column=0, sticky="nsew", pady=(0, 8))

    def _build_doctor(self, tab):
        tab.grid_rowconfigure(1, weight=1)
        self.doctor_button = ctk.CTkButton(tab, text="Rodar diagnóstico", command=self.run_doctor)
        self.doctor_button.grid(row=0, column=0, sticky="w", pady=8)
        self.doctor_box = self._textbox(tab)
        self.doctor_box.grid(row=1, column=0, sticky="nsew", pady=(0, 8))

    def _build_settings(self, tab):
        settings = self.controller.settings
        self.switches = {}

        frame = ctk.CTkFrame(tab, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="ew", pady=8)

        opcoes = [
            ("realtime_protection", "Proteção em tempo real ao abrir"),
            ("heuristic_detection", "Detecção heurística"),
            ("yara_detection", "Regras YARA"),
            ("quarantine_enabled", "Quarentena automática"),
            ("virustotal", "Consultar VirusTotal (exige VT_API_KEY)"),
        ]
        for i, (campo, texto) in enumerate(opcoes):
            sw = ctk.CTkSwitch(frame, text=texto)
            sw.select() if getattr(settings, campo) else sw.deselect()
            sw.grid(row=i, column=0, sticky="w", pady=6, padx=4)
            self.switches[campo] = sw

        linha = ctk.CTkFrame(frame, fg_color="transparent")
        linha.grid(row=len(opcoes), column=0, sticky="w", pady=(12, 6), padx=4)
        ctk.CTkLabel(linha, text="Pontuação para quarentena:").pack(side="left", padx=(0, 8))
        self.threshold_entry = ctk.CTkEntry(linha, width=70)
        self.threshold_entry.insert(0, str(settings.threat_threshold))
        self.threshold_entry.pack(side="left")

        self.notifications_switch = ctk.CTkSwitch(frame, text="Notificações do sistema")
        self.notifications_switch.select() if self.controller.notifications else None
        self.notifications_switch.grid(row=len(opcoes) + 1, column=0, sticky="w", pady=6, padx=4)

        ctk.CTkButton(frame, text="Salvar", width=110, command=self.save_settings) \
            .grid(row=len(opcoes) + 2, column=0, sticky="w", pady=(14, 6), padx=4)

        ctk.CTkLabel(tab, text=f"Arquivo: {paths.config_file()}", text_color="#8a8a8a") \
            .grid(row=1, column=0, sticky="w", padx=4)

    def _textbox(self, parent):
        box = ctk.CTkTextbox(parent, wrap="none", font=ctk.CTkFont(family="monospace", size=12))
        box.configure(state="disabled")
        for level, color in LEVEL_COLORS.items():
            box.tag_config(level, foreground=color)
        return box

    # ------------------------------------------------------------------
    # Fila de eventos
    # ------------------------------------------------------------------

    def _pump(self):
        """Lê a fila do núcleo e atualiza a tela. Roda na thread principal."""
        for event in self.controller.drain():
            if event.level == DEBUG:
                continue
            self._append(self.activity, f"{event.kind}: {event.message}", event.level)
            if event.kind == "quarantine":
                self.refresh_quarantine()

        for tipo, valor in self.controller.drain_results():
            if tipo == "scan":
                self._scan_done(valor)
            elif tipo == "doctor":
                self._doctor_done(valor)

        self.stats_label.configure(
            text=f"analisados: {self.controller.scanned}   ameaças: {self.controller.threats}")

        scanning = self.controller.scanning
        self.scan_button.configure(state="disabled" if scanning else "normal")
        self.cancel_button.configure(state="normal" if scanning else "disabled")

        self._pump_id = self.after(REFRESH_MS, self._pump)

    def _append(self, box, text, level="info"):
        box.configure(state="normal")
        box.insert("end", text + "\n", level)
        linhas = int(box.index("end-1c").split(".")[0])
        if linhas > MAX_LINES:
            box.delete("1.0", f"{linhas - MAX_LINES}.0")
        box.see("end")
        box.configure(state="disabled")

    def _set(self, box, text):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("1.0", text)
        box.configure(state="disabled")

    # ------------------------------------------------------------------
    # Ações
    # ------------------------------------------------------------------

    def choose_and_scan(self):
        folder = filedialog.askdirectory(title="Pasta para escanear", initialdir=str(Path.home()))
        if folder:
            self.start_scan(folder)

    def start_scan(self, folder):
        if not self.controller.start_scan(folder):
            return False
        self.progress.start()
        return True

    def _scan_done(self, summary):
        self.progress.stop()
        self.progress.set(0)
        self.refresh_quarantine()
        if summary and summary.threats:
            self.tabs.set("Quarentena")

    def clear_activity(self):
        self._set(self.activity, "")

    def toggle_protection(self):
        if self.protection_switch.get():
            self.controller.start_protection()
            pastas = len(self.controller.watcher.watching) if self.controller.watcher else 0
            if pastas:
                self.status_label.configure(text=f"ativa ({pastas} pasta" + ("s)" if pastas > 1 else ")"), text_color="#4cc38a")
            else:
                self.status_label.configure(text="nenhuma pasta acessível", text_color="#ff5c5c")
        else:
            self.controller.stop_protection()
            self.status_label.configure(text="parada", text_color="#9a9a9a")

    def refresh_quarantine(self):
        for widget in self.quarantine_list.winfo_children():
            widget.destroy()

        entries = self.controller.quarantine_entries()
        if not entries:
            ctk.CTkLabel(self.quarantine_list, text="Nada em quarentena").grid(row=0, column=0, pady=12)
            return

        for row, entry in enumerate(entries):
            linha = ctk.CTkFrame(self.quarantine_list)
            linha.grid(row=row, column=0, sticky="ew", pady=4, padx=4)
            linha.grid_columnconfigure(0, weight=1)

            texto = f"{entry.original_path}\n{entry.quarantined_at}   {entry.reason}"
            ctk.CTkLabel(linha, text=texto, justify="left", anchor="w") \
                .grid(row=0, column=0, sticky="ew", padx=10, pady=6)
            ctk.CTkButton(linha, text="Restaurar", width=90,
                          command=lambda e=entry: self.restore(e)) \
                .grid(row=0, column=1, padx=4)
            ctk.CTkButton(linha, text="Apagar", width=80, fg_color="#a13d3d",
                          command=lambda e=entry: self.delete(e)) \
                .grid(row=0, column=2, padx=(4, 10))

    def restore(self, entry):
        try:
            self.controller.restore(entry.id)
        except FileExistsError:
            if not messagebox.askyesno("Restaurar", f"{entry.original_path} já existe. Sobrescrever?"):
                return
            self.controller.restore(entry.id, overwrite=True)
        except (KeyError, ValueError, OSError) as e:
            messagebox.showerror("Restaurar", str(e))
        self.refresh_quarantine()

    def delete(self, entry):
        if messagebox.askyesno("Apagar", f"Apagar definitivamente {entry.original_path}?"):
            self.controller.delete(entry.id)
            self.refresh_quarantine()

    def refresh_logs(self):
        linhas = [f"{stamp}  {event:<18} {detail}"
                  for _, event, detail, stamp in self.controller.recent_logs(200)]
        self._set(self.logs_box, "\n".join(linhas) or "Nenhum evento registrado.")

    def run_doctor(self):
        self.doctor_button.configure(state="disabled")
        self._set(self.doctor_box, "Rodando...")
        self.controller.run_doctor()

    def _doctor_done(self, checks):
        icones = {"ok": "✔", "aviso": "!", "falha": "✘"}
        linhas = []
        for c in checks:
            linhas.append(f"{icones[c.status]} {c.name}: {c.detail}")
            if c.hint and c.status != "ok":
                linhas.append(f"    → {c.hint}")
        self._set(self.doctor_box, "\n".join(linhas))
        self.doctor_button.configure(state="normal")

    def save_settings(self):
        settings = self.controller.settings
        for campo, switch in self.switches.items():
            setattr(settings, campo, bool(switch.get()))

        try:
            valor = int(self.threshold_entry.get())
            if not 1 <= valor <= 200:
                raise ValueError
        except ValueError:
            messagebox.showerror("Configurações", "A pontuação deve ser um número entre 1 e 200.")
            return
        settings.threat_threshold = valor
        self.controller.notifications = bool(self.notifications_switch.get())

        try:
            destino = save_settings(settings)
        except (OSError, ConfigError) as e:
            messagebox.showerror("Configurações", str(e))
            return
        messagebox.showinfo("Configurações", f"Salvo em {destino}")

    def on_close(self):
        if self._pump_id:
            self.after_cancel(self._pump_id)   # evita o laço disparar já destruído
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
    ctk.set_default_color_theme("blue")

    controller = Controller(notifications=not args.no_notify)
    app = AlvSafeApp(controller)

    if controller.settings.realtime_protection:
        app.protection_switch.select()
        app.toggle_protection()
    if args.scan:
        app.start_scan(args.scan)

    app.mainloop()
    return 0
