#!/usr/bin/env python3

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import threading
import queue
import sys
import os
import datetime # For enabling Save button with timestamped default name

# --- Determine script directory for robust path handling ---
# This ensures that collector scripts are found even if the application
# is run from a different working directory.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Constants ---
APP_TITLE = "Windows Security Event Monitor"
DARK_THEME_BACKGROUND = "#2E2E2E"
GREEN_ACCENT = "#008A00"
GREEN_ACCENT_HOVER = "#00A500"
RED_ACCENT = "#A00000"
RED_ACCENT_HOVER = "#B80000"
MONO_FONT = ("Consolas", 11)

# Define script names (relative to SCRIPT_DIR)
_HOST_COLLECTOR_FILENAME = "host_collector_windows.py"
_NET_COLLECTOR_FILENAME = "network_collector_windows.py"

# Construct absolute paths to the collector scripts
HOST_COLLECTOR_SCRIPT_PATH = os.path.join(SCRIPT_DIR, _HOST_COLLECTOR_FILENAME)
NET_COLLECTOR_SCRIPT_PATH = os.path.join(SCRIPT_DIR, _NET_COLLECTOR_FILENAME)


class SecurityMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1100x750")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.host_collector_proc = None
        self.net_collector_proc = None
        self.host_output_queue = queue.Queue()
        self.net_output_queue = queue.Queue()
        self.monitoring_active = False

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=1)

        self.control_panel = ctk.CTkFrame(self, corner_radius=0)
        self.control_panel.grid(row=0, column=0, sticky="ew", padx=10, pady=(10,5))
        self.control_panel.grid_columnconfigure((0,1,2,3,4,5), weight=0)
        self.control_panel.grid_columnconfigure(6, weight=1)

        self.start_stop_button = ctk.CTkButton(
            self.control_panel, text="Start Collection",
            fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER,
            command=self.toggle_collection
        )
        self.start_stop_button.grid(row=0, column=0, padx=5, pady=10)

        self.save_host_log_button = ctk.CTkButton(self.control_panel, text="Save Host Log", command=lambda: self.save_log("host"))
        self.save_host_log_button.grid(row=0, column=1, padx=5, pady=10)
        self.save_host_log_button.configure(state=tk.DISABLED)

        self.save_net_log_button = ctk.CTkButton(self.control_panel, text="Save Network Log", command=lambda: self.save_log("network"))
        self.save_net_log_button.grid(row=0, column=2, padx=5, pady=10)
        self.save_net_log_button.configure(state=tk.DISABLED)

        self.save_both_button = ctk.CTkButton(self.control_panel, text="Save Both", command=self.save_both_logs)
        self.save_both_button.grid(row=0, column=3, padx=5, pady=10)
        self.save_both_button.configure(state=tk.DISABLED)

        self.correlate_button = ctk.CTkButton(self.control_panel, text="Correlate Data", state="disabled")
        self.correlate_button.grid(row=0, column=4, padx=5, pady=10)

        self.clear_button = ctk.CTkButton(self.control_panel, text="Clear Output", command=self.clear_all_output)
        self.clear_button.grid(row=0, column=5, padx=(5,10), pady=10)

        self.tab_view = ctk.CTkTabview(self, corner_radius=8)
        self.tab_view.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)

        self.tab_view.add("Host Events (psutil)")
        self.host_output_textbox = ctk.CTkTextbox(
            self.tab_view.tab("Host Events (psutil)"), font=MONO_FONT, wrap=tk.WORD, state=tk.DISABLED
        )
        self.host_output_textbox.pack(expand=True, fill="both")

        self.tab_view.add("Network Traffic (WinDump)")
        self.net_output_textbox = ctk.CTkTextbox(
            self.tab_view.tab("Network Traffic (WinDump)"), font=MONO_FONT, wrap=tk.WORD, state=tk.DISABLED
        )
        self.net_output_textbox.pack(expand=True, fill="both")

        self.status_bar = ctk.CTkLabel(self, text="Status: Stopped", text_color="red", anchor="w")
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=(5,10))

        self.after(100, self.process_queues)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _reader_thread(self, proc, queue_obj, tab_name_for_error_logging):
        try:
            if proc and proc.stdout:
                for line in iter(proc.stdout.readline, ''):
                    if line:
                        queue_obj.put(line)
                    if not self.monitoring_active and (proc.poll() is not None):
                        break
                proc.stdout.close()
        except Exception as e:
            error_msg = f"Error reading from {tab_name_for_error_logging}: {e}\n"
            queue_obj.put(error_msg)
        finally:
            queue_obj.put(None)

    def toggle_collection(self):
        if self.monitoring_active:
            self.stop_collection_logic()
        else:
            self.start_collection_logic()

    def start_collection_logic(self):
        if self.monitoring_active: return

        # Use absolute paths for checking and launching
        if not os.path.exists(HOST_COLLECTOR_SCRIPT_PATH):
            messagebox.showerror("Error", f"{_HOST_COLLECTOR_FILENAME} not found at {HOST_COLLECTOR_SCRIPT_PATH}")
            return
        if not os.path.exists(NET_COLLECTOR_SCRIPT_PATH):
            messagebox.showerror("Error", f"{_NET_COLLECTOR_FILENAME} not found at {NET_COLLECTOR_SCRIPT_PATH}")
            return

        self.monitoring_active = True
        self.start_stop_button.configure(text="Stop Collection", fg_color=RED_ACCENT, hover_color=RED_ACCENT_HOVER)
        self.status_bar.configure(text="Status: Running...", text_color="green")
        self.clear_all_output(show_info=False)
        self.save_host_log_button.configure(state=tk.DISABLED)
        self.save_net_log_button.configure(state=tk.DISABLED)
        self.save_both_button.configure(state=tk.DISABLED)

        try:
            self.host_collector_proc = subprocess.Popen(
                [sys.executable, HOST_COLLECTOR_SCRIPT_PATH], # Use absolute path
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            threading.Thread(target=self._reader_thread, args=(self.host_collector_proc, self.host_output_queue, "Host Collector"), daemon=True).start()

            self.net_collector_proc = subprocess.Popen(
                [sys.executable, NET_COLLECTOR_SCRIPT_PATH], # Use absolute path
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            threading.Thread(target=self._reader_thread, args=(self.net_collector_proc, self.net_output_queue, "Network Collector"), daemon=True).start()

            threading.Thread(target=self._log_subprocess_stderr, args=(self.host_collector_proc, self.host_output_queue, "Host Collector"), daemon=True).start()
            threading.Thread(target=self._log_subprocess_stderr, args=(self.net_collector_proc, self.net_output_queue, "Network Collector"), daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error Starting Collectors", str(e))
            self.stop_collection_logic(force_ui_update=True)

    def _log_subprocess_stderr(self, proc, queue_obj, name):
        if proc and proc.stderr:
            for line in iter(proc.stderr.readline, ''):
                if line:
                    queue_obj.put(f"[{name} STDERR] {line.strip()}\n")
            proc.stderr.close()

    def stop_collection_logic(self, force_ui_update=False):
        if not self.monitoring_active and not force_ui_update: return

        self.monitoring_active = False

        procs_to_terminate = []
        if self.host_collector_proc and self.host_collector_proc.poll() is None:
            procs_to_terminate.append(self.host_collector_proc)
        if self.net_collector_proc and self.net_collector_proc.poll() is None:
            procs_to_terminate.append(self.net_collector_proc)

        for proc in procs_to_terminate:
            try:
                proc.terminate()
            except Exception as e:
                # proc.args might be None if Popen failed weirdly, use a generic name
                proc_name = proc.args[1] if proc.args and len(proc.args) > 1 else "collector script"
                self.host_output_queue.put(f"Error terminating {proc_name}: {e}\n")

        for proc in procs_to_terminate:
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:
                pass

        self.host_collector_proc = None
        self.net_collector_proc = None

        self.start_stop_button.configure(text="Start Collection", fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER)
        self.status_bar.configure(text="Status: Stopped", text_color="red")
        self.save_host_log_button.configure(state=tk.NORMAL if self.host_output_textbox.get("1.0", tk.END).strip() else tk.DISABLED)
        self.save_net_log_button.configure(state=tk.NORMAL if self.net_output_textbox.get("1.0", tk.END).strip() else tk.DISABLED)
        self.save_both_button.configure(state=tk.NORMAL if (self.host_output_textbox.get("1.0", tk.END).strip() or self.net_output_textbox.get("1.0", tk.END).strip()) else tk.DISABLED)

    def process_queues(self):
        try:
            while True:
                line = self.host_output_queue.get_nowait()
                if line is None:
                    if self.monitoring_active:
                         self._append_to_textbox(self.host_output_textbox, "[Host collector stream ended unexpectedly]\n")
                    break
                self._append_to_textbox(self.host_output_textbox, line)
        except queue.Empty:
            pass

        try:
            while True:
                line = self.net_output_queue.get_nowait()
                if line is None:
                    if self.monitoring_active:
                         self._append_to_textbox(self.net_output_textbox, "[Network collector stream ended unexpectedly]\n")
                    break
                self._append_to_textbox(self.net_output_textbox, line)
        except queue.Empty:
            pass

        if not self.monitoring_active:
            self.save_host_log_button.configure(state=tk.NORMAL if self.host_output_textbox.get("1.0", tk.END).strip() else tk.DISABLED)
            self.save_net_log_button.configure(state=tk.NORMAL if self.net_output_textbox.get("1.0", tk.END).strip() else tk.DISABLED)
            self.save_both_button.configure(state=tk.NORMAL if (self.host_output_textbox.get("1.0", tk.END).strip() or self.net_output_textbox.get("1.0", tk.END).strip()) else tk.DISABLED)

        if self.winfo_exists():
            self.after(100, self.process_queues)

    def _append_to_textbox(self, textbox, text):
        if textbox.winfo_exists():
            textbox.configure(state=tk.NORMAL)
            textbox.insert(tk.END, text)
            textbox.see(tk.END)
            textbox.configure(state=tk.DISABLED)

    def save_log(self, log_type):
        textbox = None
        default_filename = ""
        if log_type == "host":
            textbox = self.host_output_textbox
            default_filename = f"host_events_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"
        elif log_type == "network":
            textbox = self.net_output_textbox
            default_filename = f"network_traffic_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt"
        else:
            return

        content = textbox.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Save Log", "Nothing to save.")
            return

        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename,
            defaultextension=".csv" if log_type == "host" else ".txt",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not file_path: return

        try:
            with open(file_path, "w", encoding='utf-8', newline='' if log_type == "host" else None) as f:
                f.write(content + "\n")
            messagebox.showinfo("Save Successful", f"Log saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error Saving Log", str(e))

    def save_both_logs(self):
        host_content = self.host_output_textbox.get("1.0", tk.END).strip()
        if host_content:
            file_path_host = filedialog.asksaveasfilename(
                initialfile=f"host_events_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv",
                title="Save Host Events Log As...",
                defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
            )
            if file_path_host:
                try:
                    with open(file_path_host, "w", encoding='utf-8', newline='') as f:
                        f.write(host_content + "\n")
                    messagebox.showinfo("Save Successful", f"Host log saved to {file_path_host}")
                except Exception as e:
                    messagebox.showerror("Error Saving Host Log", str(e))
            else:
                if not messagebox.askyesno("Continue?", "Host log saving cancelled. Continue to save network log?"):
                    return
        else:
            messagebox.showinfo("Save Both", "No host events to save.")

        net_content = self.net_output_textbox.get("1.0", tk.END).strip()
        if net_content:
            file_path_net = filedialog.asksaveasfilename(
                initialfile=f"network_traffic_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt",
                title="Save Network Traffic Log As...",
                defaultextension=".txt", filetypes=[("Text files", "*.txt")]
            )
            if file_path_net:
                try:
                    with open(file_path_net, "w", encoding='utf-8') as f:
                        f.write(net_content + "\n")
                    messagebox.showinfo("Save Successful", f"Network log saved to {file_path_net}")
                except Exception as e:
                    messagebox.showerror("Error Saving Network Log", str(e))
        else:
            messagebox.showinfo("Save Both", "No network traffic to save.")

    def clear_all_output(self, show_info=True):
        self.host_output_textbox.configure(state=tk.NORMAL)
        self.host_output_textbox.delete("1.0", tk.END)
        self.host_output_textbox.configure(state=tk.DISABLED)

        self.net_output_textbox.configure(state=tk.NORMAL)
        self.net_output_textbox.delete("1.0", tk.END)
        self.net_output_textbox.configure(state=tk.DISABLED)

        if show_info:
            messagebox.showinfo("Clear Output", "All output cleared.")

    def on_closing(self):
        if self.monitoring_active:
            if messagebox.askyesno(APP_TITLE, "Monitoring is active. Are you sure you want to quit? This will stop all collectors."):
                self.stop_collection_logic()
                self.after(500, self.destroy)
            else:
                return
        else:
            self.destroy()

if __name__ == "__main__":
    try:
        import customtkinter
    except ImportError:
        root_check = tk.Tk()
        root_check.withdraw()
        messagebox.showerror("Missing Library", "customtkinter is not installed. Please install it via pip.")
        root_check.destroy()
        sys.exit(1)

    app = SecurityMonitorApp()
    app.mainloop()
