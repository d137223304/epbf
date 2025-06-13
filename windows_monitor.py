import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import psutil
import threading
import time
import datetime
import queue
import os
import csv
import sys # Added for sys.exit

# --- Constants ---
APP_TITLE = "Windows Host Event Monitor"
DARK_THEME_BACKGROUND = "#2E2E2E"
GREEN_ACCENT = "#008A00"
GREEN_ACCENT_HOVER = "#00A500" # Slightly lighter green for hover
RED_ACCENT = "#A00000"
RED_ACCENT_HOVER = "#B80000"   # Slightly lighter red for hover
MONO_FONT = ("Consolas", 12) # Or "Courier New"

CSV_HEADER = ["Timestamp", "PID", "UID", "Comm", "EventType", "Syscall", "SrcIP", "DstIP", "SrcPort", "DstPort", "Details"]

class WindowsMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1000x700")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.configure(fg_color=DARK_THEME_BACKGROUND)

        # --- State Variables ---
        self.monitoring_active = False
        self.monitor_thread = None
        self.seen_pids = set()
        self.seen_connections = set()
        self.output_queue = queue.Queue()

        # --- Main Layout ---
        self.grid_columnconfigure(0, weight=1, minsize=250)
        self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(0, weight=1)

        # --- Left Control Panel (Column 0) ---
        self.control_panel = ctk.CTkFrame(self, fg_color=DARK_THEME_BACKGROUND)
        self.control_panel.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.control_panel.grid_columnconfigure(0, weight=1)

        lbl_controls_title = ctk.CTkLabel(self.control_panel, text="Controls", font=ctk.CTkFont(size=16, weight="bold"))
        lbl_controls_title.grid(row=0, column=0, pady=(0, 20), sticky="ew")

        self.start_stop_button = ctk.CTkButton(
            self.control_panel,
            text="Start Monitoring",
            fg_color=GREEN_ACCENT,
            hover_color=GREEN_ACCENT_HOVER, # Corrected: Use static color string
            command=self.toggle_monitoring
        )
        self.start_stop_button.grid(row=1, column=0, pady=10, sticky="ew")

        self.save_log_button = ctk.CTkButton(self.control_panel, text="Save Log...", command=self.save_log)
        self.save_log_button.grid(row=2, column=0, pady=10, sticky="ew")

        self.clear_log_button = ctk.CTkButton(self.control_panel, text="Clear Output", command=self.clear_log)
        self.clear_log_button.grid(row=3, column=0, pady=10, sticky="ew")

        control_panel_spacer = tk.Frame(self.control_panel, background=DARK_THEME_BACKGROUND)
        control_panel_spacer.grid(row=4, column=0, sticky="nsew", pady=(20,0))
        self.control_panel.grid_rowconfigure(4, weight=1)


        self.status_label = ctk.CTkLabel(
            self.control_panel,
            text="Status: Stopped",
            text_color="red", # Standard color name, or hex
            font=ctk.CTkFont(size=12)
        )
        self.status_label.grid(row=5, column=0, pady=(10,0), sticky="ew")


        # --- Right Output Panel (Column 1) ---
        self.output_panel = ctk.CTkFrame(self, fg_color=DARK_THEME_BACKGROUND)
        self.output_panel.grid(row=0, column=1, sticky="nsew", padx=(0,10), pady=10)
        self.output_panel.grid_rowconfigure(0, weight=1)
        self.output_panel.grid_columnconfigure(0, weight=1)

        self.output_textbox = ctk.CTkTextbox(
            self.output_panel,
            font=MONO_FONT,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.output_textbox.grid(row=0, column=0, sticky="nsew")

        self.after(100, self.process_queue)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def toggle_monitoring(self):
        if self.monitoring_active:
            self.stop_monitoring_logic()
        else:
            self.start_monitoring_logic()

    def start_monitoring_logic(self):
        self.monitoring_active = True
        # Corrected: Use static color string for hover_color
        self.start_stop_button.configure(text="Stop Monitoring", fg_color=RED_ACCENT, hover_color=RED_ACCENT_HOVER)
        self.status_label.configure(text="Status: Running...", text_color="green") # Standard color name, or hex
        self.save_log_button.configure(state=tk.DISABLED)
        self.clear_log_button.configure(state=tk.DISABLED)

        self.output_textbox.configure(state=tk.NORMAL)
        self.output_textbox.delete("1.0", tk.END)
        self.output_textbox.insert(tk.END, ",".join(CSV_HEADER) + "\n")
        self.output_textbox.configure(state=tk.DISABLED)

        self.seen_pids = set(p.pid for p in psutil.process_iter(['pid']))
        self.seen_connections = set()
        try:
            for conn in psutil.net_connections(kind='tcp4'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr and conn.pid is not None:
                    conn_tuple = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, conn.pid)
                    self.seen_connections.add(conn_tuple)
        except Exception as e:
            self.log_to_gui(f"Error initializing connections: {e}\n")

        self.monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring_logic(self, from_closing=False):
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            if not from_closing:
                 self.monitor_thread.join(timeout=1)

        # Corrected: Use static color string for hover_color
        self.start_stop_button.configure(text="Start Monitoring", fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER)
        self.status_label.configure(text="Status: Stopped", text_color="red") # Standard color name, or hex
        self.save_log_button.configure(state=tk.NORMAL)
        self.clear_log_button.configure(state=tk.NORMAL)

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.log_to_gui("Warning: Monitoring thread did not stop gracefully.\n")
        self.monitor_thread = None

    def monitoring_loop(self):
        while self.monitoring_active:
            current_time_iso = datetime.datetime.now().isoformat()

            current_pids_iter = []
            try:
                current_pids_iter = list(psutil.process_iter(['pid', 'name', 'username', 'exe', 'create_time']))
            except Exception as e:
                self.output_queue.put(f"Error iterating processes: {e}\n")

            for proc in current_pids_iter:
                if not self.monitoring_active: break
                try:
                    if proc.info['pid'] not in self.seen_pids:
                        pid = proc.info['pid']
                        uid = proc.info['username'] if proc.info['username'] else "N/A"
                        comm = proc.info['name'] if proc.info['name'] else "N/A"
                        details_path = proc.info['exe'] if proc.info['exe'] else "N/A"

                        csv_row = [
                            current_time_iso, pid, uid, comm,
                            "process_exec", "CreateProcess",
                            "", "", "", "", f'"{details_path}"'
                        ]
                        self.output_queue.put(",".join(map(str, csv_row)) + "\n")
                        self.seen_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError, AttributeError):
                    continue

            if not self.monitoring_active: break

            active_connections_now = set()
            try:
                for conn in psutil.net_connections(kind='tcp4'):
                    if not self.monitoring_active: break
                    if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr and conn.pid is not None:
                        conn_tuple = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, conn.pid)
                        active_connections_now.add(conn_tuple)

                        if conn_tuple not in self.seen_connections:
                            proc_name = "N/A"
                            proc_uid = "N/A"
                            try:
                                p = psutil.Process(conn.pid)
                                proc_name = p.name()
                                proc_uid = p.username()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass

                            csv_row = [
                                current_time_iso, conn.pid, proc_uid, proc_name,
                                "network_connect", "connect",
                                conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, ""
                            ]
                            self.output_queue.put(",".join(map(str, csv_row)) + "\n")
                            self.seen_connections.add(conn_tuple)
            except Exception as e:
                self.output_queue.put(f"Error monitoring connections: {e}\n")

            self.seen_connections.intersection_update(active_connections_now)
            time.sleep(0.5)
        self.output_queue.put("Monitoring loop stopped.\n")

    def process_queue(self):
        try:
            while True:
                line = self.output_queue.get_nowait()
                self.log_to_gui(line)
        except queue.Empty:
            pass
        finally:
            if self.winfo_exists():
                self.after(100, self.process_queue)

    def log_to_gui(self, message):
        if self.output_textbox.winfo_exists():
            self.output_textbox.configure(state=tk.NORMAL)
            self.output_textbox.insert(tk.END, message)
            self.output_textbox.see(tk.END)
            self.output_textbox.configure(state=tk.DISABLED)

    def save_log(self):
        if self.monitoring_active:
            messagebox.showwarning("Save Log", "Please stop monitoring before saving the log.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Log As"
        )
        if not file_path: return

        try:
            content = self.output_textbox.get("1.0", tk.END)
            with open(file_path, "w", newline='') as f:
                f.write(content.strip() + "\n")
            messagebox.showinfo("Save Successful", f"Log saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error Saving Log", str(e))

    def clear_log(self):
        if self.monitoring_active:
            messagebox.showwarning("Clear Log", "Please stop monitoring before clearing the log.")
            return

        self.output_textbox.configure(state=tk.NORMAL)
        self.output_textbox.delete("1.0", tk.END)
        self.output_textbox.configure(state=tk.DISABLED)
        messagebox.showinfo("Clear Log", "Output cleared.")

    def on_closing(self):
        if self.monitoring_active:
            if messagebox.askyesno(APP_TITLE, "Monitoring is active. Are you sure you want to quit?"):
                self.stop_monitoring_logic(from_closing=True)
                self.destroy()
            else:
                return
        else:
            self.destroy()

if __name__ == "__main__":
    try:
        import customtkinter
        import psutil
    except ImportError as e:
        root_check = tk.Tk()
        root_check.withdraw()
        messagebox.showerror("Missing Libraries",
                             f"Required library not found: {e}.\n"
                             f"Please install customtkinter and psutil via pip.")
        root_check.destroy()
        sys.exit(1)

    app = WindowsMonitorApp()
    app.mainloop()
