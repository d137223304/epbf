#!/usr/bin/env python3

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import threading
import queue
import sys
import os
import datetime
import re
import json

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

APP_TITLE = "Windows Security Event Monitor"
GREEN_ACCENT = "#008A00"
GREEN_ACCENT_HOVER = "#00A500"
RED_ACCENT = "#A00000"
RED_ACCENT_HOVER = "#B80000"
MONO_FONT = ("Consolas", 11)
MAX_TEXTBOX_LINES = 2000 # Max lines to keep in textboxes if display is on

_HOST_COLLECTOR_FILENAME = "host_collector_windows.py"
_NET_COLLECTOR_FILENAME = "network_collector_windows.py"

HOST_COLLECTOR_SCRIPT_PATH = os.path.join(SCRIPT_DIR, _HOST_COLLECTOR_FILENAME)
NET_COLLECTOR_SCRIPT_PATH = os.path.join(SCRIPT_DIR, _NET_COLLECTOR_FILENAME)


class SecurityMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1250x800")
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.host_collector_proc = None
        self.net_collector_proc = None
        self.host_output_queue = queue.Queue()
        self.net_output_queue = queue.Queue()
        self.monitoring_active = False

        self.tshark_interfaces_map = {}
        self.host_event_count = 0
        self.network_event_count = 0
        self.display_logs_var = ctk.IntVar(value=1)

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=0)
        self.grid_columnconfigure(0, weight=1)

        self.control_panel_row1 = ctk.CTkFrame(self, corner_radius=0)
        self.control_panel_row1.grid(row=0, column=0, sticky="ew", padx=10, pady=(10,0))
        self.control_panel_row1.grid_columnconfigure(0, weight=0)
        self.control_panel_row1.grid_columnconfigure(1, weight=0)
        self.control_panel_row1.grid_columnconfigure(2, weight=0)
        self.control_panel_row1.grid_columnconfigure(3, weight=0)
        self.control_panel_row1.grid_columnconfigure(4, weight=0)
        self.control_panel_row1.grid_columnconfigure(5, weight=0)
        self.control_panel_row1.grid_columnconfigure(6, weight=0)
        self.control_panel_row1.grid_columnconfigure(7, weight=1)

        self.start_stop_button = ctk.CTkButton(
            self.control_panel_row1, text="Start Collection",
            fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER,
            command=self.toggle_collection
        )
        self.start_stop_button.grid(row=0, column=0, padx=(0,5), pady=5)

        self.save_host_log_button = ctk.CTkButton(self.control_panel_row1, text="Save Host Log", command=lambda: self.save_log("host"))
        self.save_host_log_button.grid(row=0, column=1, padx=5, pady=5)
        self.save_host_log_button.configure(state=tk.DISABLED)

        self.save_net_log_button = ctk.CTkButton(self.control_panel_row1, text="Save Network Log", command=lambda: self.save_log("network"))
        self.save_net_log_button.grid(row=0, column=2, padx=5, pady=5)
        self.save_net_log_button.configure(state=tk.DISABLED)

        self.save_both_button = ctk.CTkButton(self.control_panel_row1, text="Save Both", command=self.save_both_logs)
        self.save_both_button.grid(row=0, column=3, padx=5, pady=5)
        self.save_both_button.configure(state=tk.DISABLED)

        self.correlate_button = ctk.CTkButton(self.control_panel_row1, text="Correlate Data", state="disabled")
        self.correlate_button.grid(row=0, column=4, padx=5, pady=5)

        self.clear_button = ctk.CTkButton(self.control_panel_row1, text="Clear Output", command=self.clear_all_output)
        self.clear_button.grid(row=0, column=5, padx=5, pady=5)

        self.display_logs_checkbox = ctk.CTkCheckBox(self.control_panel_row1, text="Display logs in real-time",
                                                     variable=self.display_logs_var, onvalue=1, offvalue=0)
        self.display_logs_checkbox.grid(row=0, column=6, padx=(10,5), pady=5, sticky="w")

        self.control_panel_row2 = ctk.CTkFrame(self, corner_radius=0)
        self.control_panel_row2.grid(row=1, column=0, sticky="ew", padx=10, pady=(0,5))
        self.control_panel_row2.grid_columnconfigure(0, weight=0)
        self.control_panel_row2.grid_columnconfigure(1, weight=1)
        self.control_panel_row2.grid_columnconfigure(2, weight=0)

        self.tshark_interface_label = ctk.CTkLabel(self.control_panel_row2, text="TShark Interface:")
        self.tshark_interface_label.grid(row=0, column=0, padx=(5,2), pady=5, sticky="w")

        self.tshark_interface_combobox = ctk.CTkComboBox(
            self.control_panel_row2, values=["Loading interfaces..."], state="readonly", width=250
        )
        self.tshark_interface_combobox.grid(row=0, column=1, padx=(0,5), pady=5, sticky="ew")

        self.refresh_interfaces_button = ctk.CTkButton(
            self.control_panel_row2, text="Refresh", width=80,
            command=self.populate_tshark_interfaces_combobox
        )
        self.refresh_interfaces_button.grid(row=0, column=2, padx=(0,10), pady=5, sticky="e")

        self.tab_view = ctk.CTkTabview(self, corner_radius=8)
        self.tab_view.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        self.tab_view.add("Host Events (psutil)")
        self.host_output_textbox = ctk.CTkTextbox(
            self.tab_view.tab("Host Events (psutil)"), font=MONO_FONT, wrap=tk.WORD, state=tk.DISABLED
        )
        self.host_output_textbox.pack(expand=True, fill="both")

        self.tab_view.add("Network Traffic (TShark)")
        self.net_output_textbox = ctk.CTkTextbox(
            self.tab_view.tab("Network Traffic (TShark)"), font=MONO_FONT, wrap=tk.WORD, state=tk.DISABLED
        )
        self.net_output_textbox.pack(expand=True, fill="both")

        self.status_text_var = ctk.StringVar(value="Status: Stopped")
        self.status_bar = ctk.CTkLabel(self, textvariable=self.status_text_var, text_color="red", anchor="w")
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=10, pady=(5,10))

        self.populate_tshark_interfaces_combobox()
        self.after(200, self.process_queues_and_update_gui) # Renamed and adjusted frequency
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def update_status_bar(self):
        status_prefix = "Status: Running..." if self.monitoring_active else "Status: Stopped"
        color = "green" if self.monitoring_active else "red"
        counts_str = f" | Host: {self.host_event_count} | Network: {self.network_event_count}"
        self.status_text_var.set(f"{status_prefix}{counts_str}")
        self.status_bar.configure(text_color=color)

    def get_tshark_interfaces(self):
        interfaces_map = {}
        try:
            proc = subprocess.run(
                ["tshark.exe", "-D"], capture_output=True, text=True, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW, encoding='utf-8'
            )
            if proc.returncode != 0:
                error_msg = f"'tshark -D' failed. STDERR: {proc.stderr.strip() if proc.stderr else 'Unknown error'}"
                self._queue_internal_message(self.net_output_queue, f"[main_ui.py ERROR] {error_msg}\\n")
                return {"Error: Could not list (tshark -D failed)": ""}
            output = proc.stdout.strip()
            if not output:
                self._queue_internal_message(self.net_output_queue, "[main_ui.py WARNING] 'tshark -D' returned no interfaces.\\n")
                return {"No interfaces found": ""}
            for line in output.splitlines():
                line = line.strip()
                match = re.match(r"(\d+)\.\s+(.+)", line)
                if match:
                    number = match.group(1)
                    full_description = match.group(2)
                    friendly_name_match = re.search(r"\((.+)\)", full_description)
                    display_name_suffix = friendly_name_match.group(1) if friendly_name_match else full_description
                    identifier_for_tshark = number
                    npf_match = re.search(r"(\\Device\\NPF_\{[\w-]+\})", full_description)
                    if npf_match:
                        identifier_for_tshark = npf_match.group(1)
                        if not friendly_name_match :
                             display_name_suffix = identifier_for_tshark
                    display_text = f"{number}. {display_name_suffix}"
                    interfaces_map[display_text] = identifier_for_tshark
            if not interfaces_map: return {"No parsable interfaces found": ""}
            return interfaces_map
        except FileNotFoundError:
            self._queue_internal_message(self.net_output_queue,"[main_ui.py ERROR] tshark.exe not found. Cannot list interfaces.\\n")
            messagebox.showerror("TShark Error", "tshark.exe not found. Please ensure Wireshark is installed and TShark is in the system PATH.")
            return {"Error: tshark.exe not found": ""}
        except Exception as e:
            self._queue_internal_message(self.net_output_queue,f"[main_ui.py ERROR] Error getting TShark interfaces: {e}\\n")
            messagebox.showerror("TShark Error", f"Error getting TShark interfaces: {e}")
            return {f"Error: {str(e)[:100]}": ""}

    def populate_tshark_interfaces_combobox(self):
        self.tshark_interface_combobox.configure(values=["Loading..."], state="readonly")
        self.tshark_interface_combobox.set("Loading...")
        self.update_idletasks()
        self.tshark_interfaces_map = self.get_tshark_interfaces()
        if self.tshark_interfaces_map:
            combobox_values = list(self.tshark_interfaces_map.keys())
            is_error_or_empty = False
            if combobox_values:
                first_val_lower = combobox_values[0].lower()
                if "error:" in first_val_lower or "no interfaces" in first_val_lower or "failed to load" in first_val_lower :
                    is_error_or_empty = True
            if combobox_values and not is_error_or_empty:
                self.tshark_interface_combobox.configure(values=combobox_values, state="readonly")
                self.tshark_interface_combobox.set(combobox_values[0])
            else:
                self.tshark_interface_combobox.configure(values=combobox_values if combobox_values else ["No interfaces found"], state="disabled")
                self.tshark_interface_combobox.set(combobox_values[0] if combobox_values else "No interfaces found")
        else:
            self.tshark_interface_combobox.configure(values=["Failed to load interfaces"], state="disabled")
            self.tshark_interface_combobox.set("Failed to load interfaces")

    def _reader_thread(self, proc, queue_obj, tab_name_for_error_logging):
        try:
            if proc and proc.stdout:
                for line in iter(proc.stdout.readline, ''): # line includes newline
                    if line: queue_obj.put(line)
                    if not self.monitoring_active and (proc.poll() is not None): break
                proc.stdout.close()
        except Exception as e:
            self._queue_internal_message(queue_obj, f"Error reading from {tab_name_for_error_logging}: {e}\\n")
        finally:
            queue_obj.put(None)

    def _queue_internal_message(self, queue_obj, message):
        queue_obj.put(message) # Internal messages always go to queue; display is handled by process_queues

    def toggle_collection(self):
        if self.monitoring_active: self.stop_collection_logic()
        else: self.start_collection_logic()

    def start_collection_logic(self):
        if self.monitoring_active: return
        if not os.path.exists(HOST_COLLECTOR_SCRIPT_PATH):
            messagebox.showerror("Error", f"{_HOST_COLLECTOR_FILENAME} not found at {HOST_COLLECTOR_SCRIPT_PATH}")
            return
        if not os.path.exists(NET_COLLECTOR_SCRIPT_PATH):
            messagebox.showerror("Error", f"{_NET_COLLECTOR_FILENAME} not found at {NET_COLLECTOR_SCRIPT_PATH}")
            return

        self.monitoring_active = True
        self.host_event_count = 0
        self.network_event_count = 0
        self.update_status_bar()

        self.start_stop_button.configure(text="Stop Collection", fg_color=RED_ACCENT, hover_color=RED_ACCENT_HOVER)

        if self.display_logs_var.get() == 1:
            self.clear_all_output(show_info=False, reset_counts_override=False)
        else: # If display is off, ensure textboxes are empty for a new session
            for textbox in [self.host_output_textbox, self.net_output_textbox]:
                 if textbox.get("1.0", tk.END).strip():
                    textbox.configure(state=tk.NORMAL); textbox.delete("1.0", tk.END); textbox.configure(state=tk.DISABLED)

        self.save_host_log_button.configure(state=tk.DISABLED)
        self.save_net_log_button.configure(state=tk.DISABLED)
        self.save_both_button.configure(state=tk.DISABLED)
        self.tshark_interface_combobox.configure(state=tk.DISABLED)
        self.refresh_interfaces_button.configure(state=tk.DISABLED)
        self.display_logs_checkbox.configure(state=tk.DISABLED)

        try:
            host_cmd = [sys.executable, HOST_COLLECTOR_SCRIPT_PATH]
            self.host_collector_proc = subprocess.Popen(
                host_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            threading.Thread(target=self._reader_thread, args=(self.host_collector_proc, self.host_output_queue, "Host Collector"), daemon=True).start()
            threading.Thread(target=self._log_subprocess_stderr, args=(self.host_collector_proc, self.host_output_queue, "Host Collector"), daemon=True).start()

            net_cmd = [sys.executable, NET_COLLECTOR_SCRIPT_PATH]
            selected_display_name = self.tshark_interface_combobox.get()
            tshark_identifier = self.tshark_interfaces_map.get(selected_display_name)
            if tshark_identifier and not ("Error:" in selected_display_name or "No interfaces" in selected_display_name or "Failed to load" in selected_display_name or not tshark_identifier.strip()):
                net_cmd.extend(["--interface", tshark_identifier])

            self._queue_internal_message(self.net_output_queue, f"[main_ui.py DEBUG] Launching Network Collector with command: {' '.join(net_cmd)}\\n")

            self.net_collector_proc = subprocess.Popen(
                net_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            threading.Thread(target=self._reader_thread, args=(self.net_collector_proc, self.net_output_queue, "Network Collector (TShark)"), daemon=True).start()
            threading.Thread(target=self._log_subprocess_stderr, args=(self.net_collector_proc, self.net_output_queue, "Network Collector (TShark)"), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error Starting Collectors", str(e))
            self.stop_collection_logic(force_ui_update=True)

    def _log_subprocess_stderr(self, proc, queue_obj, name):
        if proc and proc.stderr:
            for line in iter(proc.stderr.readline, ''):
                if line: self._queue_internal_message(queue_obj, f"[{name} STDERR] {line.strip()}\\n")
            proc.stderr.close()

    def stop_collection_logic(self, force_ui_update=False):
        if not self.monitoring_active and not force_ui_update: return
        self.monitoring_active = False
        if hasattr(self, 'tshark_interface_combobox'): self.tshark_interface_combobox.configure(state="readonly")
        if hasattr(self, 'refresh_interfaces_button'): self.refresh_interfaces_button.configure(state=tk.NORMAL)
        if hasattr(self, 'display_logs_checkbox'): self.display_logs_checkbox.configure(state=tk.NORMAL)

        procs_to_terminate = []
        if self.host_collector_proc and self.host_collector_proc.poll() is None: procs_to_terminate.append(self.host_collector_proc)
        if self.net_collector_proc and self.net_collector_proc.poll() is None: procs_to_terminate.append(self.net_collector_proc)

        for proc in procs_to_terminate:
            try: proc.terminate()
            except Exception as e:
                proc_name = proc.args[1] if proc.args and len(proc.args) > 1 else "collector script"
                self._queue_internal_message(self.host_output_queue, f"Error terminating {proc_name}: {e}\\n")
        for proc in procs_to_terminate:
            try: proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired: proc.kill()
            except Exception: pass

        self.host_collector_proc = None; self.net_collector_proc = None
        self.start_stop_button.configure(text="Start Collection", fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER)
        self.update_status_bar()

        self.save_host_log_button.configure(state=tk.NORMAL if self.host_event_count > 0 else tk.DISABLED)
        self.save_net_log_button.configure(state=tk.NORMAL if self.network_event_count > 0 else tk.DISABLED)
        self.save_both_button.configure(state=tk.NORMAL if (self.host_event_count > 0 or self.network_event_count > 0) else tk.DISABLED)

    def process_queues_and_update_gui(self):
        # Process queues to update counts
        host_lines_in_batch = []
        try:
            while not self.host_output_queue.empty():
                line = self.host_output_queue.get_nowait()
                if line is None:
                    if self.monitoring_active:
                        self._queue_internal_message(self.host_output_queue, "[Host collector stream ended unexpectedly]\\n")
                    break
                if line.strip() and not line.startswith("[main_ui.py"): self.host_event_count += 1
                host_lines_in_batch.append(line)
        except queue.Empty: pass

        net_lines_in_batch = []
        try:
            while not self.net_output_queue.empty():
                line = self.net_output_queue.get_nowait()
                if line is None:
                    if self.monitoring_active:
                        self._queue_internal_message(self.net_output_queue,"[Network collector (TShark) stream ended unexpectedly]\\n")
                    break
                if line.strip() and not line.startswith("[main_ui.py"): self.network_event_count += 1
                net_lines_in_batch.append(line)
        except queue.Empty: pass

        # Update GUI textboxes if display is enabled
        if self.display_logs_var.get() == 1:
            if host_lines_in_batch:
                self._append_chunk_to_textbox(self.host_output_textbox, "".join(host_lines_in_batch))
            if net_lines_in_batch:
                self._append_chunk_to_textbox(self.net_output_textbox, "".join(net_lines_in_batch))

        # Always update status bar if monitoring or if counts changed
        if self.monitoring_active or host_lines_in_batch or net_lines_in_batch :
             self.update_status_bar()

        if not self.monitoring_active: # Update save button states if not monitoring
            self.save_host_log_button.configure(state=tk.NORMAL if self.host_event_count > 0 else tk.DISABLED)
            self.save_net_log_button.configure(state=tk.NORMAL if self.network_event_count > 0 else tk.DISABLED)
            self.save_both_button.configure(state=tk.NORMAL if (self.host_event_count > 0 or self.network_event_count > 0) else tk.DISABLED)

        if self.winfo_exists(): self.after(300, self.process_queues_and_update_gui) # Adjusted frequency

    def _append_chunk_to_textbox(self, textbox, text_chunk):
        if not text_chunk: return
        if textbox.winfo_exists():
            textbox.configure(state=tk.NORMAL)
            current_lines_str = textbox.index('end-1c').split('.')[0]
            current_lines = int(current_lines_str) if current_lines_str.isdigit() else 0 # Handle empty textbox

            # Simple way to count new lines in chunk, assuming each line from queue ends with \n
            new_lines_in_chunk = text_chunk.count('\\n')
            if new_lines_in_chunk == 0 and text_chunk.strip(): new_lines_in_chunk = 1 # Count non-empty chunk as at least one line


            if current_lines + new_lines_in_chunk > MAX_TEXTBOX_LINES:
                lines_to_delete = (current_lines + new_lines_in_chunk) - MAX_TEXTBOX_LINES
                if lines_to_delete > 0:
                    # Add 1 because delete is exclusive of the end index's line itself if it's X.0
                    delete_end_index = f"{lines_to_delete + 1}.0"
                    textbox.delete("1.0", delete_end_index)

            textbox.insert(tk.END, text_chunk)
            textbox.see(tk.END)
            textbox.configure(state=tk.DISABLED)

    def save_log(self, log_type):
        textbox_content = ""; default_filename = ""; ext = ".txt";
        filetypes_list = [("Text files", "*.txt"), ("All files", "*.*")]
        actual_event_count = 0

        if log_type == "host":
            textbox = self.host_output_textbox
            actual_event_count = self.host_event_count
            default_filename = f"host_events_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"; ext = ".csv"
            filetypes_list = [("CSV files", "*.csv"), ("All files", "*.*")]
        elif log_type == "network":
            textbox = self.net_output_textbox
            actual_event_count = self.network_event_count
            default_filename = f"network_traffic_tshark_{datetime.datetime.now():%Y%m%d_%H%M%S}.jsonl"; ext = ".jsonl"
            filetypes_list = [("JSON Lines files", "*.jsonl"), ("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        else: return

        textbox_content_to_save = textbox.get("1.0", tk.END).strip()

        if self.display_logs_var.get() == 0 and actual_event_count > 0:
            messagebox.showwarning("Save Log",
                f"Log display was off. {actual_event_count} {log_type} events were collected. "
                "This function saves the content currently visible in the textbox. "
                "Since display was off, the textbox is empty. The saved file will contain a placeholder message. "
                "To save all collected data when display is off, a direct-to-file buffering mechanism for collectors would be needed (not yet implemented).")
            if not textbox_content_to_save: # If textbox is truly empty
                 textbox_content_to_save = f"# Log display was OFF during collection. Total {log_type} events collected: {actual_event_count}\\n# This file is a placeholder as actual log data was not written to the UI textbox."

        if not textbox_content_to_save.strip() :
            messagebox.showinfo("Save Log", "Nothing to save (no content in textbox)."); return

        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename, defaultextension=ext, filetypes=filetypes_list
        )
        if not file_path: return
        try:
            with open(file_path, "w", encoding='utf-8', newline=None if log_type == "network" else '') as f:
                f.write(textbox_content_to_save)
                if textbox_content_to_save and not textbox_content_to_save.endswith('\\n'): f.write('\\n')
            messagebox.showinfo("Save Successful", f"Log saved to {file_path}")
        except Exception as e: messagebox.showerror("Error Saving Log", str(e))

    def save_both_logs(self):
        if self.display_logs_var.get() == 0 and (self.host_event_count > 0 or self.network_event_count > 0) :
            messagebox.showwarning("Save Both",
                "Log display was off. Textboxes may be empty or incomplete. "
                "Saving will use textbox content or placeholders if empty. "
                "For full data, ensure 'Display logs' is on or implement off-screen buffering.")

        if self.host_event_count > 0 or self.host_output_textbox.get("1.0", tk.END).strip():
            self.save_log("host")
        else:
            messagebox.showinfo("Save Both", "No host events to save.")

        if self.network_event_count > 0 or self.net_output_textbox.get("1.0", tk.END).strip():
            self.save_log("network")
        else:
            messagebox.showinfo("Save Both", "No network traffic (TShark) to save.")

    def clear_all_output(self, show_info=True, reset_counts_override=None):
        for textbox in [self.host_output_textbox, self.net_output_textbox]:
            textbox.configure(state=tk.NORMAL); textbox.delete("1.0", tk.END); textbox.configure(state=tk.DISABLED)

        should_reset_counts = not self.monitoring_active
        if reset_counts_override is not None:
            should_reset_counts = reset_counts_override

        if should_reset_counts:
            self.host_event_count = 0
            self.network_event_count = 0

        self.update_status_bar()
        if show_info: messagebox.showinfo("Clear Output", "All output cleared.")

    def on_closing(self):
        if self.monitoring_active:
            if messagebox.askyesno(APP_TITLE, "Monitoring is active. Quit & stop collectors?"):
                self.stop_collection_logic()
                self.after(500, self.destroy)
            else: return
        else: self.destroy()

if __name__ == "__main__":
    try: import customtkinter
    except ImportError:
        root_check = tk.Tk(); root_check.withdraw()
        messagebox.showerror("Missing Library", "customtkinter is not installed. Please install it via pip.")
        root_check.destroy(); sys.exit(1)
    app = SecurityMonitorApp(); app.mainloop()
```

Key changes:
1.  **`MAX_TEXTBOX_LINES`**: Increased slightly, but the core idea is strict limiting.
2.  **`_queue_internal_message`**: Helper to ensure UI-generated messages (like errors from `get_tshark_interfaces` or the DEBUG Popen command) go through the queue system. This is important so they are also batched and respect the display toggle.
3.  **`process_queues_and_update_gui()`**:
    *   This is the new central UI update loop, called by `self.after`. Frequency adjusted (e.g., 300ms).
    *   It empties both queues completely in each cycle, collecting lines into `host_lines_in_batch` and `net_lines_in_batch`.
    *   Event counters (`self.host_event_count`, `self.network_event_count`) are incremented for each *valid data line* (not internal UI messages).
    *   If `self.display_logs_var.get() == 1`, it calls `_append_chunk_to_textbox()` with the *entire batch* of lines for each textbox.
    *   Calls `self.update_status_bar()` if monitoring or if any lines were processed (to reflect new counts).
4.  **`_append_chunk_to_textbox()`**:
    *   Now takes a `text_chunk` (a single string, potentially multi-line).
    *   The line limiting logic is refined:
        *   It correctly gets the `current_lines` even if the textbox was previously empty.
        *   It counts new lines in the incoming `text_chunk` (assumes `\n` from queue).
        *   If the total exceeds `MAX_TEXTBOX_LINES`, it calculates how many lines to delete from the top (`1.0` to `delete_end_index`).
5.  **`start_collection_logic()`**:
    *   When display is off, it now ensures textboxes are cleared of any *old* data from a previous "display on" session, so they are truly empty if display is toggled on later during the *same* collection run.
6.  **`save_log()`**:
    *   The warning message when display is off is more precise.
    *   If display was off and the textbox is empty, it now writes a placeholder message into the saved file, including the actual event count. This is better than a completely empty file.
7.  **`save_both_logs()`**: Updated to reflect the new `save_log` behavior.
8.  **`clear_all_output()`**: `reset_counts_override` parameter added to allow `start_collection_logic` to clear display without resetting counts that are about to start.

This version should be more robust against high-frequency log messages by batching UI updates and strictly limiting the number of lines in the textboxes, preventing the UI from becoming unresponsive or crashing. The event counters will always reflect the total number of events received, providing accurate feedback even if the display is off or being throttled.
