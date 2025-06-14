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

_HOST_COLLECTOR_FILENAME = "host_collector_windows.py"
_NET_COLLECTOR_FILENAME = "network_collector_windows.py"

HOST_COLLECTOR_SCRIPT_PATH = os.path.join(SCRIPT_DIR, _HOST_COLLECTOR_FILENAME)
NET_COLLECTOR_SCRIPT_PATH = os.path.join(SCRIPT_DIR, _NET_COLLECTOR_FILENAME)


class SecurityMonitorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1200x800")
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
        self.display_logs_var = ctk.IntVar(value=1) # Checkbox variable, 1=checked (display), 0=unchecked

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)
        self.grid_rowconfigure(3, weight=0)
        self.grid_columnconfigure(0, weight=1)

        # --- Control Panel Row 1 (Primary Buttons) ---
        self.control_panel_row1 = ctk.CTkFrame(self, corner_radius=0)
        self.control_panel_row1.grid(row=0, column=0, sticky="ew", padx=10, pady=(10,0))
        # Adjusted column weights for more balanced spacing with checkbox potentially moving here
        self.control_panel_row1.grid_columnconfigure(0, weight=0) # Start/Stop
        self.control_panel_row1.grid_columnconfigure(1, weight=0) # Save Host
        self.control_panel_row1.grid_columnconfigure(2, weight=0) # Save Net
        self.control_panel_row1.grid_columnconfigure(3, weight=0) # Save Both
        self.control_panel_row1.grid_columnconfigure(4, weight=0) # Correlate
        self.control_panel_row1.grid_columnconfigure(5, weight=0) # Clear
        self.control_panel_row1.grid_columnconfigure(6, weight=0) # Display Logs Checkbox
        self.control_panel_row1.grid_columnconfigure(7, weight=1) # Spacer

        self.start_stop_button = ctk.CTkButton(
            self.control_panel_row1, text="Start Collection",
            fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER,
            command=self.toggle_collection
        )
        self.start_stop_button.grid(row=0, column=0, padx=5, pady=5)

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
        self.clear_button.grid(row=0, column=5, padx=(5,5), pady=5) # Adjusted padding

        self.display_logs_checkbox = ctk.CTkCheckBox(self.control_panel_row1, text="Display logs in real-time",
                                                     variable=self.display_logs_var, onvalue=1, offvalue=0)
        self.display_logs_checkbox.grid(row=0, column=6, padx=(5,10), pady=5, sticky="w")


        # --- Control Panel Row 2: TShark Interface Input ---
        self.control_panel_row2 = ctk.CTkFrame(self, corner_radius=0)
        self.control_panel_row2.grid(row=1, column=0, sticky="ew", padx=10, pady=(0,5))
        self.control_panel_row2.grid_columnconfigure(0, weight=0)
        self.control_panel_row2.grid_columnconfigure(1, weight=1)
        self.control_panel_row2.grid_columnconfigure(2, weight=0)

        self.tshark_interface_label = ctk.CTkLabel(self.control_panel_row2, text="TShark Interface:")
        self.tshark_interface_label.grid(row=0, column=0, padx=(5,2), pady=5, sticky="w")

        self.tshark_interface_combobox = ctk.CTkComboBox(
            self.control_panel_row2, values=["Loading interfaces..."], state="readonly"
        )
        self.tshark_interface_combobox.grid(row=0, column=1, padx=(0,5), pady=5, sticky="ew")

        self.refresh_interfaces_button = ctk.CTkButton(
            self.control_panel_row2, text="Refresh", width=80,
            command=self.populate_tshark_interfaces_combobox
        )
        self.refresh_interfaces_button.grid(row=0, column=2, padx=(0,10), pady=5, sticky="e")

        # --- Middle Row: Output Display (CTkTabview) ---
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

        # --- Bottom Row: Status Bar ---
        self.status_text_var = ctk.StringVar(value="Status: Stopped")
        self.status_bar = ctk.CTkLabel(self, textvariable=self.status_text_var, text_color="red", anchor="w")
        self.status_bar.grid(row=3, column=0, sticky="ew", padx=10, pady=(5,10))

        self.populate_tshark_interfaces_combobox()
        self.after(100, self.process_queues)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def update_status_bar(self):
        status_prefix = "Status: Running..." if self.monitoring_active else "Status: Stopped"
        color = "green" if self.monitoring_active else "red"

        counts_str = ""
        if self.monitoring_active: # Only show counts when running
            counts_str = f" | Host: {self.host_event_count} | Network: {self.network_event_count}"
        elif self.host_event_count > 0 or self.network_event_count > 0: # Show final counts when stopped if any events were captured
             counts_str = f" | Host: {self.host_event_count} | Network: {self.network_event_count} (Collection Stopped)"


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
                self.net_output_queue.put(f"[main_ui.py ERROR] {error_msg}\\n")
                return {"Error: Could not list (tshark -D failed)": ""}
            output = proc.stdout.strip()
            if not output:
                self.net_output_queue.put("[main_ui.py WARNING] 'tshark -D' returned no interfaces.\\n")
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
            self.net_output_queue.put("[main_ui.py ERROR] tshark.exe not found. Cannot list interfaces.\\n")
            messagebox.showerror("TShark Error", "tshark.exe not found. Please ensure Wireshark is installed and TShark is in the system PATH.")
            return {"Error: tshark.exe not found": ""}
        except Exception as e:
            self.net_output_queue.put(f"[main_ui.py ERROR] Error getting TShark interfaces: {e}\\n")
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
                for line in iter(proc.stdout.readline, ''):
                    if line: queue_obj.put(line)
                    if not self.monitoring_active and (proc.poll() is not None): break
                proc.stdout.close()
        except Exception as e:
            queue_obj.put(f"Error reading from {tab_name_for_error_logging}: {e}\\n")
        finally:
            queue_obj.put(None)

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
        if self.display_logs_var.get() == 1: # Only clear textboxes if they were being displayed
            self.clear_all_output(show_info=False)
        else: # If display was off, just ensure textboxes are technically empty for new session if it were to be turned on
            for textbox in [self.host_output_textbox, self.net_output_textbox]:
                 if textbox.get("1.0", tk.END).strip(): # if it has content from previous (display on) session
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
            self.net_output_queue.put(f"[main_ui.py DEBUG] Launching Network Collector with command: {' '.join(net_cmd)}\\n")
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
                if line: queue_obj.put(f"[{name} STDERR] {line.strip()}\\n")
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
                self.host_output_queue.put(f"Error terminating {proc_name}: {e}\\n")
        for proc in procs_to_terminate:
            try: proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired: proc.kill()
            except Exception: pass

        self.host_collector_proc = None; self.net_collector_proc = None
        self.start_stop_button.configure(text="Start Collection", fg_color=GREEN_ACCENT, hover_color=GREEN_ACCENT_HOVER)
        self.update_status_bar()

        # Enable save buttons based on actual collected data (counts), not just textbox content
        self.save_host_log_button.configure(state=tk.NORMAL if self.host_event_count > 0 else tk.DISABLED)
        self.save_net_log_button.configure(state=tk.NORMAL if self.network_event_count > 0 else tk.DISABLED)
        self.save_both_button.configure(state=tk.NORMAL if (self.host_event_count > 0 or self.network_event_count > 0) else tk.DISABLED)


    def process_queues(self):
        # Process host queue
        host_lines_processed_this_cycle = 0
        try:
            while True: # Process all available items
                line = self.host_output_queue.get_nowait()
                if line is None:
                    if self.monitoring_active: self._append_to_textbox(self.host_output_textbox, "[Host collector stream ended unexpectedly]\\n", is_host_event=False) # Don't count this as data
                    break
                # Increment count for any non-empty line that is not a special message from UI itself
                if line.strip() and not line.startswith("[main_ui.py"): self.host_event_count += 1
                if self.display_logs_var.get() == 1: self._append_to_textbox(self.host_output_textbox, line, is_host_event=False) # Display if checked
                host_lines_processed_this_cycle +=1
        except queue.Empty: pass

        # Process network queue
        net_lines_processed_this_cycle = 0
        try:
            while True: # Process all available items
                line = self.net_output_queue.get_nowait()
                if line is None:
                    if self.monitoring_active: self._append_to_textbox(self.net_output_textbox, "[Network collector (TShark) stream ended unexpectedly]\\n", is_network_event=False)
                    break
                if line.strip() and not line.startswith("[main_ui.py"): self.network_event_count += 1
                if self.display_logs_var.get() == 1: self._append_to_textbox(self.net_output_textbox, line, is_network_event=False)
                net_lines_processed_this_cycle += 1
        except queue.Empty: pass

        if self.monitoring_active and (host_lines_processed_this_cycle > 0 or net_lines_processed_this_cycle > 0):
            self.update_status_bar()

        if not self.monitoring_active:
            # Re-check save button state based on counts when monitoring stops
            self.save_host_log_button.configure(state=tk.NORMAL if self.host_event_count > 0 else tk.DISABLED)
            self.save_net_log_button.configure(state=tk.NORMAL if self.network_event_count > 0 else tk.DISABLED)
            self.save_both_button.configure(state=tk.NORMAL if (self.host_event_count > 0 or self.network_event_count > 0) else tk.DISABLED)


        if self.winfo_exists(): self.after(100, self.process_queues)

    def _append_to_textbox(self, textbox, text, is_host_event=False, is_network_event=False): # Flags removed, counting is in process_queues
        # This function is now purely for appending to the textbox if display_logs_var is set
        if self.display_logs_var.get() == 1:
            if textbox.winfo_exists():
                textbox.configure(state=tk.NORMAL)
                textbox.insert(tk.END, text)
                # Limit textbox length to prevent performance issues with massive amounts of data
                # Example: Keep last 5000 lines (adjust as needed)
                num_lines = int(textbox.index('end-1c').split('.')[0])
                max_lines = 5000
                if num_lines > max_lines:
                    textbox.delete('1.0', f'{num_lines - max_lines}.0')
                textbox.see(tk.END)
                textbox.configure(state=tk.DISABLED)
        # Counts are updated in process_queues directly

    def save_log(self, log_type):
        # This function needs significant rework if we want to save data that wasn't displayed.
        # Current implementation saves ONLY what's in the textbox.
        # If display_logs_var is OFF, textboxes will be empty (or have old data if not cleared).

        textbox_content = ""
        default_filename = ""; ext = ".txt";
        filetypes_list = [("Text files", "*.txt"), ("All files", "*.*")]
        actual_event_count = 0

        if log_type == "host":
            textbox_content = self.host_output_textbox.get("1.0", tk.END).strip()
            actual_event_count = self.host_event_count
            default_filename = f"host_events_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv"; ext = ".csv"
            filetypes_list = [("CSV files", "*.csv"), ("All files", "*.*")]
        elif log_type == "network":
            textbox_content = self.net_output_textbox.get("1.0", tk.END).strip()
            actual_event_count = self.network_event_count
            default_filename = f"network_traffic_tshark_{datetime.datetime.now():%Y%m%d_%H%M%S}.jsonl"; ext = ".jsonl"
            filetypes_list = [("JSON Lines files", "*.jsonl"), ("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        else: return

        if self.display_logs_var.get() == 0 and actual_event_count > 0:
            messagebox.showwarning("Save Log",
                f"Log display was off. {actual_event_count} {log_type} events were collected but not shown in the textbox. "
                "Saving will result in an empty file as this function saves textbox content only. "
                "To save all collected data when display is off, a data buffering mechanism would be needed (not yet implemented).")
            if not messagebox.askyesno("Save Empty File?", "The textbox is empty because display was off. Save an empty file anyway?"):
                 return

        if not textbox_content and actual_event_count == 0 : # No content and no events collected
            messagebox.showinfo("Save Log", "Nothing to save (no events collected)."); return
        if not textbox_content and self.display_logs_var.get() == 1 : # Display was on but textbox is empty (e.g. cleared)
             messagebox.showinfo("Save Log", "Nothing to save (textbox is empty)."); return


        file_path = filedialog.asksaveasfilename(
            initialfile=default_filename, defaultextension=ext, filetypes=filetypes_list
        )
        if not file_path: return
        try:
            # Write the content from the textbox (which might be empty if display was off)
            with open(file_path, "w", encoding='utf-8', newline=None if log_type == "network" else '') as f:
                f.write(textbox_content) # Write what's in textbox
                if textbox_content and not textbox_content.endswith('\\n'): f.write('\\n')
            messagebox.showinfo("Save Successful", f"Log saved to {file_path}")
        except Exception as e: messagebox.showerror("Error Saving Log", str(e))

    def save_both_logs(self):
        if self.display_logs_var.get() == 0 and (self.host_event_count > 0 or self.network_event_count > 0) :
            messagebox.showwarning("Save Both",
                "Log display was off. Textboxes are empty. "
                "Saving will result in empty files unless off-screen buffering is implemented for this feature.")

        # Call save_log for host
        if self.host_event_count > 0 or self.host_output_textbox.get("1.0", tk.END).strip():
            self.save_log("host")
        else:
            messagebox.showinfo("Save Both", "No host events to save.")

        # Call save_log for network, allow user to cancel this one if host was cancelled.
        # save_log itself will ask for confirmation if path was not provided from dialog.
        if self.network_event_count > 0 or self.net_output_textbox.get("1.0", tk.END).strip():
            self.save_log("network")
        else:
            messagebox.showinfo("Save Both", "No network traffic (TShark) to save.")


    def clear_all_output(self, show_info=True):
        for textbox in [self.host_output_textbox, self.net_output_textbox]:
            textbox.configure(state=tk.NORMAL); textbox.delete("1.0", tk.END); textbox.configure(state=tk.DISABLED)

        # Reset counts only if monitoring is NOT active. If active, counts should continue.
        if not self.monitoring_active:
            self.host_event_count = 0
            self.network_event_count = 0
        self.update_status_bar() # Update display to reflect cleared counts if stopped.

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

The main changes are:
1.  **Event Counters & Checkbox Var**: `self.host_event_count`, `self.network_event_count`, `self.display_logs_var` initialized.
2.  **Display Logs Checkbox**: Added to `control_panel_row1`.
3.  **Status Bar Update**:
    *   `status_bar` now uses `textvariable=self.status_text_var`.
    *   `update_status_bar()` method created to format status string with event counts.
4.  **Start/Stop Logic**:
    *   `start_collection_logic()`: Resets counters, calls `update_status_bar()`, disables checkbox.
    *   `stop_collection_logic()`: Calls `update_status_bar()` for final counts, enables checkbox. Save buttons now enabled based on `*_event_count > 0`.
5.  **`process_queues()`**:
    *   Increments `host_event_count` or `network_event_count` for each valid line from the queues (ignoring self-generated UI messages).
    *   Calls `update_status_bar()` if monitoring and new lines were processed.
    *   Save buttons are re-evaluated based on counts if monitoring is stopped.
6.  **`_append_to_textbox()`**:
    *   No longer directly responsible for incrementing counts.
    *   Checks `self.display_logs_var.get() == 1` before writing to the textbox.
    *   Added a basic mechanism to limit textbox lines to `max_lines` (e.g., 5000) to prevent performance degradation with very large outputs.
7.  **`save_log()` & `save_both_logs()`**:
    *   These now primarily save what's in the textboxes.
    *   A warning is issued if the user tries to save when "Display logs" was off and events *were* collected, explaining that the saved file will be empty (as the textbox is empty). This is a crucial UX point given the current implementation. A more advanced version would buffer all data separately if display is off.
8.  **`clear_all_output()`**: Resets counts to 0 only if monitoring is *not* active. If monitoring is active, counts continue, but the displayed text is cleared. `update_status_bar()` is called.
9.  **Initial `start_collection_logic()` clear behavior**: Only clears textboxes if display logs is ON. If it was off, and user starts again, the (hidden) textboxes are not cleared of old data unless they are explicitly cleared. This is a subtle point, but current `clear_all_output(show_info=False)` handles it. I've added a small check to ensure textboxes are empty if display was off and they had old content.

The limitation of saving empty files if "Display logs" is off is acknowledged in comments and user messages.
