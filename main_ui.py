import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import sys
import os
import csv
from datetime import datetime

class HostMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Host Event Monitor")
        self.root.geometry("800x600")

        self.collector_process = None
        self.output_thread = None
        self.is_collecting = False

        # --- Top Frame for Controls ---
        control_frame = ttk.Frame(root, padding="10")
        control_frame.pack(side=tk.TOP, fill=tk.X)

        self.start_button = ttk.Button(control_frame, text="Start Collection", command=self.start_collection)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Collection", command=self.stop_collection, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.save_button = ttk.Button(control_frame, text="Save to File", command=self.save_to_file)
        self.save_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(control_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # --- Output Text Area ---
        self.output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED, height=20)
        self.output_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # --- Status Bar ---
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Stopped")
        self.status_bar_label = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, foreground="red", padding="5") # Store as instance variable
        self.status_bar_label.pack(side=tk.BOTTOM, fill=tk.X)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _get_collector_script_path(self):
        base_path = os.path.dirname(os.path.abspath(__file__))
        if sys.platform.startswith("linux"):
            return os.path.join(base_path, "collector_linux.py")
        elif sys.platform.startswith("win"):
            return os.path.join(base_path, "collector_windows.py")
        else:
            messagebox.showerror("Unsupported OS", f"Operating system {sys.platform} is not supported.")
            return None

    def start_collection(self):
        collector_script = self._get_collector_script_path()
        if not collector_script:
            return

        if not os.path.exists(collector_script):
            messagebox.showerror("Error", f"Collector script not found: {collector_script}. Please ensure it is in the same directory as main_ui.py.")
            return

        if self.is_collecting:
            messagebox.showwarning("Collection Running", "Collection is already in progress.")
            return

        self.is_collecting = True
        self.clear_output()
        self.output_area.config(state=tk.NORMAL)
        self.output_area.insert(tk.END, f"Attempting to start {os.path.basename(collector_script)}...\n")
        self.output_area.config(state=tk.DISABLED)
        self.output_area.see(tk.END)

        try:
            self.collector_process = subprocess.Popen(
                [sys.executable, collector_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform.startswith("win") else 0
            )
            self._append_output(f"{os.path.basename(collector_script)} started. PID: {self.collector_process.pid}\n")

            self.output_thread = threading.Thread(target=self._read_output, daemon=True)
            self.output_thread.start()

            self.status_var.set("Status: Running")
            self.status_bar_label.config(foreground="green")

            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

        except Exception as e:
            self.is_collecting = False
            messagebox.showerror("Error Starting Collector", str(e))
            self.status_var.set("Status: Stopped")
            self.status_bar_label.config(foreground="red")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self._append_output(f"Error starting collector: {e}\n")


    def _read_output(self):
        if self.collector_process and self.collector_process.stdout:
            for line in iter(self.collector_process.stdout.readline, ''):
                if line:
                    self.root.after(0, self._append_output, line)
                if not self.is_collecting:
                    break

            # Process remaining stderr after stdout is done or if an error occurs
            if self.collector_process:
                stderr_output = ""
                try:
                    # Non-blocking read for stderr if possible, or handle termination
                    if self.collector_process.stderr:
                        stderr_output = self.collector_process.stderr.read()
                except Exception as e:
                     # Handle cases where stderr might not be available (e.g., process already terminated)
                    stderr_output = f"Error reading stderr: {e}\n"

                if stderr_output:
                    self.root.after(0, self._append_output, f"STDERR: {stderr_output}")

        self.root.after(0, self._collection_finished)


    def _append_output(self, text):
        self.output_area.config(state=tk.NORMAL)
        self.output_area.insert(tk.END, text)
        self.output_area.see(tk.END)
        self.output_area.config(state=tk.DISABLED)

    def stop_collection(self):
        if not self.is_collecting or not self.collector_process:
            # messagebox.showwarning("Collection Not Running", "No collection process is currently active.") # Can be noisy
            if not self.collector_process and self.is_collecting: # Edge case: flag set but process died
                 self._collection_finished() # Reset UI
            return

        current_pid = self.collector_process.pid if self.collector_process else "N/A"
        self._append_output(f"\nAttempting to stop collector process (PID: {current_pid})...\n")
        self.is_collecting = False

        if self.collector_process:
            try:
                if self.collector_process.poll() is None:
                    self.collector_process.terminate()
                    try:
                        self.collector_process.wait(timeout=5)
                        self._append_output(f"Collector process (PID: {current_pid}) terminated.\n")
                    except subprocess.TimeoutExpired:
                        self._append_output(f"Collector process (PID: {current_pid}) did not terminate gracefully, killing...\n")
                        self.collector_process.kill()
                        self.collector_process.wait(timeout=2) # Wait for kill
                        self._append_output(f"Collector process (PID: {current_pid}) killed.\n")
                else:
                    self._append_output(f"Collector process (PID: {current_pid}) already terminated.\n")
            except Exception as e:
                self._append_output(f"Error during collector process termination (PID: {current_pid}): {e}\n")
            finally:
                self.collector_process = None

        # Call _collection_finished directly to ensure UI updates,
        # as the reading thread might have already exited or might be blocked.
        self._collection_finished()


    def _collection_finished(self):
        self.is_collecting = False # Explicitly set flag

        # Clean up collector_process if it wasn't done in stop_collection
        if self.collector_process:
            if self.collector_process.poll() is None: # Still running?
                try:
                    self.collector_process.kill()
                    self.collector_process.wait(timeout=1) # Brief wait
                except Exception:
                    pass # Best effort
            self.collector_process = None

        self.status_var.set("Status: Stopped")
        if hasattr(self, 'status_bar_label'): # Check if status_bar_label exists
             self.status_bar_label.config(foreground="red")

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        # self._append_output("Collection stopped.\n") # This can be redundant if stop_collection also appends
        # Check thread status
        if self.output_thread and self.output_thread.is_alive():
            # Thread should exit due to self.is_collecting = False
            # and readline returning EOF or empty string.
            # No explicit join() here to avoid blocking UI if thread is stuck,
            # daemon=True ensures it exits with main.
            pass

    def save_to_file(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not file_path:
            return

        try:
            content = self.output_area.get(1.0, tk.END).strip() # Get all content and strip trailing newline

            # A simple check if it looks like CSV.
            # More robust would be to try parsing it with csv module or store data in a list of lists.
            lines = content.split('\n')
            is_likely_csv = False
            if lines:
                # Check if the first non-empty line looks like a header or data
                for line in lines:
                    if line.strip(): # Find first non-empty line
                        if "Timestamp,PID,UID,Comm,EventType,Syscall" in line or (',' in line and len(line.split(',')) > 3):
                            is_likely_csv = True
                        break

            if not is_likely_csv:
                 if not messagebox.askyesno("Save Warning", "The output may not be in the expected CSV format or is empty. Save anyway?"):
                    return

            with open(file_path, "w", newline="") as f:
                # For now, write the raw text area content.
                # If strict CSV is needed, this part would need to parse 'content'
                # and use a csv.writer, filtering out non-CSV lines.
                f.write(content + '\n') # Ensure a newline at the end if stripped
            messagebox.showinfo("Save Successful", f"Output saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error Saving File", str(e))

    def clear_output(self):
        self.output_area.config(state=tk.NORMAL)
        self.output_area.delete(1.0, tk.END)
        self.output_area.config(state=tk.DISABLED)

    def on_closing(self):
        if self.is_collecting: # Check self.is_collecting first
            if messagebox.askyesno("Confirm Exit", "Collection is running. Are you sure you want to exit? This will stop the collection."):
                self.stop_collection()
                # Give a moment for stop_collection to attempt cleanup
                self.root.after(200, self.root.destroy)
            else:
                return
        else:
            self.root.destroy()

if __name__ == "__main__":
    app_root = tk.Tk()
    gui = HostMonitorApp(app_root)
    app_root.mainloop()
