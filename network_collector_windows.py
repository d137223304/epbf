#!/usr/bin/env python3

import subprocess
import sys
import os
import psutil
import threading
import datetime
import socket
import time
import argparse # For command-line arguments

# --- Configuration ---
# USER_SPECIFIED_INTERFACE (in-script variable): Set this as a fallback if no CLI argument is given.
# Example: USER_SPECIFIED_INTERFACE = "3"
USER_SPECIFIED_INTERFACE = ""

# Global variable to store the TShark process
tshark_process = None
stderr_capture_list = []
stderr_capture_lock = threading.Lock()

def find_suitable_interface():
    """Attempts to find a suitable non-loopback network interface name for TShark."""
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        candidate_interfaces = []
        for iface_name, iface_addrs in addrs.items():
            if iface_name in stats and stats[iface_name].isup:
                is_loopback = "loopback" in iface_name.lower() or "isatap" in iface_name.lower()
                if is_loopback: continue
                has_ipv4 = any(addr.family == socket.AF_INET for addr in iface_addrs)
                has_mac = any(addr.family == psutil.AF_LINK for addr in iface_addrs)
                if has_ipv4 and has_mac: candidate_interfaces.append(iface_name)
                elif has_ipv4 and not candidate_interfaces: candidate_interfaces.append(iface_name)

        if candidate_interfaces:
            selected = candidate_interfaces[0]
            print(f"Info: Heuristically selected interface '{selected}' for TShark based on psutil info.", file=sys.stderr)
            return selected
    except Exception as e:
        print(f"Error finding interface with psutil: {e}. Will let TShark try its default.", file=sys.stderr)
    print("Info: Could not determine a specific interface via psutil for TShark.", file=sys.stderr)
    return None

def handle_stderr_thread_func(process, initial_capture_list=None, initial_capture_max_lines=10):
    """Reads stderr from process, optionally capturing initial lines."""
    if process and process.stderr:
        lines_captured = 0
        for line in iter(process.stderr.readline, ''): # Stays text, Popen handles decoding for stderr too if encoding is set
            if line:
                line_strip = line.strip()
                print(f"TShark STDERR: {line_strip}", file=sys.stderr)
                sys.stderr.flush()
                if initial_capture_list is not None and lines_captured < initial_capture_max_lines:
                    with stderr_capture_lock:
                        initial_capture_list.append(line_strip)
                    lines_captured += 1
        process.stderr.close()

def start_tshark_and_read_stdout(tshark_cmd_list):
    """Launches TShark and reads its stdout. Returns True on success, False on critical/adapter error."""
    global tshark_process, stderr_capture_list
    stderr_capture_list.clear()
    print(f"[{datetime.datetime.now().isoformat()}] Attempting to start TShark with command: {' '.join(tshark_cmd_list)}", file=sys.stderr)
    sys.stderr.flush()

    try:
        tshark_process = subprocess.Popen(
            tshark_cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',     # Specify UTF-8 encoding for stdout/stderr
            errors='replace',     # Handle potential decoding errors gracefully
            bufsize=1,
            universal_newlines=True, # With text=True, this helps normalize line endings
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        # Stderr will also be decoded with utf-8, errors='replace' due to Popen's behavior with encoding.
        stderr_thread = threading.Thread(target=handle_stderr_thread_func, args=(tshark_process, stderr_capture_list), daemon=True)
        stderr_thread.start()
        time.sleep(2.5)

        if tshark_process.poll() is not None:
            with stderr_capture_lock:
                adapter_error_indicators = [
                    "Error opening adapter", "cannot find the device specified", "No such device",
                    "could not be initiated", "failed to set hardware filter", "Can't get adoration type"
                ]
                for err_line in stderr_capture_list:
                    if any(indicator.lower() in err_line.lower() for indicator in adapter_error_indicators):
                        print(f"TShark failed to start (command: {' '.join(tshark_cmd_list)}) due to adapter error.", file=sys.stderr)
                        return False
            print(f"TShark exited quickly (code {tshark_process.returncode}, command: {' '.join(tshark_cmd_list)}).", file=sys.stderr)
            return False

        print(f"TShark started successfully (command: {' '.join(tshark_cmd_list)}).", file=sys.stderr)
        if tshark_process.stdout:
            for line in iter(tshark_process.stdout.readline, ''): # line will be str
                if line:
                    sys.stdout.write(line) # Write str directly
                    sys.stdout.flush()
            tshark_process.stdout.close()
        tshark_process.wait()
        if tshark_process.returncode != 0 and tshark_process.returncode is not None:
             print(f"TShark process (cmd: {' '.join(tshark_cmd_list)}) exited with error code {tshark_process.returncode}.", file=sys.stderr)
        return True
    except FileNotFoundError:
        print(f"Error: {tshark_cmd_list[0]} not found. Ensure TShark (Wireshark) is installed and in PATH.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Unexpected error running TShark ({' '.join(tshark_cmd_list)}): {e}", file=sys.stderr)
        return False

def main(cli_interface_arg=None):
    print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Script launched.", file=sys.stderr)
    print(f"[DEBUG network_collector.py] Raw sys.argv: {sys.argv}", file=sys.stderr)
    print(f"[DEBUG network_collector.py] Value of cli_interface_arg in main(): '{cli_interface_arg}'", file=sys.stderr)
    sys.stderr.flush()

    global tshark_process
    base_tshark_cmd = ["tshark.exe", "-n", "-l"]
    interface_to_use = None
    source_of_interface = "None"

    if cli_interface_arg:
        interface_to_use = cli_interface_arg
        source_of_interface = "Command-Line Argument"
        print(f"Info: Using interface '{interface_to_use}' from {source_of_interface}.", file=sys.stderr)
        tshark_cmd_final = list(base_tshark_cmd)
        tshark_cmd_final.extend(["-i", interface_to_use])
        if not start_tshark_and_read_stdout(tshark_cmd_final):
            print(f"Error: TShark failed with command-line specified interface '{interface_to_use}'.", file=sys.stderr)
        return

    if USER_SPECIFIED_INTERFACE and USER_SPECIFIED_INTERFACE.strip():
        interface_to_use = USER_SPECIFIED_INTERFACE.strip()
        source_of_interface = "In-Script Variable (USER_SPECIFIED_INTERFACE)"
        print(f"Info: Using interface '{interface_to_use}' from {source_of_interface}.", file=sys.stderr)
        tshark_cmd_final = list(base_tshark_cmd)
        tshark_cmd_final.extend(["-i", interface_to_use])
        if not start_tshark_and_read_stdout(tshark_cmd_final):
            print(f"Error: TShark failed with in-script specified interface '{interface_to_use}'.", file=sys.stderr)
        return

    print(f"Info: No interface specified by CLI or in-script variable. Attempting auto-detection.", file=sys.stderr)
    selected_interface = find_suitable_interface()
    tshark_cmd_attempt1 = list(base_tshark_cmd)

    if selected_interface:
        source_of_interface = "Auto-detection (psutil)"
        tshark_cmd_attempt1.extend(["-i", selected_interface])
        if start_tshark_and_read_stdout(tshark_cmd_attempt1):
            return
        print(f"Info: Attempt with auto-selected interface ('{selected_interface}') failed. Trying TShark default.", file=sys.stderr)
    else:
        source_of_interface = "Auto-detection (psutil failed)"
        print(f"Info: No specific interface auto-selected. Proceeding with TShark default.", file=sys.stderr)

    source_of_interface = "TShark Default"
    print(f"Info: Attempting to run TShark with its default interface.", file=sys.stderr)
    tshark_cmd_attempt2 = list(base_tshark_cmd)
    if start_tshark_and_read_stdout(tshark_cmd_attempt2):
        return

    print(f"Error: TShark failed to start using method: {source_of_interface}.", file=sys.stderr)
    print("Please try running 'tshark -D' in a command prompt to list available interfaces. "
          "Then, provide the correct interface via the command-line (-i INTERFACE), "
          "by setting 'USER_SPECIFIED_INTERFACE' at the top of this script, "
          "or ensure TShark's default works on your system.", file=sys.stderr)
    sys.stderr.flush()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network collector script using TShark. Captures network traffic.")
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface identifier to capture on (e.g., number from 'tshark -D' or name). "
                             "Overrides in-script USER_SPECIFIED_INTERFACE and auto-detection.")
    args = parser.parse_args()

    try:
        main(cli_interface_arg=args.interface)
    except KeyboardInterrupt:
        print(f"\n[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Stopping due to KeyboardInterrupt.", file=sys.stderr)
    finally:
        if tshark_process and tshark_process.poll() is None:
            print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Terminating TShark process.", file=sys.stderr)
            tshark_process.terminate()
            try:
                tshark_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: TShark did not terminate gracefully, killing.", file=sys.stderr)
                tshark_process.kill()
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Exiting.", file=sys.stderr)
        sys.stderr.flush()
