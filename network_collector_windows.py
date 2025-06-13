#!/usr/bin/env python3

import subprocess
import sys
import os
import psutil
import threading
import datetime
import socket
import time

# --- Configuration ---
# USER_SPECIFIED_INTERFACE: Set this to a specific interface number or name if auto-detection fails.
# Obtain the interface identifier by running "tshark -D" in your command prompt.
# Example: USER_SPECIFIED_INTERFACE = "3"  (for interface number 3)
# Example: USER_SPECIFIED_INTERFACE = "\Device\NPF_{YOUR-GUID-HERE}" (for a specific NPF device path)
# Example: USER_SPECIFIED_INTERFACE = "Ethernet 2" (for a descriptive name, if TShark supports it on your system)
# If left as "" or None, the script will try to auto-detect an interface.
USER_SPECIFIED_INTERFACE = ""

# Global variable to store the TShark process
tshark_process = None
# Global list to capture initial stderr lines for error checking
stderr_capture_list = []
stderr_capture_lock = threading.Lock()

def find_suitable_interface():
    """
    Attempts to find a suitable non-loopback network interface name for TShark.
    This is a best-effort heuristic. Manual configuration might be needed.
    TShark can often use descriptive names, but sometimes requires numbers from 'tshark -D'.
    """
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

                if has_ipv4 and has_mac :
                    candidate_interfaces.append(iface_name)
                elif has_ipv4 and not candidate_interfaces:
                    candidate_interfaces.append(iface_name)

        if candidate_interfaces:
            selected = candidate_interfaces[0]
            print(f"Info: Heuristically selected interface '{selected}' for TShark based on psutil info.", file=sys.stderr)
            return selected

    except Exception as e:
        print(f"Error finding interface with psutil: {e}. Will let TShark try its default.", file=sys.stderr)

    print("Info: Could not determine a specific interface via psutil. TShark will attempt to use its default.", file=sys.stderr)
    return None

def handle_stderr_thread_func(process, initial_capture_list=None, initial_capture_max_lines=10):
    """Reads stderr from process, optionally capturing initial lines."""
    if process and process.stderr:
        lines_captured = 0
        for line in iter(process.stderr.readline, ''):
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
    """
    Launches TShark with the given command list and reads its stdout.
    Returns True if TShark started and ran, False if it failed with a recognized adapter error or other critical failure.
    Updates global tshark_process.
    """
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
            bufsize=1,
            universal_newlines=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        stderr_thread = threading.Thread(target=handle_stderr_thread_func, args=(tshark_process, stderr_capture_list), daemon=True)
        stderr_thread.start()

        time.sleep(2.5)

        if tshark_process.poll() is not None:
            with stderr_capture_lock:
                adapter_error_indicators = [
                    "Error opening adapter", "cannot find the device specified",
                    "No such device", "could not be initiated", "failed to set hardware filter",
                    "Can't get adoration type" # Another TShark error for bad interface
                ]
                for err_line in stderr_capture_list:
                    if any(indicator.lower() in err_line.lower() for indicator in adapter_error_indicators):
                        print(f"TShark failed to start with command {' '.join(tshark_cmd_list)} due to adapter error (see TShark STDERR).", file=sys.stderr)
                        return False
            print(f"TShark exited quickly with code {tshark_process.returncode}. Command: {' '.join(tshark_cmd_list)}", file=sys.stderr)
            return False # Not necessarily adapter error, but failed to stay running

        print(f"TShark started successfully with command: {' '.join(tshark_cmd_list)}", file=sys.stderr)
        if tshark_process.stdout:
            for line in iter(tshark_process.stdout.readline, ''):
                if line:
                    sys.stdout.write(line)
                    sys.stdout.flush()
            tshark_process.stdout.close()

        tshark_process.wait()
        if tshark_process.returncode != 0 and tshark_process.returncode is not None:
             print(f"TShark process (cmd: {' '.join(tshark_cmd_list)}) exited with error code {tshark_process.returncode}", file=sys.stderr)
        return True # True means it ran, even if it exited with an error later (not an immediate adapter error)

    except FileNotFoundError:
        print(f"Error: {tshark_cmd_list[0]} not found. Please ensure TShark (Wireshark) is installed and in PATH.", file=sys.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred while trying to run TShark ({' '.join(tshark_cmd_list)}): {e}", file=sys.stderr)
        return False

def main():
    global tshark_process
    base_tshark_cmd = ["tshark.exe", "-n", "-l"]

    if USER_SPECIFIED_INTERFACE and USER_SPECIFIED_INTERFACE.strip():
        print(f"Info: Using user-specified interface: '{USER_SPECIFIED_INTERFACE}'", file=sys.stderr)
        tshark_cmd_user_specified = list(base_tshark_cmd)
        tshark_cmd_user_specified.extend(["-i", USER_SPECIFIED_INTERFACE.strip()])
        if not start_tshark_and_read_stdout(tshark_cmd_user_specified):
            print(f"Error: TShark failed to start with user-specified interface '{USER_SPECIFIED_INTERFACE}'. "
                  "Please check the interface identifier and TShark's STDERR output.", file=sys.stderr)
            # No fallback if user specifies an interface - assume they want that one or none.
        return # Exit after trying user-specified, whether success or failure.

    # --- Automatic detection if USER_SPECIFIED_INTERFACE is not set ---
    selected_interface = find_suitable_interface()
    tshark_cmd_attempt1 = list(base_tshark_cmd)

    if selected_interface:
        tshark_cmd_attempt1.extend(["-i", selected_interface])
        if start_tshark_and_read_stdout(tshark_cmd_attempt1):
            return
        print("Info: First attempt to run TShark with auto-selected interface failed. Trying TShark default.", file=sys.stderr)
    else:
        print("Info: No specific interface auto-selected by psutil. Proceeding with TShark default.", file=sys.stderr)

    # --- Attempt 2: Without -i (TShark default) ---
    tshark_cmd_attempt2 = list(base_tshark_cmd)
    if start_tshark_and_read_stdout(tshark_cmd_attempt2):
        return

    print("Error: TShark failed to start with auto-selected interface and default settings.", file=sys.stderr)
    print("Please try running 'tshark -D' in a command prompt to list available interfaces. "
          "Then, you can manually edit this script (network_collector_windows.py) "
          "by setting the 'USER_SPECIFIED_INTERFACE' variable at the top of the file "
          "to the correct interface number or name.", file=sys.stderr)
    sys.stderr.flush()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Stopping due to KeyboardInterrupt.", file=sys.stderr)
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
