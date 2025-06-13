#!/usr/bin/env python3

import subprocess
import sys
import os
import psutil
import threading
import datetime
import socket
import time # For sleep

# Global variable to store the WinDump process
windump_process = None
# Global list to capture initial stderr lines for error checking
stderr_capture_list = []
stderr_capture_lock = threading.Lock()

def find_suitable_interface():
    """
    Attempts to find a suitable non-loopback network interface name.
    This is a best-effort heuristic. Manual configuration might be needed.
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
                # Prioritize interfaces with IPv4 that seem physical (have a MAC)
                # This is still a heuristic.
                has_mac = any(addr.family == psutil.AF_LINK for addr in iface_addrs)

                if has_ipv4 and has_mac : # Good candidate
                    candidate_interfaces.append(iface_name)
                elif has_ipv4 and not candidate_interfaces: # Fallback if no MAC interfaces with IPv4 found
                    candidate_interfaces.append(iface_name)

        if candidate_interfaces:
            # Prefer shorter names, or names that don't look like GUIDs, if multiple candidates
            # Simple: just take the first one for now.
            selected = candidate_interfaces[0]
            print(f"Info: Heuristically selected interface '{selected}' based on psutil info.", file=sys.stderr)
            return selected

    except Exception as e:
        print(f"Error finding interface with psutil: {e}. Will let WinDump try its default.", file=sys.stderr)

    print("Info: Could not determine a specific interface via psutil. WinDump will attempt to use its default.", file=sys.stderr)
    return None

def handle_stderr_thread_func(process, initial_capture_list=None, initial_capture_max_lines=5):
    """Reads stderr from process, optionally capturing initial lines."""
    if process and process.stderr:
        lines_captured = 0
        for line in iter(process.stderr.readline, ''):
            if line:
                line_strip = line.strip()
                print(f"WinDump STDERR: {line_strip}", file=sys.stderr)
                sys.stderr.flush()
                if initial_capture_list is not None and lines_captured < initial_capture_max_lines:
                    with stderr_capture_lock:
                        initial_capture_list.append(line_strip)
                    lines_captured += 1
        process.stderr.close()

def start_windump_and_read_stdout(windump_cmd_list):
    """
    Launches WinDump with the given command list and reads its stdout.
    Returns True if WinDump started and ran (even if it exits later),
    False if it failed immediately with a recognized adapter error.
    Updates global windump_process.
    """
    global windump_process, stderr_capture_list

    stderr_capture_list.clear() # Clear for this attempt

    print(f"[{datetime.datetime.now().isoformat()}] Attempting to start WinDump with command: {' '.join(windump_cmd_list)}", file=sys.stderr)
    sys.stderr.flush()

    try:
        windump_process = subprocess.Popen(
            windump_cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        stderr_thread = threading.Thread(target=handle_stderr_thread_func, args=(windump_process, stderr_capture_list), daemon=True)
        stderr_thread.start()

        # Brief pause to see if WinDump fails immediately
        time.sleep(2.0) # Wait 2 seconds

        if windump_process.poll() is not None: # Process has terminated
            # Check if it's the adapter error
            with stderr_capture_lock:
                for err_line in stderr_capture_list:
                    if "Error opening adapter" in err_line or "The system cannot find the device specified" in err_line:
                        print(f"WinDump failed to start with command {' '.join(windump_cmd_list)} due to adapter error.", file=sys.stderr)
                        return False # Signal failure for fallback
            # Some other early exit error
            print(f"WinDump exited quickly with code {windump_process.returncode}. Command: {' '.join(windump_cmd_list)}", file=sys.stderr)
            return False # Signal failure

        # If process is still running, it likely started OK.
        print(f"WinDump started successfully with command: {' '.join(windump_cmd_list)}", file=sys.stderr)
        if windump_process.stdout:
            for line in iter(windump_process.stdout.readline, ''):
                if line:
                    sys.stdout.write(line)
                    sys.stdout.flush()
            windump_process.stdout.close()

        windump_process.wait() # Wait for it to finish (e.g. if main loop is exited by external signal)
        if windump_process.returncode != 0 and windump_process.returncode is not None:
             print(f"WinDump process (cmd: {' '.join(windump_cmd_list)}) exited with error code {windump_process.returncode}", file=sys.stderr)
        return True # Ran successfully or exited normally after running

    except FileNotFoundError:
        print(f"Error: {windump_cmd_list[0]} not found. Please ensure WinDump is installed and in PATH.", file=sys.stderr)
        return False # Critical failure
    except Exception as e:
        print(f"An unexpected error occurred while trying to run WinDump ({' '.join(windump_cmd_list)}): {e}", file=sys.stderr)
        return False # Critical failure

def main():
    global windump_process

    # --- Attempt 1: With psutil-derived interface name ---
    base_windump_cmd = ["windump.exe", "-n", "-l"]
    windump_cmd_attempt1 = list(base_windump_cmd) # Make a copy

    selected_interface = find_suitable_interface()
    if selected_interface:
        windump_cmd_attempt1.extend(["-i", selected_interface])
        # If find_suitable_interface returned None, windump_cmd_attempt1 will not have -i,
        # effectively making it same as attempt 2. So, only try specific if selected.

        if start_windump_and_read_stdout(windump_cmd_attempt1):
            return # Success or normal exit

        # If we are here, start_windump_and_read_stdout returned False, meaning an adapter error.
        print("Info: First attempt to run WinDump with selected interface failed. Trying WinDump default.", file=sys.stderr)
    else:
        # find_suitable_interface returned None, so proceed directly to default.
        print("Info: No specific interface selected by psutil. Proceeding with WinDump default.", file=sys.stderr)


    # --- Attempt 2: Without -i (WinDump default) ---
    # This command will be just ["windump.exe", "-n", "-l"]
    windump_cmd_attempt2 = list(base_windump_cmd)
    if start_windump_and_read_stdout(windump_cmd_attempt2):
        return # Success or normal exit

    # If both attempts fail
    print("Error: WinDump failed to start with both selected interface and default settings.", file=sys.stderr)
    print("Please try running 'windump -D' in a command prompt to list available interfaces, "
          "then manually edit this script (network_collector_windows.py) to specify the correct interface number or name for the '-i' flag.", file=sys.stderr)
    sys.stderr.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Stopping due to KeyboardInterrupt.", file=sys.stderr)
    finally:
        if windump_process and windump_process.poll() is None:
            print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Terminating WinDump process.", file=sys.stderr)
            windump_process.terminate()
            try:
                windump_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                windump_process.kill()
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Exiting.", file=sys.stderr)
        sys.stderr.flush()
