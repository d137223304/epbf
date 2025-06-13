#!/usr/bin/env python3

import subprocess
import sys
import os
import psutil # To help find a suitable network interface
import threading # To handle stderr separately if needed
import datetime # Added for timestamping
import socket # Added for AF_INET

# Global variable to store the WinDump process
windump_process = None

def find_suitable_interface():
    """
    Attempts to find a suitable non-loopback network interface name.
    WinDump might require an interface number or a specific name format.
    This function provides a best-effort name.
    Users might need to adjust this or the WinDump command directly.
    """
    try:
        # Get all network interface addresses
        addrs = psutil.net_if_addrs()
        # Get interface stats to check if they are up
        stats = psutil.net_if_stats()

        candidate_interfaces = []
        for iface_name, iface_addrs in addrs.items():
            if iface_name in stats and stats[iface_name].isup:
                # Check for a non-loopback IPv4 address
                for addr in iface_addrs:
                    if addr.family == psutil.AF_LINK: # Check for MAC address as a proxy for physical interfaces
                        if not iface_name.lower().startswith("loopback") and not iface_name.lower().startswith("isatap"):
                             # Prefer interfaces with an IPv4 address
                            for check_addr in iface_addrs:
                                if check_addr.family == socket.AF_INET:
                                    candidate_interfaces.append(iface_name)
                                    break # Found IPv4, add this interface name
                            break # Done with this interface name's addresses

        if candidate_interfaces:
            # Try to return a name that WinDump might recognize.
            # This is heuristic. WinDump often uses adapter names from its own enumeration.
            # For now, return the first plausible candidate.
            # Example: "Ethernet", "Wi-Fi"
            # These names from psutil might work with WinDump's -i flag on modern versions.
            # If WinDump strictly needs numbers, this will require manual adjustment by the user
            # or parsing `windump -D` output.
            print(f"Info: Selected interface '{candidate_interfaces[0]}' based on psutil info.", file=sys.stderr)
            return candidate_interfaces[0]

    except Exception as e:
        print(f"Error finding interface: {e}. WinDump will try its default.", file=sys.stderr)

    # Fallback: Let WinDump try to pick a default interface or use a common number
    # If -i is omitted, WinDump often picks the "best" one or fails if multiple are ambiguous.
    # Using a common default like '1' can be risky if it's not the correct one.
    print("Info: Could not determine a specific interface, WinDump will use its default or may require manual configuration.", file=sys.stderr)
    return None # Let WinDump decide, or user can modify to provide a number like "1"


def main():
    global windump_process

    # Assumption: WinDump.exe is in PATH and Npcap/WinPcap is installed.
    windump_cmd = ["windump.exe", "-n", "-l"] # -n: no name resolution, -l: line-buffered

    selected_interface = find_suitable_interface()
    if selected_interface:
        # If WinDump on Windows expects interface *names* (like "Ethernet 0")
        # this might work. If it expects *numbers* from `windump -D`, this will fail
        # and the user would need to manually set the interface (e.g. by number).
        windump_cmd.extend(["-i", selected_interface])
    else:
        print("Warning: No specific interface provided to WinDump. It will use its default.", file=sys.stderr)
        # Alternatively, could try with a common interface number, e.g. # windump_cmd.extend(["-i", "1"])
        # But this is a guess and might not be correct.

    print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Starting WinDump with command: {' '.join(windump_cmd)}", file=sys.stderr)
    sys.stderr.flush()

    try:
        # CREATE_NO_WINDOW flag prevents WinDump console from appearing
        windump_process = subprocess.Popen(
            windump_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, # Capture stderr to avoid polluting its own stdout
            text=True,
            bufsize=1, # Line buffered
            universal_newlines=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # Thread to print WinDump's stderr to this script's stderr (for debugging)
        def handle_stderr():
            if windump_process and windump_process.stderr:
                for line in iter(windump_process.stderr.readline, ''):
                    if line:
                        print(f"WinDump STDERR: {line.strip()}", file=sys.stderr)
                        sys.stderr.flush()

        stderr_thread = threading.Thread(target=handle_stderr, daemon=True)
        stderr_thread.start()

        # Read from WinDump's stdout and print to this script's stdout
        if windump_process.stdout:
            for line in iter(windump_process.stdout.readline, ''):
                if line:
                    sys.stdout.write(line) # Write directly, line already has newline
                    sys.stdout.flush()
            windump_process.stdout.close()

        # Wait for the process to complete (shouldn't happen unless error or Ctrl+C)
        windump_process.wait()
        if windump_process.returncode != 0 and windump_process.returncode is not None : # None if terminated by signal
             print(f"WinDump process exited with error code {windump_process.returncode}", file=sys.stderr)


    except FileNotFoundError:
        print("Error: WinDump.exe not found. Please ensure it is installed and in your system PATH.", file=sys.stderr)
        sys.stderr.flush()
    except KeyboardInterrupt:
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Stopping due to KeyboardInterrupt.", file=sys.stderr)
        sys.stderr.flush()
    except Exception as e:
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: An unexpected error occurred: {e}", file=sys.stderr)
        sys.stderr.flush()
    finally:
        if windump_process and windump_process.poll() is None:
            print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Terminating WinDump process.", file=sys.stderr)
            sys.stderr.flush()
            windump_process.terminate()
            try:
                windump_process.wait(timeout=5) # Wait for graceful termination
            except subprocess.TimeoutExpired:
                print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: WinDump did not terminate gracefully, killing.", file=sys.stderr)
                windump_process.kill()
        print(f"[{datetime.datetime.now().isoformat()}] network_collector_windows.py: Exiting.", file=sys.stderr)
        sys.stderr.flush()

if __name__ == "__main__":
    # import datetime # Ensure datetime is available in main's scope if not already - already imported
    # import socket # For AF_INET in find_suitable_interface - already imported
    main()
