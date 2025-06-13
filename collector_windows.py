#!/usr/bin/env python3

import psutil
import time
import datetime
import sys
import os

def get_process_details(proc):
    """Safely get details for a psutil.Process object."""
    try:
        pid = proc.pid
        name = proc.name()
        username = proc.username()
        # To get the full path, use exe(). If it fails, cmdline() might give some info.
        try:
            details_path = proc.exe()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            try:
                details_path = " ".join(proc.cmdline()) if proc.cmdline() else "N/A (access denied or no cmdline)"
            except (psutil.AccessDenied, psutil.ZombieProcess, psutil.NoSuchProcess):
                 details_path = "N/A (cannot access cmdline)"
        except psutil.NoSuchProcess: # Process ended before exe could be read
            return None # Skip this process

        if not details_path: # If exe() returned empty
            details_path = "N/A (empty exe path)"

        return pid, name, username, details_path
    except psutil.NoSuchProcess: # Process might have terminated
        return None
    except (psutil.AccessDenied, psutil.ZombieProcess) as e:
        # Log access denied but try to provide minimal info if possible
        # print(f"Access denied for PID {proc.pid if hasattr(proc, 'pid') else 'unknown'}: {e}", file=sys.stderr)
        pid = proc.pid if hasattr(proc, 'pid') else "N/A"
        name = "N/A (access denied)"
        username = "N/A (access denied)"
        details_path = f"Access Denied: {e}"
        # Still return a tuple so it can be unpacked, but with clear indicators of issues
        return pid, name, username, details_path


def main():
    header = "Timestamp,PID,UID,Comm,EventType,Syscall,SrcIP,DstIP,SrcPort,DstPort,Details"
    print(header)
    sys.stdout.flush()

    seen_pids = set()
    # For connections, store a tuple: (local_addr, remote_addr, local_port, remote_port, pid)
    # This helps identify unique established TCPv4 connections associated with a PID.
    seen_connections = set()

    # Get initial set of PIDs and connections to avoid reporting all existing ones at start
    try:
        for proc in psutil.process_iter(['pid']):
            seen_pids.add(proc.pid)

        # For connections, only consider TCPv4 and ESTABLISHED
        # This initial population helps avoid flooding with pre-existing connections
        for conn in psutil.net_connections(kind='tcp4'):
            if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr:
                # Ensure pid is available, sometimes it might not be for system connections
                # or due to permissions.
                pid = conn.pid if conn.pid is not None else 0 # Use 0 or similar for unknown PID
                conn_tuple = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, pid)
                seen_connections.add(conn_tuple)

    except Exception as e:
        print(f"Error during initial population: {e}", file=sys.stderr)
        sys.stderr.flush()


    print(f"[{datetime.datetime.now().isoformat()}] collector_windows.py running. Monitoring processes and connections...", file=sys.stderr)
    sys.stderr.flush()

    try:
        while True:
            current_time_iso = datetime.datetime.now().isoformat()

            # --- Process Monitoring ---
            current_pids = set()
            for proc in psutil.process_iter(['pid', 'name', 'username', 'exe', 'cmdline']):
                current_pids.add(proc.pid)
                if proc.pid not in seen_pids:
                    details = get_process_details(proc)
                    if details:
                        pid, name, username, path = details
                        # UID on Windows is often a SID or DOMAIN\username. psutil returns username.
                        # Syscall for process creation is 'exec' as per requirements.
                        csv_line = f"{current_time_iso},{pid},{username},{name},process_exec,exec,,,,,\"{path}\""
                        print(csv_line)
                        sys.stdout.flush()
                        seen_pids.add(pid)

            # Optional: Handle terminated PIDs if needed, though not specified in requirements
            # terminated_pids = seen_pids - current_pids
            # for pid in terminated_pids:
            #     # print(f"{current_time_iso},{pid},,,process_exit,,,,,,Terminated")
            # seen_pids = current_pids


            # --- Network Monitoring ---
            # Only interested in TCPv4 established connections
            current_connections_map = {} # Store full conn object to get PID info later

            for conn in psutil.net_connections(kind='tcp4'):
                if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr:
                    # conn.pid can be None if process info is not available (e.g. system, or insufficient perms)
                    pid = conn.pid if conn.pid is not None else 0 # Use a placeholder like 0 for PID if None
                    conn_tuple = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, pid)

                    if conn_tuple not in seen_connections:
                        proc_name = "N/A"
                        proc_username = "N/A"
                        if conn.pid:
                            try:
                                p = psutil.Process(conn.pid)
                                proc_name = p.name()
                                proc_username = p.username()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                # Process might have ended or access is denied
                                proc_name = "N/A (process ended or access denied)"
                                proc_username = "N/A (process ended or access denied)"

                        # Syscall for network connection is 'connect'
                        csv_line = (
                            f"{current_time_iso},{conn.pid if conn.pid else '0'},{proc_username},{proc_name},"
                            f"network_connect,connect,"
                            f"{conn.laddr.ip},{conn.raddr.ip},{conn.laddr.port},{conn.raddr.port},"
                            f"TCPv4" # Details for network connection
                        )
                        print(csv_line)
                        sys.stdout.flush()
                        seen_connections.add(conn_tuple)

            # Clean up old connections from seen_connections that are no longer active
            # This is important to detect if a connection with the same tuple reappears later
            active_conn_tuples_now = set()
            for conn in psutil.net_connections(kind='tcp4'):
                 if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr:
                    pid = conn.pid if conn.pid is not None else 0
                    active_conn_tuples_now.add((conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, pid))
            seen_connections.intersection_update(active_conn_tuples_now)


            time.sleep(1) # Adjust poll interval as needed

    except KeyboardInterrupt:
        print(f"[{datetime.datetime.now().isoformat()}] Windows collector stopped by user (KeyboardInterrupt).", file=sys.stderr)
        sys.stderr.flush()
    except Exception as e:
        print(f"[{datetime.datetime.now().isoformat()}] Error in Windows collector: {e}", file=sys.stderr)
        sys.stderr.flush()
    finally:
        print(f"[{datetime.datetime.now().isoformat()}] Windows collector exiting.", file=sys.stderr)
        sys.stderr.flush()

if __name__ == "__main__":
    # Ensure psutil is installed
    try:
        import psutil
    except ImportError:
        print("Error: psutil library is not installed. Please install it using 'pip install psutil'.", file=sys.stderr)
        sys.stderr.flush()
        sys.exit(1)
    main()
