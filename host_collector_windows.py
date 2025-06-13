#!/usr/bin/env python3

import psutil
import time
import datetime
import sys
import os

# --- CSV Header ---
CSV_HEADER = "Timestamp,PID,UID,Comm,EventType,Syscall,SrcIP,DstIP,SrcPort,DstPort,Details"

def get_process_username(proc):
    """Safely get username, return 'N/A' on failure."""
    try:
        return proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception): # Catch generic Exception too
        return "N/A"

def get_process_exe(proc):
    """Safely get executable path, return 'N/A' on failure."""
    try:
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        return "N/A"

def get_process_name(proc):
    """Safely get process name, return 'N/A' on failure."""
    try:
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        return "N/A"

def main():
    # Print the CSV header immediately
    print(CSV_HEADER)
    sys.stdout.flush()

    seen_pids = set()
    try:
        for p in psutil.process_iter(['pid']):
            seen_pids.add(p.pid)
    except Exception as e:
        print(f"Initial PID scan error: {e}", file=sys.stderr)
        sys.stderr.flush()

    seen_connections = set()
    try:
        for conn in psutil.net_connections(kind='tcp4'):
            if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr and conn.pid is not None:
                conn_tuple = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, conn.pid)
                seen_connections.add(conn_tuple)
    except Exception as e:
        print(f"Initial connection scan error: {e}", file=sys.stderr)
        sys.stderr.flush()

    print(f"[{datetime.datetime.now().isoformat()}] host_collector_windows.py: Initialized. Monitoring new events...", file=sys.stderr)
    sys.stderr.flush()

    try:
        while True:
            current_time_iso = datetime.datetime.now().isoformat()

            processes_snapshot = list(psutil.process_iter(['pid', 'create_time']))

            for proc_info in processes_snapshot:
                try:
                    pid = proc_info.info['pid']
                    if pid not in seen_pids:
                        proc = psutil.Process(pid)

                        uid = get_process_username(proc)
                        comm = get_process_name(proc)
                        details_path = get_process_exe(proc)

                        csv_row = [
                            current_time_iso, pid, uid, comm,
                            "process_exec", "CreateProcess",
                            "", "", "", "",
                            f'"{details_path}"'
                        ]
                        print(",".join(map(str, csv_row)))
                        sys.stdout.flush()
                        seen_pids.add(pid)
                except psutil.NoSuchProcess:
                    if pid not in seen_pids: seen_pids.add(pid)
                    continue
                except (psutil.AccessDenied, Exception) as e:
                    if pid not in seen_pids: seen_pids.add(pid)
                    continue

            active_connections_this_iteration = set()
            try:
                for conn in psutil.net_connections(kind='tcp4'):
                    if conn.status == psutil.CONN_ESTABLISHED and conn.laddr and conn.raddr and conn.pid is not None:
                        conn_tuple = (conn.laddr.ip, conn.raddr.ip, conn.laddr.port, conn.raddr.port, conn.pid)
                        active_connections_this_iteration.add(conn_tuple)

                        if conn_tuple not in seen_connections:
                            conn_pid = conn.pid
                            proc_uid = "N/A"
                            proc_comm = "N/A"
                            try:
                                p_conn = psutil.Process(conn_pid)
                                proc_uid = get_process_username(p_conn)
                                proc_comm = get_process_name(p_conn)
                            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                                pass

                            csv_row = [
                                current_time_iso, conn_pid, proc_uid, proc_comm,
                                "network_connect", "connect",
                                conn.laddr.ip, conn.raddr.ip,
                                conn.laddr.port, conn.raddr.port,
                                ""
                            ]
                            print(",".join(map(str, csv_row)))
                            sys.stdout.flush()
                            seen_connections.add(conn_tuple)
            except Exception as e:
                print(f"Error during network connection scan: {e}", file=sys.stderr)
                sys.stderr.flush()

            seen_connections.intersection_update(active_connections_this_iteration)

            time.sleep(0.5)

    except KeyboardInterrupt:
        print(f"[{datetime.datetime.now().isoformat()}] host_collector_windows.py: Stopping due to KeyboardInterrupt.", file=sys.stderr)
        sys.stderr.flush()
    except Exception as e:
        print(f"[{datetime.datetime.now().isoformat()}] host_collector_windows.py: An unexpected error occurred: {e}", file=sys.stderr)
        sys.stderr.flush()
    finally:
        print(f"[{datetime.datetime.now().isoformat()}] host_collector_windows.py: Exiting.", file=sys.stderr)
        sys.stderr.flush()

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("Error: psutil library is not installed. Please install it using 'pip install psutil'.", file=sys.stderr)
        sys.stderr.flush()
        sys.exit(1)
    main()
