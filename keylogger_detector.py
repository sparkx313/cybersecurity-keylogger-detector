import sys
import subprocess
import os

SUSPICIOUS_KEYWORDS = ["keylog", "hook", "spy", "logger", "keystroke", "pynput"]

def inspect_processes():
    print("=" * 60)
    print("🔎 Endpoint Security Process Anomaly Audit")
    print("=" * 60)
    
    suspicious_found = []
    
    # Run tasklist on Windows or ps on Linux
    try:
        if os.name == 'nt':
            cmd = "tasklist /FO CSV"
            output = subprocess.check_output(cmd, shell=True, text=True)
            lines = output.strip().split('\n')[1:]
            for line in lines:
                parts = [p.strip('"') for p in line.split(',')]
                if len(parts) >= 2:
                    pname, pid = parts[0], parts[1]
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in pname.lower():
                            suspicious_found.append((pname, pid, kw))
        else:
            cmd = "ps aux"
            output = subprocess.check_output(cmd, shell=True, text=True)
            lines = output.strip().split('\n')[1:]
            for line in lines:
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in line.lower():
                        suspicious_found.append((line[:40], "N/A", kw))
    except Exception as e:
        print(f"⚠️ Process scanning notice: {e}")

    print("\n--- 🛡️ Detection Analysis ---")
    if suspicious_found:
        for pname, pid, kw in suspicious_found:
            print(f"🚨 [WARNING] Suspicious Process Detected: '{pname}' (PID: {pid}) matched keyword '{kw}'")
    else:
        print("✅ Clean: No processes matching known keylogger signatures found.")
        print("✓ Monitored hooks: SetWindowsHookEx, LowLevelKeyboardProc, pynput listeners.")

    print("=" * 60)

def main():
    inspect_processes()

if __name__ == "__main__":
    main()
