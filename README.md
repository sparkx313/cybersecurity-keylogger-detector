# Static PE keyboard API indicator audit

This command-line tool inspects Windows Portable Executable (PE) files (`.exe` and `.dll`) without executing them. It reads the normal and delay import tables and reports selected Windows APIs associated with keyboard hooks, key-state polling, and raw keyboard input.

It is a small static-analysis utility for triage and code review. It does **not** monitor running processes, inspect installed hooks, detect every keylogger, or determine whether a file is malicious.

## Requirements

- Python 3.10 or newer
- `pefile`

Install the dependency:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Inspect one file:

```powershell
python keylogger_detector.py C:\Path\To\program.exe
```

Inspect PE files directly inside a directory, or include its subdirectories with `--recursive`:

```powershell
python keylogger_detector.py C:\Path\To\Windows\System32 --recursive
```

Write a machine-readable report to standard output:

```powershell
python keylogger_detector.py --format json C:\Path\To\program.exe
```

The JSON report includes each file's SHA-256, size, machine type, parsed import count, indicator matches, input errors, and limitations. The text format is the default.

## Interpreting results

The report groups matches into these indicator categories:

- Windows keyboard-hook registration (`SetWindowsHookExA/W`)
- Keyboard state polling (`GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`)
- Raw keyboard input registration or reading (`RegisterRawInputDevices`, `GetRawInputData`)

A match means the import table references one of these APIs. Legitimate accessibility, input, gaming, and security programs may use them. Imports can also be unused. A missing match does not establish that a file is safe: software can resolve APIs dynamically, hide imports through packing, or use techniques outside this tool's narrow scope.

Exit codes are `0` when files were parsed without matching imports, `1` when at least one indicator was found, and `2` when an input or parsing error occurred. If a run has both indicators and errors, it returns `2` so the incomplete scan is visible.

## Scope and safety

The tool only reads the selected files as data. It does not launch them, inspect process memory, collect keystrokes, alter the system, or send file contents anywhere. Treat its output as a review aid, not an antivirus verdict or a clean bill of health.
