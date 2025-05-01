from command_shell import CommandShell
import os


if __name__ == '__main__':
    default_cert = '../ssl_deets/server.crt'
    default_key = '../ssl_deets/server.key'
    if not os.path.isfile(default_cert) or not os.path.isfile(default_key):
         print(f"[!] Warning: Default SSL certificate ({default_cert}) or key ({default_key}) not found.", file=sys.stderr)
         print("[!] Server start may fail unless paths are specified via: start_server -cert /path/to/cert -key /path/to/key", file=sys.stderr)

    try:
        shell = CommandShell(certfile=default_cert, keyfile=default_key)
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n[*] Exiting AceLock Shell via KeyboardInterrupt.")
    except ImportError as import_err:
         print(f"\n[!] Critical Error: Could not load server code from server.py: {import_err}", file=sys.stderr)
         sys.exit(1)
    except Exception as main_e:
        print(f"\n[!] Critical error: {main_e}", file=sys.stderr)
        sys.exit(1)
