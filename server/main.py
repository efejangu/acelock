from command_shell import CommandShell
from server import TCPServer


if __name__ == "__main__":
    shell = CommandShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\n[!] Received keyboard interrupt, exiting...")
        shell.cleanup()
        sys.exit(0)