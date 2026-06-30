"""
host_cli.py — host-side interactive menu for the password manager.
 
Design note: this script runs OUTSIDE Gramine, on the untrusted host side
of the architecture. It owns all user interaction (menu display, password
and secret prompts via getpass, which needs real terminal control that
Gramine's sandbox does not fully provide). It never touches the master
password's cryptographic use directly — it only collects it and pipes it,
over stdin, into the Gramine-wrapped vault_crypto.py subprocess, which
performs all key derivation and encryption/decryption.
 
This mirrors the project's intended trust boundary: host = UI + untrusted
vault storage, Gramine-wrapped process = key derivation + crypto only.
"""
 
import subprocess
import getpass
import sys
 
# Name of the built manifest (gramine-direct expects this without
# the .manifest extension), and the absolute in-sandbox path to the
# script, matching what vault.manifest.template declares.
GRAMINE_MANIFEST_NAME = "vault"
SANDBOXED_SCRIPT_PATH = "/vault_crypto.py"
 
 
def run_vault_command(cmd: str, args: list[str], password: str, secret: str = None) -> str:
    """Invoke the Gramine-wrapped vault_crypto.py as a subprocess.
 
    Sends the master password (and, for 'add', the secret) over stdin,
    one per line, matching the protocol vault_crypto.py's
    get_secret_input() expects when stdin is piped rather than a tty.
 
    Returns combined stdout+stderr as a string for the caller to display.
    """
    full_args = ["gramine-direct", GRAMINE_MANIFEST_NAME, SANDBOXED_SCRIPT_PATH, cmd] + args
 
    stdin_lines = [password]
    if secret is not None:
        stdin_lines.append(secret)
    stdin_data = "\n".join(stdin_lines) + "\n"
 
    result = subprocess.run(
        full_args,
        input=stdin_data,
        capture_output=True,
        text=True,
    )
 
    output = result.stdout
    if result.returncode != 0:
        output += "\n[stderr]\n" + result.stderr
    return output.strip()
 
 
def show_menu():
    print("\n=== Password Manager ===")
    print("1) Add entry")
    print("2) Get entry")
    print("3) List entries")
    print("4) Delete entry")
    print("5) Quit")
 
 
def main():
    print("Confidential Password Manager (host CLI)")
    print("Running vault operations via gramine-direct.\n")
 
    while True:
        show_menu()
        choice = input("Choose an option: ").strip()
 
        if choice == "1":
            name = input("Entry name: ").strip()
            password = getpass.getpass("Master password: ")
            secret = getpass.getpass("Secret value: ")
            output = run_vault_command("add", [name], password, secret)
            print(output)
 
        elif choice == "2":
            name = input("Entry name: ").strip()
            password = getpass.getpass("Master password: ")
            output = run_vault_command("get", [name], password)
            print(output)
 
        elif choice == "3":
            password = getpass.getpass("Master password: ")
            output = run_vault_command("list", [], password)
            print(output)
 
        elif choice == "4":
            name = input("Entry name: ").strip()
            password = getpass.getpass("Master password: ")
            output = run_vault_command("delete", [name], password)
            print(output)
 
        elif choice == "5":
            print("Goodbye.")
            sys.exit(0)
 
        else:
            print("Invalid choice, please pick 1-5.")
 
 
if __name__ == "__main__":
    main()
