import string
import secrets
import sqlite3
from rich.console import Console
from rich.table import Table
from cryptography.fernet import Fernet

console = Console()

def get_yes_no_input(prompt):
    while True:
        choice = input(prompt).lower()
        if choice in ['y', 'n']:
            return choice
        console.print("[red]Invalid input. Please enter 'y' or 'n'.[/red]")

class PasswordGenerator:
    def __init__(self, length=12, uppercase=True, digits=True, special_chars=True):
        self.length = length
        self.uppercase = uppercase
        self.digits = digits
        self.special_chars = special_chars
        self.limited_special_chars = ["%", "&", "#", "$", "*", "-", "_", "/"]
        self.character_set = ''.join(filter(None, [
            string.ascii_uppercase if uppercase else '',
            string.ascii_lowercase,
            string.digits if digits else '',
            ''.join(self.limited_special_chars) if special_chars else ''
        ]))

    def generate(self):
        if not self.character_set:
            raise ValueError("At least one character type must be selected.")
        return ''.join(secrets.choice(self.character_set) for _ in range(self.length))

class ShowPasswords:
    def __init__(self, selected_password=None):
        self.selected_password = selected_password

    def show_all_passwords(self):
        with sqlite3.connect('ornek.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM passwords")
            rows = cursor.fetchall()

            if not rows:
                console.print("[red]No passwords found in database![/red]")
                return

            mask = get_yes_no_input("\nDo you want to mask the passwords? (y/n): ")
            table = Table(
                title="[bold green]All Passwords",
                show_header=True,
                header_style="bold blue",
                border_style="dim green"
            )

            column_names = [description[0] for description in cursor.description]
            for col in column_names:
                table.add_column(col, style="cyan", justify="left")

            for row in rows:
                modified_row = list(row)
                if mask == 'y':
                    modified_row[2] = "•" * 8
                table.add_row(*[str(item) for item in modified_row])

            console.print(table)

    def show_specific_password(self):
        with sqlite3.connect('ornek.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM passwords WHERE name=?", (self.selected_password,))
            row = cursor.fetchone()

            if not row:
                console.print("[red]Error:[/] Password not found!")
                return

            detail_table = Table(
                title=f"[bold][cyan]Password Details for '{self.selected_password}'",
                show_header=False,
                box=None
            )

            detail_table.add_column("Field", style="bold green")
            detail_table.add_column("Value", style="yellow")

            column_names = [desc[0] for desc in cursor.description]
            for name, value in zip(column_names, row):
                if name.lower() == "password":
                    value = f"[red]{value}[/]"
                detail_table.add_row(name, str(value))

            console.print(detail_table)

class CryptoManager:
    def __init__(self, key_file="key.key"):
        self.key_file = key_file
        self.key = self.load_or_generate_key()
        self.cipher = Fernet(self.key)

    def load_or_generate_key(self):
        try:
            with open(self.key_file, "rb") as file:
                return file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as file:
                file.write(key)
            return key

    def encrypt(self, password):
        return self.cipher.encrypt(password.encode())

class AddPassword:
    def __init__(self, name, password):
        self.name = name
        self.password = password

    def add_password(self):
        with sqlite3.connect('ornek.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO passwords (name, password) VALUES (?, ?)", (self.name, self.password))
            conn.commit()

def handle_password_generation():
    console.print("\n[bold green]Password Generator selected[/bold green]")
    while True:
        length = int(input("\nEnter the desired password length: "))
        if length < 8:
            console.print("[red]Password length must be at least 8.[/red]")
        else:
            break

    uppercase = get_yes_no_input("\nInclude uppercase letters? (y/n): ") == 'y'
    digits = get_yes_no_input("\nInclude digits? (y/n): ") == 'y'
    special_chars = get_yes_no_input("\nInclude special characters? (y/n): ") == 'y'

    password_generator = PasswordGenerator(length, uppercase, digits, special_chars)
    password = password_generator.generate()
    console.print(f"\n[bold green]Generated password:[/bold green] {password}")

    save = get_yes_no_input("\nDo you want to save this password? (y/n): ")
    if save == 'y':
        name = input("\nEnter a name for this password: ")
        add_password = AddPassword(name, password)
        add_password.add_password()
        console.print(f"\n[bold green]Password '{name}' saved successfully.[/bold green]")

def handle_password_display():
    selected_password = input("\nWhich password do you want to see? (specific one / all): ").lower()
    show_passwords = ShowPasswords(selected_password)
    if selected_password == "all":
        show_passwords.show_all_passwords()
    else:
        show_passwords.show_specific_password()

def handle_crypto_manager():
    console.print("\n[bold green]Crypto Manager selected[/bold green]")
    password = input("\nEnter the password to encrypt: ")
    crypto_manager = CryptoManager()
    encrypted_password = crypto_manager.encrypt(password)
    console.print(f"\n[bold green]Encrypted password:[/bold green] {encrypted_password.decode()}")

def main():
    console.print("\n[bold green]Welcome to the Password Storage Application![/bold green]")
    while True:
        console.print("\n[bold blue]1-) Password Generator\n2-) Show Password(s)\n3-) Crypto Manager\n4-) Quit[/bold blue]")
        try:
            user_choice = int(input("\nEnter your choice: "))
            if user_choice == 1:
                handle_password_generation()
            elif user_choice == 2:
                handle_password_display()
            elif user_choice == 3:
                handle_crypto_manager()
            elif user_choice == 4:
                console.print("\n[bold red]Goodbye![/bold red]")
                break
            else:
                console.print("[red]Invalid selection. Please try again.[/red]")
        except ValueError:
            console.print("[red]Invalid input. Please enter a number.[/red]")
        except KeyboardInterrupt:
            console.print("\n[bold red]Exiting the program.[/bold red]")
            break

if __name__ == "__main__":
    conn = sqlite3.connect('ornek.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                  (id INTEGER PRIMARY KEY, 
                   name TEXT, 
                   password TEXT,
                   created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.close()
    main()