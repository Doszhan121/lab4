from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json
import os
import tkinter as tk
from tkinter import messagebox, simpledialog


class Wallet:
    def __init__(self):
        self.private_key, self.public_key = self.generate_keys()
        self.address = self.get_address()
        self.balance = 100

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_keys(self):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open("private_key.pem", "wb") as f:
            f.write(private_pem)
        with open("public_key.pem", "wb") as f:
            f.write(public_pem)

    def load_keys(self):
        if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
            with open("private_key.pem", "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open("public_key.pem", "rb") as f:
                self.public_key = serialization.load_pem_public_key(f.read())
            self.address = self.get_address()

    def get_address(self):
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return str(hash(public_bytes))

    def sign_transaction(self, receiver, amount):
        transaction = {"sender": self.address, "receiver": receiver, "amount": amount}
        transaction_data = json.dumps(transaction, sort_keys=True).encode()
        signature = self.private_key.sign(
            transaction_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return transaction, signature

    @staticmethod
    def verify_signature(transaction, signature, public_key):
        transaction_data = json.dumps(transaction, sort_keys=True).encode()
        try:
            public_key.verify(
                signature,
                transaction_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False


class WalletGUI:
    def __init__(self, root, wallet):
        self.root = root
        self.wallet = wallet
        self.root.title("Крипто Әмиян")

        tk.Label(root, text=f"Мекенжай: {self.wallet.address}").pack()
        self.balance_label = tk.Label(root, text=f"Баланс: {self.wallet.balance}")
        self.balance_label.pack()

        tk.Button(root, text="Транзакция Жіберу", command=self.send_transaction).pack()
        tk.Button(root, text="Шығу", command=root.quit).pack()

    def send_transaction(self):
        receiver = simpledialog.askstring("Транзакция", "Алушының мекенжайын енгізіңіз:")
        amount = simpledialog.askinteger("Транзакция", "Соманы енгізіңіз:")

        if amount > self.wallet.balance:
            messagebox.showerror("Қате", "Жеткілікті Баланс Жоқ!")
            return

        transaction, signature = self.wallet.sign_transaction(receiver, amount)
        self.wallet.balance -= amount
        self.balance_label.config(text=f"Баланс: {self.wallet.balance}")

        messagebox.showinfo("Транзакция",
                            f"Транзакция жіберілді!\nДеректер: {transaction}\nҚолтаңба: {signature.hex()}")


if __name__ == "__main__":
    wallet = Wallet()
    wallet.load_keys()
    root = tk.Tk()
    gui = WalletGUI(root, wallet)
    root.mainloop()
