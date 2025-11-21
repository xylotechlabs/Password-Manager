# 🔐 Python Password Manager (Tkinter + AES Encryption)

A secure and lightweight **local password manager** built using **Python** and **Tkinter**, featuring **AES-based encryption (Fernet)** and a clean GUI for storing and managing passwords offline.  
All data is encrypted using a **master password**, ensuring only you can access your vault.

---

## ✨ Features

| Feature | Description |
|--------|------------|
| 🔑 Master Password | Protects your entire vault — required at launch |
| 🛢 Local encrypted vault | Stored as `vault.bin` on disk |
| 🧠 AES-256 based encryption | Using PBKDF2 + SHA256 + Fernet |
| ➕ Add / Edit / Delete entries | Store service, username, password, notes |
| 🧰 Built-in password generator | Custom length and character sets |
| 📋 Copy password button | Makes copying secure and easy |
| 👁 Toggle visibility | Show / hide password |
| 💾 Auto save | Saves changes after update or delete |

---

## 📦 Requirements

| Dependency | Install command |
|------------|----------------|
| Python 3.8+ | Pre-installed on most systems |
| `cryptography` | `pip install cryptography` |

---

## ▶ Running the Application

1. Clone or download the project
2. Install dependencies
   ```bash
   pip install cryptography
3. Run it
