# client.py
import tkinter as tk
from tkinter import messagebox
import socket
import os
from rsa_encryption import encrypt_data, decrypt_data
from security import hash_password, verify_password  # Import from security.py

# Server settings
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

# File paths for storing user data
USER_CREDENTIALS = "user_data.txt"
PERSONAL_DETAILS_FILE = "personal_data.txt"
TRANSFER_LOG = "transfers.txt"

active_user = None  # Track the currently logged-in user

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_HOST, SERVER_PORT))

def communicate_with_server(data):
    """Send a message to the server."""
    try:
        client_socket.sendall(data.encode())
    except Exception as e:
        print("Failed to send message to server:", e)

def create_new_user():
    username = username_entry_register.get()
    password = password_entry_register.get()
    ssn = ssn_entry.get()
    address = address_entry.get()
    phone = phone_entry.get()
    country = country_entry.get()
    
    if username and password and ssn and address and phone and country:
        hashed_password = hash_password(password)  # Hash the password

        # Encrypt personal details
        encrypted_ssn = encrypt_data(ssn)
        encrypted_address = encrypt_data(address)
        encrypted_phone = encrypt_data(phone)
        encrypted_country = encrypt_data(country)

        # Store user credentials with hashed password
        with open(USER_CREDENTIALS, "a") as file:
            file.write(f"{username},{hashed_password}\n")
        
        # Store encrypted personal details
        with open(PERSONAL_DETAILS_FILE, "a") as file:
            file.write(f"{username},{encrypted_ssn},{encrypted_address},{encrypted_phone},{encrypted_country}\n")
        
        messagebox.showinfo("Success", "Registration successful!")
        register_screen.destroy()  # Close the registration window
    else:
        messagebox.showerror("Error", "All fields are required.")

def authenticate_user():
    global active_user
    username = username_entry_login.get()
    password = password_entry_login.get()
    
    if username and password:
        hashed_password = hash_password(password)  # Hash the entered password

        # Validate credentials by comparing hashed passwords
        with open(USER_CREDENTIALS, "r") as file:
            for record in file:
                # Skip lines that don't match expected format
                if ',' not in record:
                    continue
                user, stored_hashed_password = record.strip().split(",", 1)
                if username == user and verify_password(stored_hashed_password, password):
                    active_user = username  # Set active user
                    messagebox.showinfo("Success", "Login successful!")
                    communicate_with_server(f"User logged in: {username}")
                    login_screen.destroy()  # Close login window
                    show_user_dashboard()
                    return
        messagebox.showerror("Error", "Incorrect username or password.")
    else:
        messagebox.showerror("Error", "All fields are required.")

def display_user_information():
    """Display the decrypted personal details of the active user."""
    if active_user:
        with open(PERSONAL_DETAILS_FILE, "r") as file:
            for record in file:
                username, encrypted_ssn, encrypted_address, encrypted_phone, encrypted_country = record.strip().split(",")
                if username == active_user:
                    # Decrypt details
                    ssn = decrypt_data(encrypted_ssn)
                    address = decrypt_data(encrypted_address)
                    phone = decrypt_data(encrypted_phone)
                    country = decrypt_data(encrypted_country)

                    # Display decrypted details in a new window
                    details_window = tk.Tk()
                    details_window.title(f"{active_user}'s Personal Details")
                    
                    tk.Label(details_window, text="Social Security Number:").grid(row=0, column=0, sticky="e")
                    tk.Label(details_window, text=ssn).grid(row=0, column=1, sticky="w")

                    tk.Label(details_window, text="Address:").grid(row=1, column=0, sticky="e")
                    tk.Label(details_window, text=address).grid(row=1, column=1, sticky="w")

                    tk.Label(details_window, text="Phone:").grid(row=2, column=0, sticky="e")
                    tk.Label(details_window, text=phone).grid(row=2, column=1, sticky="w")

                    tk.Label(details_window, text="Country:").grid(row=3, column=0, sticky="e")
                    tk.Label(details_window, text=country).grid(row=3, column=1, sticky="w")
                    return


def show_user_dashboard():
    """Open the post-login options interface."""
    post_login_window = tk.Tk()
    post_login_window.title(f"Welcome, {active_user}")

    # Button to open the transfer interface
    btn_transfer_interface = tk.Button(post_login_window, text="Open Transfer Interface", command=initiate_transfer_portal)
    btn_transfer_interface.pack(pady=10)

    # Button to show personal details
    btn_show_details = tk.Button(post_login_window, text="Show Personal Details", command=display_user_information)
    btn_show_details.pack(pady=10)

def record_money_transfer():
    account_id = account_entry.get()
    transfer_amount = amount_entry.get()
    
    if account_id and transfer_amount and active_user:
        try:
            # Log the transfer data to the local file
            with open(TRANSFER_LOG, "a") as file:
                file.write(f"{active_user},{account_id},{transfer_amount}\n")
            # Also send the information to the server
            communicate_with_server(f"Transfer submitted by {active_user}: {transfer_amount} to account {account_id}")
            messagebox.showinfo("Success", "Transfer recorded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Transfer failed: {e}")
    else:
        messagebox.showerror("Error", "All fields are required.")

def initiate_transfer_portal():
    # Transfer interface
    global sender_screen, account_entry, amount_entry
    sender_screen = tk.Tk()
    sender_screen.title(f"Money Transfer - Sender ({active_user})")
    
    tk.Label(sender_screen, text="Account Number:").grid(row=0, column=0)
    account_entry = tk.Entry(sender_screen)
    account_entry.grid(row=0, column=1)

    tk.Label(sender_screen, text="Amount:").grid(row=1, column=0)
    amount_entry = tk.Entry(sender_screen)
    amount_entry.grid(row=1, column=1)

    submit_button = tk.Button(sender_screen, text="Submit Transfer", command=record_money_transfer)
    submit_button.grid(row=2, columnspan=2)

def setup_registration_form():
    global register_screen, username_entry_register, password_entry_register
    global ssn_entry, address_entry, phone_entry, country_entry

    register_screen = tk.Tk()
    register_screen.title("Register")
    
    # Credentials Section
    credentials_label = tk.Label(register_screen, text="Credentials", font=('Arial', 14, 'bold'))
    credentials_label.grid(row=0, column=0, columnspan=2, pady=(10, 0))
    
    tk.Label(register_screen, text="Username:").grid(row=1, column=0, sticky="e")
    username_entry_register = tk.Entry(register_screen)
    username_entry_register.grid(row=1, column=1)
    
    tk.Label(register_screen, text="Password:").grid(row=2, column=0, sticky="e")
    password_entry_register = tk.Entry(register_screen, show="*")
    password_entry_register.grid(row=2, column=1)
    
    # Personal Details Section
    personal_details_label = tk.Label(register_screen, text="Personal Details", font=('Arial', 14, 'bold'))
    personal_details_label.grid(row=3, column=0, columnspan=2, pady=(10, 0))
    
    tk.Label(register_screen, text="SSN:").grid(row=4, column=0, sticky="e")
    ssn_entry = tk.Entry(register_screen)
    ssn_entry.grid(row=4, column=1)
    
    tk.Label(register_screen, text="Address:").grid(row=5, column=0, sticky="e")
    address_entry = tk.Entry(register_screen)
    address_entry.grid(row=5, column=1)
    
    tk.Label(register_screen, text="Phone:").grid(row=6, column=0, sticky="e")
    phone_entry = tk.Entry(register_screen)
    phone_entry.grid(row=6, column=1)
    
    tk.Label(register_screen, text="Country:").grid(row=7, column=0, sticky="e")
    country_entry = tk.Entry(register_screen)
    country_entry.grid(row=7, column=1)
    
    # Register Button
    register_button = tk.Button(register_screen, text="Register", command=create_new_user)
    register_button.grid(row=8, columnspan=2, pady=(10, 10))

def setup_login_form():
    global login_screen, username_entry_login, password_entry_login
    login_screen = tk.Tk()
    login_screen.title("Login")
    
    tk.Label(login_screen, text="Username:").grid(row=0, column=0)
    username_entry_login = tk.Entry(login_screen)
    username_entry_login.grid(row=0, column=1)
    
    tk.Label(login_screen, text="Password:").grid(row=1, column=0)
    password_entry_login = tk.Entry(login_screen, show="*")
    password_entry_login.grid(row=1, column=1)
    
    login_button = tk.Button(login_screen, text="Login", command=authenticate_user)
    login_button.grid(row=2, columnspan=2)

# Main interface for user options
main_screen = tk.Tk()
main_screen.title("Money Transfer Application")

register_btn = tk.Button(main_screen, text="Register", command=setup_registration_form)
register_btn.pack()

login_btn = tk.Button(main_screen, text="Login", command=setup_login_form)
login_btn.pack()

main_screen.mainloop()
