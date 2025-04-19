from imutils import paths
import numpy as np
import argparse
import imutils
import pickle
import cv2
import os
from os import listdir
from os.path import isfile, join
from pathlib import Path
from collections import Counter
# import the necessary packages

from imutils.video import VideoStream
from imutils.video import FPS
import time
from tkinter import *
from tkinter import messagebox
import tkinter.simpledialog as simpledialog
import sqlite3
import pandas as pd
from PIL import Image, ImageTk
import tkinter as tk
import pandas as pd
import csv
from random import randint
import hashlib
import os
import random

from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder
import joblib

# When training your recognizer
recognizer = SVC(kernel='linear', probability=True)  # <--- Important!
# Save the model
joblib.dump(recognizer,"face_recognizer.pkl")
ARIAL = ("arial", 10, "bold")
class BankUi:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1100x900")
        # Header
        self.header = Label(self.root,
            text="SBI BANK",
            bg="#002B7F",  # Deep royal blue
            fg="white",
            font=("Arial", 20, "bold")
            )
        self.header.pack(fill=X)

            # Main Frame
        self.frame = Frame(self.root, bg="#F0F4F8", width=900, height=500)  # Light clean background
        self.frame.pack()

            # Fonts
        btn_font = ("Arial", 12, "bold")

            # Button 1
        self.button1 = Button(
            self.frame,
            text="Click to Begin Transactions",
            bg="#004E64",  # Deep teal/navy
            fg="white",
            font=btn_font,
            command=self.begin_page
            )
        self.button1.place(x=155, y=230, width=500, height=40)

            # Quit Button
        self.q = Button(
            self.frame,
            text="Quit",
            bg="#004E64",
            fg="white",
            font=btn_font,
            command=self.root.destroy
            )
        self.q.place(x=340, y=340, width=200, height=40)

        self.countter = 2

    def begin_page(self):
        self.frame.destroy()
        #self.frame = Frame(self.root, bg="#F0F4F8", width=900, height=500)  # Updated background
        #root.geometry("800x500")
        self.frame = Frame(self.root, bg="#F0F4F8", width=1100, height=900)
        self.frame.pack_propagate(True)  # Allow the frame to resize based on contents
        self.frame.pack()

        # Updated button colors
        self.enroll = Button(self.frame, text="Enroll", bg="#004E64", fg="white", font=ARIAL, command=self.enroll_user)
        self.withdraw = Button(self.frame, text="Login", bg="#004E64", fg="white", font=ARIAL,
                               command=self.withdraw_money_page)
        self.q = Button(self.frame, text="Quit", bg="#004E64", fg="white", font=ARIAL, command=self.root.destroy)

        self.enroll.place(x=300, y=150, width=200, height=50)
        self.withdraw.place(x=300, y=220, width=200, height=50)
        self.q.place(x=300, y=340, width=180, height=40)
        self.frame.pack()

    def family_access_auth(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#F0F4F8", width=900, height=900)

        label_fg = "#333333"
        btn_bg = "#004E64"

        # Labels and Entries for Family Member Access
        """self.fam_label = Label(self.frame, text="Family Member Name:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.fam_entry = Entry(self.frame, bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                               highlightbackground="white")

        self.pin_label = Label(self.frame, text="Shared PIN:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.pin_entry = Entry(self.frame, show="*", bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                               highlightbackground="white")"""

        # Submit button (simulate validation)
        self.submit_btn = Button(self.frame, text="Verify Access", bg=btn_bg, fg="white", font=ARIAL,
                                 command=self.password_verification)

        # Place everything
        """self.fam_label.place(x=200, y=120, width=200, height=75)
        self.fam_entry.place(x=410, y=120, width=250, height=75)

        self.pin_label.place(x=200, y=170, width=200, height=25)
        self.pin_entry.place(x=410, y=170, width=250, height=25)"""

        self.submit_btn.place(x=330, y=230, width=250, height=75)

        # Back and Quit
        self.q = Button(self.frame, text="Quit", bg=btn_bg, fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg=btn_bg, fg="white", font=ARIAL, command=self.withdraw_money_page)

        self.q.place(x=480, y=360, width=120, height=20)
        self.b.place(x=280, y=360, width=120, height=20)
        self.selected_verification = "Family Access"
        self.frame.pack()



    def fake_otp_auth(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#F0F4F8", width=900, height=900)

        label_fg = "#333333"
        btn_bg = "#004E64"
        self.generated_otp = str(random.randint(100000, 999999))  # Generate 6-digit OTP
        print(f"[INFO] Simulated OTP sent: {self.generated_otp}")  # In real app, this would be sent via SMS/Email

        """# OTP Instruction
        self.otp_label = Label(self.frame, text="Enter the 6-digit OTP sent to your registered number:", bg="#F0F4F8",
                               fg=label_fg, font=ARIAL)
        self.otp_entry = Entry(self.frame, bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                               highlightbackground="white")"""

        # Submit button to verify OTP
        self.submit_otp_btn = Button(self.frame, text="Verify OTP", bg=btn_bg, fg="white", font=ARIAL,
                                     command=self.password_verification)

        """# Place UI
        self.otp_label.place(x=200, y=120, width=500, height=25)
        self.otp_entry.place(x=330, y=160, width=200, height=25)"""
        self.submit_otp_btn.place(x=330, y=200, width=200, height=30)

        # Back and Quit buttons
        self.q = Button(self.frame, text="Quit", bg=btn_bg, fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg=btn_bg, fg="white", font=ARIAL, command=self.withdraw_money_page)

        self.q.place(x=480, y=360, width=120, height=20)
        self.b.place(x=280, y=360, width=120, height=20)
        self.selected_verification = "OTP"


        self.frame.pack()



    """def withdraw_money_page(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="white", width=1100, height=900)

        label_fg = "#333333"
        btn_bg = "#004E64"

        # --- Account number input ---
        self.acc_label = Label(self.frame, text="Enter Account Number:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.acc_entry = Entry(self.frame, bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                               highlightbackground="white")

        self.acc_label.place(x=100, y=80, width=250, height=25)
        self.acc_entry.place(x=360, y=80, width=250, height=25)

        # --- Verification Method Buttons ---
        self.label_method = Label(self.frame, text="Choose Verification Method:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.label_method.place(x=100, y=120, width=400, height=25)

        self.face_btn = Button(self.frame, text="Face Recognition", bg=btn_bg, fg="white", font=ARIAL,
                               command=self.video_check)
        # Rename fingerprint button to "Family Access"
        self.family_btn = Button(self.frame, text="Family Access", bg=btn_bg, fg="white", font=ARIAL,
                                 command=self.family_access_auth)


        self.otp_btn = Button(self.frame, text="OTP", bg=btn_bg, fg="white", font=ARIAL, command=self.fake_otp_auth)

        self.face_btn.place(x=100, y=160, width=200, height=30)
        self.family_btn.place(x=320, y=160, width=200, height=30)
        self.otp_btn.place(x=540, y=160, width=200, height=30)

        # --- Quit & Back Buttons ---
        self.q = Button(self.frame, text="Quit", bg=btn_bg, fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg=btn_bg, fg="white", font=ARIAL, command=self.begin_page)
        self.q.place(x=480, y=360, width=120, height=20)
        self.b.place(x=280, y=360, width=120, height=20)
        self.real_user = self.acc_entry.get()
        self.frame.pack()"""

    def withdraw_money_page(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="white", width=1100, height=900)

        label_fg = "#333333"
        btn_bg = "#004E64"

        # Account Number Entry
        self.acc_label = Label(self.frame, text="Enter Account Number:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.acc_entry = Entry(self.frame, bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                               highlightbackground="white")
        self.acc_label.place(x=100, y=80, width=250, height=25)
        self.acc_entry.place(x=360, y=80, width=250, height=25)

        # Password Entry
        self.pass_label = Label(self.frame, text="Enter Account Password:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.pass_entry = Entry(self.frame, bg="honeydew", show="*", highlightcolor=btn_bg, highlightthickness=2,
                                highlightbackground="white")
        self.pass_label.place(x=100, y=120, width=250, height=25)
        self.pass_entry.place(x=360, y=120, width=250, height=25)

        # Validation Button
        self.validate_btn = Button(self.frame, text="Validate", bg=btn_bg, fg="white", font=ARIAL,
                                   command=self.validate_credentials)
        self.validate_btn.place(x=320, y=160, width=150, height=30)
        self.q = Button(self.frame, text="Quit", bg="black", fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg="black", fg="white", font=ARIAL, command=self.begin_page)

        self.q.place(x=480, y=430, width=120, height=20)
        self.b.place(x=480, y=400, width=120, height=20)

        self.frame.pack()

    def validate_credentials(self):
        try:
            # Get the account number and password entered by the user
            acc_input = self.acc_entry.get().strip()
            pass_input = self.pass_entry.get().strip()

            if not acc_input or not pass_input:
                raise ValueError("Account number and password are required.")

            self.real_user = acc_input  # Store account number
            self.account_password = pass_input  # Store entered password

            # Simulate checking user credentials from the database (CSV file)
            import pandas as pd
            data = pd.read_csv('bank_details.csv', on_bad_lines='skip')
            # user_data = data[data['account_number'] == self.real_user
            # Ensure both values are strings for accurate matching
            user_data = data[data['account_number'].astype(str) == str(self.real_user)]

            # Print the matched user row(s)
            print("\n[DEBUG] User Data:")
            print(user_data)

            if user_data.empty:
                messagebox.showerror("User Not Found", "Account number not found.")
                return

            # Validate the password
            if str(user_data['password'].values[0]) != self.account_password:
                messagebox.showerror("Authentication Failed", "Incorrect password.")
                return

            # Proceed to display verification options after successful login
            self.display_verification_options()

        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        self.q = Button(self.frame, text="Quit", bg="black", fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg="black", fg="white", font=ARIAL, command=self.begin_page)

        self.q.place(x=480, y=430, width=120, height=20)
        self.b.place(x=480, y=400, width=120, height=20)

    def display_verification_options(self):
        # Clear previous widgets if any
        self.frame.destroy()
        self.frame = Frame(self.root, bg="white", width=1100, height=900)

        label_fg = "#333333"
        btn_bg = "#004E64"

        # Display the message
        self.label_method = Label(self.frame, text="Choose Verification Method:", bg="#F0F4F8", fg=label_fg,
                                  font=ARIAL)
        self.label_method.place(x=100, y=80, width=400, height=25)
        self.q = Button(self.frame, text="Quit", bg=btn_bg, fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg=btn_bg, fg="white", font=ARIAL, command=self.begin_page)


        self.q.place(x=480, y=430, width=120, height=20)
        self.b.place(x=480, y=400, width=120, height=20)

        # Shared validation wrapper to continue with verification
        def validate_and_continue(callback, method_name):
            self.selected_verification = method_name  # Store selected verification method
            callback()

        # Buttons for different verification methods
        self.face_btn = Button(self.frame, text="Face Recognition", bg=btn_bg, fg="white", font=ARIAL,
                               command=lambda: validate_and_continue(self.video_check, "Face Recognition"))
        self.family_btn = Button(self.frame, text="Family Access", bg=btn_bg, fg="white", font=ARIAL,
                                 command=lambda: validate_and_continue(self.family_access_auth, "Family Access"))
        self.otp_btn = Button(self.frame, text="OTP", bg=btn_bg, fg="white", font=ARIAL,
                              command=lambda: validate_and_continue(self.fake_otp_auth, "OTP"))

        self.face_btn.place(x=100, y=120, width=200, height=30)
        self.family_btn.place(x=320, y=120, width=200, height=30)
        self.otp_btn.place(x=540, y=120, width=200, height=30)

        self.frame.pack()

    def enroll_user(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#F0F4F8", width=1100, height=500)

        label_fg = "#333333"
        btn_bg = "#004E64"

        # ------- Personal Info Fields -------
        fields = {
            "First Name": (125, 40),
            "Last Name (Optional)": (125, 70),
            "Username": (125, 100),
            "Password": (125, 130),
            "Confirm Password": (125, 160),
            "Email": (125, 190),
            "Mobile Number": (125, 220),
            "Address": (125, 250)
        }

        self.entries = {}  # Store entry widgets for all fields

        for label, pos in fields.items():
            lbl = Label(self.frame, text=label, bg="#F0F4F8", fg=label_fg, font=ARIAL)
            lbl.place(x=pos[0], y=pos[1], width=150, height=30)

            show = "*" if "Password" in label else ""
            entry = Entry(self.frame, show=show, bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                          highlightbackground="white")
            entry.place(x=300, y=pos[1], width=250, height=20)

            self.entries[label] = entry

        # ------- Family Access Toggle -------
        self.family_label = Label(self.frame, text="Add Family Member Access?", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.family_label.place(x=125, y=280, width=200, height=30)

        self.family_yes = Button(self.frame, text="Yes", bg=btn_bg, fg="white", font=ARIAL,
                                 command=self.show_family_access_fields)
        self.family_no = Button(self.frame, text="No", bg=btn_bg, fg="white", font=ARIAL,
                                command=self.hide_family_access_fields)

        self.family_yes.place(x=330, y=280, width=50, height=20)
        self.family_no.place(x=390, y=280, width=50, height=20)

        # Family Access Inputs (initially hidden)
        self.fam_name_label = Label(self.frame, text="Family Member Name:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.fam_name_entry = Entry(self.frame, bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                                    highlightbackground="white")

        self.pin_label = Label(self.frame, text="Shared PIN:", bg="#F0F4F8", fg=label_fg, font=ARIAL)
        self.pin_entry = Entry(self.frame, show="*", bg="honeydew", highlightcolor=btn_bg, highlightthickness=2,
                               highlightbackground="white")

        # ------- Buttons -------
        self.button1 = Button(self.frame, text="Next", bg=btn_bg, fg="white", font=ARIAL,
                              command=self.enroll_and_move_to_next_screen)
        self.q = Button(self.frame, text="Quit", bg=btn_bg, fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg=btn_bg, fg="white", font=ARIAL, command=self.begin_page)

        self.button1.place(x=120, y=400, width=180, height=30)
        self.q.place(x=480, y=430, width=120, height=20)
        self.b.place(x=480, y=400, width=120, height=20)

        self.frame.pack()

    def show_family_access_fields(self):
        # Show family access fields
        self.fam_name_label.place(x=125, y=310, width=150, height=20)
        self.fam_name_entry.place(x=300, y=310, width=250, height=20)

        self.pin_label.place(x=125, y=340, width=150, height=20)
        self.pin_entry.place(x=300, y=340, width=250, height=20)

    def hide_family_access_fields(self):
        # Hide family access fields
        self.fam_name_label.place_forget()
        self.fam_name_entry.place_forget()
        self.pin_label.place_forget()
        self.pin_entry.place_forget()

    def enroll_and_move_to_next_screen(self):
        username = self.entries["Username"].get()
        password = self.entries["Password"].get()

        if not username and not password:
            messagebox.showerror("Error", "You need a name to enroll an account and you need to input a password!")
            self.enroll_user()
        elif not password:
            messagebox.showerror("Error", "You need to input a password!")
            self.enroll_user()
        elif not username:
            messagebox.showerror("Error", "You need a name to enroll an account!")
            self.enroll_user()
        elif len(password) < 8:
            messagebox.showerror("Password Error", "Your password needs to be at least 8 characters!")
            self.enroll_user()
        else:
            self.write_to_csv()
            self.video_capture_page()

    def password_verification(self):
        # This function is intentionally blank
        # It immediately redirects to verify_user
        self.verify_user()

    """def password_verification(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#0019fc", width=900, height=500)
        # Example: When user enters account number and selects a verification method

        print(self.real_user)
        # Login Page Form Components
        self.plabel = Label(self.frame, text="Please enter your account password", bg="#0019fc", fg="white", font=ARIAL)
        self.givenpentry = Entry(self.frame, bg="honeydew", show="*", highlightcolor="#50A8B0",
                                 highlightthickness=2,
                                 highlightbackground="white")
        self.button1 = Button(self.frame, text="Verify", bg="#50A8B0", fg="white", font=ARIAL, command=self.verify_user)
        self.q = Button(self.frame, text="Quit", bg="#50A8B0", fg="white", font=ARIAL, command=self.root.destroy)
        self.b = Button(self.frame, text="Back", bg="#50A8B0", fg="white", font=ARIAL, command=self.begin_page)
        self.plabel.place(x=125, y=160, width=300, height=20)
        self.givenpentry.place(x=153, y=190, width=200, height=20)
        self.button1.place(x=155, y=230, width=180, height=30)
        self.q.place(x=480, y=360, width=120, height=20)
        self.b.place(x=280, y=360, width=120, height=20)
        self.frame.pack()"""



    def verify_user(self):
        import pandas as pd
        data = pd.read_csv('bank_details.csv', on_bad_lines='skip')
        user_data = data[data['account_number'] == self.real_user]
        # --- CASE 1: Face Recognition ---
        if self.selected_verification == "Face Recognition":
                messagebox.showinfo("Login Successful", "Face recognition matched!")
                self.final_page()

        # --- CASE 2: Family Access ---
        elif self.selected_verification == "Family Access":
            # Ask for both family name and shared pin
            family_name = simpledialog.askstring("Family Access", "Enter family member name:")
            shared_pin = simpledialog.askstring("Family Access", "Enter shared family PIN:", show="*")

            expected_family_name = str(user_data['family_name'].values[0]).lower()
            expected_pin = str(user_data['shared_pin'].values[0])  # or use a separate family_pin if you have it

            if (family_name and shared_pin and
                    family_name.lower() == expected_family_name and
                    shared_pin == expected_pin):
                messagebox.showinfo("Login Successful", "Family access verified!")
                self.final_page()
            else:
                messagebox.showerror("Authentication Failed", "Invalid family name or PIN.")


        # --- CASE 3: OTP Verification ---
        elif self.selected_verification == "OTP":
            entered_otp = simpledialog.askstring("OTP Verification", "Enter the OTP sent to your device:")

            print(f"[DEBUG] Generated OTP: {self.generated_otp}, Entered OTP: {entered_otp}")

            if entered_otp == self.generated_otp:
                messagebox.showinfo("Login Successful", "OTP matched!")
                self.final_page()
            else:
                messagebox.showerror("Authentication Failed", "Incorrect OTP.")

        else:
            messagebox.showerror("Invalid Option", "No valid verification method selected.")

    """def verify_user(self):
        data = pd.read_csv('bank_details.csv')
        self.gottenpassword = data[data.loc[:, 'unique_id'] == self.real_user].loc[:, 'password'].values[0]
        # print(str(self.givenpentry.get()))
        print(str(self.gottenpassword))
        if str(self.givenpentry.get()) == str(self.gottenpassword):
            messagebox._show("Verification Info!", "Verification Successful!")
            self.final_page()
        else:
            messagebox._show("Verification Info!", "Verification Failed")
            self.begin_page()"""

    def final_page(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="white", width=1100, height=500)
        self.detail = Button(self.frame, text="Transfer", bg="#50A8B0", fg="white", font=ARIAL,
                             command=self.user_account_transfer)
        self.enquiry = Button(self.frame, text="Balance Enquiry", bg="#50A8B0", fg="white", font=ARIAL,
                              command=self.user_balance)
        self.deposit = Button(self.frame, text="Deposit Money", bg="#50A8B0", fg="white", font=ARIAL,
                              command=self.user_deposit_money)
        self.withdrawl = Button(self.frame, text="Withdrawl Money", bg="#50A8B0", fg="white", font=ARIAL,
                                command=self.user_withdrawl_money)
        self.q = Button(self.frame, text="Log out", bg="#50A8B0", fg="white", font=ARIAL, command=self.begin_page)
        self.detail.place(x=550, y=100, width=200, height=50)
        self.enquiry.place(x=550, y=160, width=200, height=50)
        self.deposit.place(x=550, y=220, width=200, height=50)
        self.withdrawl.place(x=550, y=280, width=200, height=50)
        self.q.place(x=570, y=340, width=120, height=30)
        self.frame.pack()

    def user_account_transfer(self):
        from tkinter import Frame, Label, Entry, Button

        self.frame.destroy()
        self.frame = Frame(self.root, bg="white", width=900, height=500)

        Label(self.frame, text="Money Transfer", font=("Arial", 20, "bold"), bg="white", fg="white").place(x=320, y=40)

        # Recipient Account Number
        Label(self.frame, text="Recipient Account Number:", bg="#0019fc", fg="white", font=ARIAL).place(x=200, y=130)
        self.transfer_acc_entry = Entry(self.frame, bg="white", fg="black", font=ARIAL)
        self.transfer_acc_entry.place(x=200, y=160, width=300, height=25)

        # Amount to Transfer
        Label(self.frame, text="Amount to Transfer:", bg="#0019fc", fg="white", font=ARIAL).place(x=200, y=200)
        self.transfer_amt_entry = Entry(self.frame, bg="white", fg="black", font=ARIAL)
        self.transfer_amt_entry.place(x=200, y=230, width=300, height=25)

        # Transfer Button
        Button(self.frame, text="Transfer", bg="white", fg="#0019fc", font=ARIAL,
               command=self.user_account_transfer_transc).place(x=260, y=280, width=180, height=30)
        back_btn = Button(self.frame, text="Back", bg="white", fg="#0019fc", font=("Arial", 12, "bold"),
                          command=self.final_page, relief=RAISED, borderwidth=2)
        back_btn.place(x=380, y=320, width=140, height=35)

        self.frame.pack()

    def user_account_transfer_transc(self):
        import pandas as pd
        from tkinter import messagebox

        to_acc = self.transfer_acc_entry.get().strip()
        amount = self.transfer_amt_entry.get().strip()
        to_acc = str(to_acc)
        amount = float(amount)

        if not to_acc.isdigit() or not self.is_valid_amount(amount):
            messagebox.showinfo("Transfer Info", "Please enter valid numeric inputs.")
            return

        # Read and clean data
        data = pd.read_csv('bank_details.csv')
        data = data.dropna(subset=['account_number', 'account_balance'])

        # Strip spaces and fix datatypes
        data['account_number'] = data['account_number'].astype(str).str.strip()
        data['account_balance'] = data['account_balance'].astype(str).str.replace(',', '').str.strip()

        # Now safely convert account_balance to float
        data['account_balance'] = pd.to_numeric(data['account_balance'], errors='coerce')

        # Drop any rows where conversion failed (NaN balances)
        data = data.dropna(subset=['account_balance'])

        # Confirm types
        print(data.dtypes)

        # Validate recipient
        if to_acc == str(self.real_user):
            messagebox.showinfo("Transfer Info", "You cannot transfer money to your own account.")
            return

        if to_acc not in data['account_number'].values:
            print("Available accounts:", list(data['account_number'].values))  # Debug
            messagebox.showinfo("Transfer Info", "Recipient account not found.")
            return

        sender_balance = float(data.loc[data['account_number'] == str(self.real_user), 'account_balance'].values[0])

        if amount <= 0:
            messagebox.showinfo("Transfer Info", "Amount must be greater than zero.")
            return

        if sender_balance < amount:
            messagebox.showinfo("Transfer Info", "Insufficient balance.")
            return

        # Do the transaction
        data.loc[data['account_number'] == str(self.real_user), 'account_balance'] -= amount
        data.loc[data['account_number'] == to_acc, 'account_balance'] += amount
        data.to_csv('bank_details.csv', index=False)

        messagebox.showinfo("Transfer Info", f"₹{amount} transferred successfully to account {to_acc}.")
        self.user_balance()

        # Update the back button
        back_btn = Button(self.frame, text="Back", bg="white", fg="#0019fc", font=("Arial", 11, "bold"),
                          command=self.final_page)
        back_btn.place(x=390, y=290, width=120, height=30)

    def is_valid_amount(self, amount):
        # Check if the amount is a valid float or integer value
        try:
            float(amount)  # Try converting to float
            return True
        except ValueError:
            return False

    def user_balance(self):
        import pandas as pd

        if not hasattr(self, 'real_user'):
            messagebox.showerror("Error", "User not authenticated. Please log in first.")
            self.begin_page()
            return

        self.frame.destroy()
        self.frame = Frame(self.root, bg="#0019fc", width=900, height=500)

        # Title
        title = Label(self.frame, text="Balance Enquiry", bg="#0019fc", fg="white", font=("Arial", 20, "bold"))
        title.place(x=320, y=40, width=300)

        # Load balance from CSV
        try:
            data = pd.read_csv('bank_details.csv')
            account_info = data[data['account_number'] == self.real_user]

            if account_info.empty:
                raise ValueError("User account not found.")

            balance = account_info.iloc[0]['account_balance']

        except Exception as e:
            messagebox.showerror("Error", f"Could not fetch balance: {e}")
            self.begin_page()
            return

        # Balance display
        balance_label = Label(
            self.frame,
            text=f"Available Balance:\n\n₹ {balance}",
            font=("Arial", 18, "bold"),
            bg="#0019fc",
            fg="white",
            justify="center"
        )
        balance_label.place(x=200, y=140, width=500, height=150)

        # Back button
        back_btn = Button(self.frame, text="Back", bg="white", fg="#0019fc", font=("Arial", 12, "bold"),
                          command=self.final_page, relief=RAISED, borderwidth=2)
        back_btn.place(x=380, y=320, width=140, height=35)

        self.frame.pack()

    def user_deposit_money(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#0019fc", width=900, height=500)

        # Title
        title = Label(self.frame, text="Deposit Money", font=("Arial", 20, "bold"), bg="#0019fc", fg="white")
        title.place(x=300, y=50, width=300)

        # Amount Label
        self.label = Label(self.frame, text="Enter the amount to deposit", font=("Arial", 14),
                           bg="#0019fc", fg="white")
        self.label.place(x=250, y=140, width=400, height=30)

        # Entry Field
        self.money_box = Entry(self.frame, font=("Arial", 12), bg="white", fg="black",
                               highlightcolor="#50A8B0", highlightthickness=2)
        self.money_box.place(x=300, y=180, width=300, height=30)

        # Submit Button
        self.submitButton = Button(self.frame, text="Deposit", bg="white", fg="#0019fc",
                                   font=("Arial", 12, "bold"), command=self.user_deposit_trans)
        self.submitButton.place(x=370, y=230, width=160, height=35)

        # Back Button
        back_btn = Button(self.frame, text="Back", bg="white", fg="#0019fc", font=("Arial", 11, "bold"),
                          command=self.final_page)
        back_btn.place(x=390, y=290, width=120, height=30)

        self.frame.pack()

    def user_deposit_trans(self):
        import time
        if not hasattr(self, 'real_user'):
            messagebox.showerror("Error", "User not authenticated. Please log in first.")
            self.begin_page()
            return

        try:
            deposit_amount = int(self.money_box.get())
            if deposit_amount <= 0:
                messagebox.showerror("Invalid Amount", "Please enter a positive amount.")
                return

            data = pd.read_csv('bank_details.csv')

            if 'account_number' not in data.columns:
                raise ValueError("Missing 'account_number' column in data.")

            update_data = data.set_index('account_number')

            if self.real_user not in update_data.index:
                raise ValueError("User not found in records.")

            # Simulate processing delay
            loading_popup = Toplevel(self.root)
            loading_popup.configure(bg="#0019fc")
            Label(loading_popup, text="Depositing your money...\nPlease wait ⏳",
                  font=("Arial", 14, "bold"), bg="#0019fc", fg="white").pack(padx=40, pady=30)
            loading_popup.update()

            # Wait 5 seconds
            self.root.after(5000, lambda: self._complete_deposit(loading_popup, update_data, deposit_amount))

        except ValueError as ve:
            messagebox.showerror("Value Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def _complete_deposit(self, popup, update_data, deposit_amount):
        popup.destroy()

        # Update balance
        update_data.loc[self.real_user, 'account_balance'] = (
                float(update_data.loc[self.real_user, 'account_balance']) + deposit_amount
        )

        #update_data.loc[self.real_user, 'account_balance'] += deposit_amount
        update_data.reset_index(inplace=True)
        update_data.to_csv('bank_details.csv', index=False)

        messagebox.showinfo("Deposit Successful", f"₹{deposit_amount} has been successfully deposited!")
        self.user_balance()  # Optional: redirect to updated balance

    def user_withdrawl_money(self):
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#0019fc", width=900, height=500)

        # Title
        title = Label(self.frame, text="Withdraw Money", font=("Arial", 20, "bold"), bg="#0019fc", fg="white")
        title.place(x=300, y=50, width=300)

        # Input Label
        self.label = Label(self.frame, text="Enter the amount to withdraw", font=("Arial", 14),
                           bg="#0019fc", fg="white")
        self.label.place(x=250, y=140, width=400, height=30)

        # Entry Field
        self.money_box = Entry(self.frame, font=("Arial", 12), bg="white", fg="black",
                               highlightcolor="#50A8B0", highlightthickness=2)
        self.money_box.place(x=300, y=180, width=300, height=30)

        # Withdraw Button
        self.submitButton = Button(self.frame, text="Withdraw", bg="white", fg="#0019fc",
                                   font=("Arial", 12, "bold"), command=self.user_withdrawl_trans)
        self.submitButton.place(x=370, y=230, width=160, height=35)

        # Back Button
        back_btn = Button(self.frame, text="Back", bg="white", fg="#0019fc", font=("Arial", 11, "bold"),
                          command=self.final_page)
        back_btn.place(x=390, y=290, width=120, height=30)

        self.frame.pack()

    def user_withdrawl_trans(self):
        import time

        if not hasattr(self, 'real_user'):
            messagebox.showerror("Error", "User not authenticated. Please log in first.")
            self.begin_page()
            return

        try:
            # Get withdrawal amount from the user input
            withdraw_amount = int(self.money_box.get())

            # Validate the withdrawal amount
            if withdraw_amount <= 0:
                messagebox.showerror("Invalid Amount", "Please enter a positive withdrawal amount.")
                return

            data = pd.read_csv('bank_details.csv')

            if 'account_number' not in data.columns:
                raise ValueError("Missing 'account_number' column in data.")

            # Set the dataframe index to account_number for easy access
            update_data = data.set_index('account_number')

            if self.real_user not in update_data.index:
                raise ValueError("User not found in records.")

            # Simulate processing delay
            loading_popup = Toplevel(self.root)
            loading_popup.configure(bg="#0019fc")
            Label(loading_popup, text="Processing your withdrawal...\nPlease wait ⏳",
                  font=("Arial", 14, "bold"), bg="#0019fc", fg="white").pack(padx=40, pady=30)
            loading_popup.update()

            # Wait 5 seconds (simulating withdrawal processing time)
            self.root.after(5000, lambda: self._complete_withdrawal(loading_popup, update_data, withdraw_amount))

        except ValueError as ve:
            messagebox.showerror("Value Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def _complete_withdrawal(self, popup, update_data, withdraw_amount):
        try:
            # Close the loading popup after the process is complete
            popup.destroy()

            # Update the balance by subtracting the withdrawal amount
            update_data.loc[self.real_user, 'account_balance'] = (
                    float(update_data.loc[self.real_user, 'account_balance']) - withdraw_amount
            )

            # Reset the index and save the updated data back to the CSV
            update_data.reset_index(inplace=True)
            update_data.to_csv('bank_details.csv', index=False)

            # Show a success message
            messagebox.showinfo("Withdrawal Successful",
                                f"₹{withdraw_amount} has been successfully withdrawn. Please collect your cash.")

            # Optionally, update the user's balance or redirect to the final page
            self.user_balance()  # You can replace this with your method to update the balance on screen

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def write_to_csv(self):
        n = 11
        account_number = randint(10 ** (n - 1), 10 ** n - 1)
        bank = "Unilag Bank"
        account_balance = "10000"

        # Get data from entries
        name = self.entries["First Name"].get()
        username = self.entries["Username"].get()
        password = self.entries["Password"].get()
        email = self.entries["Email"].get()
        mobile = self.entries["Mobile Number"].get()
        address = self.entries["Address"].get()
        family_name = self.fam_name_entry.get() if self.fam_name_entry.winfo_ismapped() else ""
        shared_pin = self.pin_entry.get() if self.pin_entry.winfo_ismapped() else ""
        # Check if file exists
        file_path = 'bank_details.csv'

        with open(file_path, 'a', newline='\n') as f:
            writer = csv.writer(f)
            writer.writerow([ account_number, name, username, email, mobile,
                             address, bank,password, account_balance, family_name, shared_pin])

        messagebox.showinfo("Enrollment Info!", "Successfully Enrolled!")

    def video_capture_page(self):
        # Destroy the previous frame and create a new one for the video capture page
        self.frame.destroy()
        self.frame = Frame(self.root, bg="#0019fc", width=900, height=500)

        # Login Page Form Components
        self.label1 = Label(self.frame, text="Note:", bg="#0019fc", fg="white", font=ARIAL)
        self.label2 = Label(self.frame, text="1. By clicking on the 'Capture' button below, your image gets captured.",
                            bg="#0019fc", fg="white", font=ARIAL)
        self.label3 = Label(self.frame, text="2. You will be required to capture 5 images for full registration.",
                            bg="#0019fc", fg="white", font=ARIAL)
        self.label4 = Label(self.frame,
                            text="3. To capture each image, click the space bar on your keyboard when the camera turns on.",
                            bg="#0019fc", fg="white", font=ARIAL)
        self.label5 = Label(self.frame,
                            text="4. Please wait till you are notified that your capture was successful before leaving the page.",
                            bg="#0019fc", fg="white", font=ARIAL)
        self.label6 = Label(self.frame,
                            text="5. To begin, click the 'Capture' button below and press the space bar to capture a new image.",
                            bg="#0019fc", fg="white", font=ARIAL)

        # Read the CSV (with error handling)
        try:
            data = pd.read_csv('bank_details.csv', on_bad_lines='skip')
            print(data)  # Optional: You can print or process the data as per your requirement
        #except Exception as e:
            #print(f"Error reading CSV file: {e}")
           # messagebox.showerror("Error", "Failed to read bank details file.")


        except Exception as e:
            messagebox.showerror("CSV Read Error", f"Problem reading user data: {e}")
            return

        # Capture button
        self.button = Button(self.frame, text="Capture", bg="#50A8B0", fg="white", font=ARIAL, command=self.captureuser)

        # Place the labels and button in the frame
        self.label1.place(x=100, y=100, width=600, height=20)
        self.label2.place(x=100, y=120, width=600, height=20)
        self.label3.place(x=100, y=140, width=600, height=20)
        self.label4.place(x=100, y=160, width=600, height=20)
        self.label5.place(x=100, y=180, width=600, height=20)
        self.label6.place(x=100, y=200, width=600, height=20)
        self.button.place(x=100, y=230, width=600, height=30)

        # Pack the frame to display it
        self.frame.pack()

    # hit space bar to capture
    import cv2
    import os
    import pandas as pd
    from tkinter import messagebox

    def captureuser(self):
        # Read the last entry from the CSV file (assuming unique_id is in the first column)
        data = pd.read_csv('bank_details.csv', on_bad_lines='skip')
        name = data.loc[:, 'account_number'].values[-1]  # Get the last unique_id from the CSV file

        # Initialize camera
        cam = cv2.VideoCapture(0)
        cv2.namedWindow("capture")

        img_counter = 0

        # Create directory for saving images (if it doesn't exist already)
        dirname = f'dataset/{name}'
        os.makedirs(dirname, exist_ok=True)  # This will create the directory if it doesn't exist

        # Start capturing frames
        while True:
            ret, frame = cam.read()
            cv2.imshow("capture", frame)

            if img_counter == 5:
                cv2.destroyWindow("capture")
                break
            if not ret:
                break

            k = cv2.waitKey(1)

            if k % 256 == 27:
                # ESC pressed
                print("Escape hit, closing...")
                break
            elif k % 256 == 32:
                # SPACE pressed to capture image
                img_name = "{}.jpg".format(img_counter)
                img_path = os.path.join(dirname, img_name)  # Save image inside the correct folder
                cv2.imwrite(img_path, frame)
                print("{} written!".format(img_name))
                img_counter += 1

        # Release the camera
        cam.release()
        cv2.destroyAllWindows()

        # Call functions to process and train the model
        self.get_embeddings()
        self.train_model()

        # Show success message
        messagebox.showinfo('Registration Info', "Face ID Successfully Registered!")

        # Move to the next screen
        self.begin_page()

    def get_embeddings(self):
        # summary:
        # construct the argument parser and parse the arguments
        ap = argparse.ArgumentParser()
        ap.add_argument("-i", "--dataset", required=True,
                        help="path to input directory of faces + images")
        ap.add_argument("-e", "--embeddings", required=True,
                        help="path to output serialized db of facial embeddings")
        ap.add_argument("-d", "--detector", required=True,
                        help="path to OpenCV's deep learning face detector")
        ap.add_argument("-m", "--embedding-model", required=True,
                        help="path to OpenCV's deep learning face embedding model")
        ap.add_argument("-c", "--confidence", type=float, default=0.5,
                        help="minimum probability to filter weak detections")
        # args = vars(ap.parse_args())

        # load our serialized face detector from disk
        print("[INFO] loading face detector...")

        detector = cv2.dnn.readNetFromCaffe('face_detection_model/deploy.prototxt',
                                            'face_detection_model/res10_300x300_ssd_iter_140000.caffemodel')
        # load our serialized face embedding model from disk
        embedder = cv2.dnn.readNetFromTorch('nn4.small2.v1.t7')
        # embedder = cv2.dnn.readNetFromTorch('openface_nn4.small2.v1.t7')

        # grab the paths to the input images in our dataset
        print("[INFO] quantifying faces...")
        imagePaths = list(paths.list_images('dataset'))
        # initialize our lists of extracted facial embeddings and
        # corresponding people names
        knownEmbeddings = []
        knownNames = []
        # initialize the total number of faces processed
        total = 0
        # loop over the image paths
        for (i, imagePath) in enumerate(imagePaths):
            # extract the person name from the image path
            print("[INFO] processing image {}/{}".format(i + 1,
                                                         len(imagePaths)))
            name = imagePath.split(os.path.sep)[-2]

            # load the image, resize it to have a width of 600 pixels (while
            # maintaining the aspect ratio), and then grab the image
            # dimensions
            image = cv2.imread(imagePath)
            image = imutils.resize(image, width=600)
            (h, w) = image.shape[:2]
            # construct a blob from the image
            imageBlob = cv2.dnn.blobFromImage(
                cv2.resize(image, (300, 300)), 1.0, (300, 300),
                (104.0, 177.0, 123.0), swapRB=False, crop=False)

            # apply OpenCV's deep learning-based face detector to localize
            # faces in the input image
            detector.setInput(imageBlob)
            detections = detector.forward()

            # ensure at least one face was found
            if len(detections) > 0:
                # we're making the assumption that each image has only ONE
                # face, so find the bounding box with the largest probability
                i = np.argmax(detections[0, 0, :, 2])
                confidence = detections[0, 0, i, 2]

                # ensure that the detection with the largest probability also
                # means our minimum probability test (thus helping filter out
                # weak detections)
                if confidence > 0.5:
                    # compute the (x, y)-coordinates of the bounding box for
                    # the face
                    box = detections[0, 0, i, 3:7] * np.array([w, h, w, h])
                    (startX, startY, endX, endY) = box.astype("int")

                    # extract the face ROI and grab the ROI dimensions
                    face = image[startY:endY, startX:endX]
                    (fH, fW) = face.shape[:2]

                    # ensure the face width and height are sufficiently large
                    if fW < 20 or fH < 20:
                        continue

                    # construct a blob for the face ROI, then pass the blob
                    # through our face embedding model to obtain the 128-d
                    # quantification of the face
                    faceBlob = cv2.dnn.blobFromImage(face, 1.0 / 255,
                                                     (96, 96), (0, 0, 0), swapRB=True, crop=False)
                    embedder.setInput(faceBlob)
                    vec = embedder.forward()

                    # add the name of the person + corresponding face
                    # embedding to their respective lists
                    knownNames.append(name)
                    knownEmbeddings.append(vec.flatten())
                    total += 1
        # dump the facial embeddings + names to disk
        print("[INFO] serializing {} encodings...".format(total))
        data = {"embeddings": knownEmbeddings, "names": knownNames}
        f = open('output/embeddings.pickle', "wb")
        f.write(pickle.dumps(data))
        f.close()

    def train_model(self):
        # summary
        print("[INFO] loading face embeddings...")
        data = pickle.loads(open('output/embeddings.pickle', "rb").read())
        le = LabelEncoder()
        labels = le.fit_transform(data["names"])
        # train the model used to accept the 128-d embeddings of the face and
        # then produce the actual face recognition
        print("[INFO] training model...")
        recognizer = SVC(C=1.0, kernel="linear", probability=True)
        recognizer.fit(data["embeddings"], labels)
        # write the actual face recognition model to disk
        f = open('output/recognizer.pickle', "wb")
        f.write(pickle.dumps(recognizer))
        f.close()

        # write the label encoder to disk
        f = open('output/le.pickle', "wb")
        f.write(pickle.dumps(le))
        f.close()

    def video_check(self):

        detector = cv2.dnn.readNetFromCaffe('face_detection_model/deploy.prototxt',
                                            'face_detection_model/res10_300x300_ssd_iter_140000.caffemodel')
        # summary
        # load our serialized face embedding model from disk
        print("[INFO] loading face recognizer...")
        embedder = cv2.dnn.readNetFromTorch('nn4.small2.v1.t7')

        # load the actual face recognition model along with the label encoder
        recognizer = pickle.loads(open('output/recognizer.pickle', "rb").read())
        le = pickle.loads(open('output/le.pickle', "rb").read())

        # initialize the video stream, then allow the camera sensor to warm up
        print("[INFO] starting video stream...")
        vs = VideoStream(src=0).start()
        time.sleep(2.0)

        # run check for only 15seconds and then stop
        timeout = time.time() + 5

        # start the FPS throughput estimator
        fps = FPS().start()

        # loop over frames from the video file stream
        real_user_list = []
        while True:

            # run check for only 15seconds and then stop
            if time.time() > timeout:
                cv2.destroyWindow("Frame")
                break;

            # grab the frame from the threaded video stream
            frame = vs.read()

            # resize the frame to have a width of 600 pixels (while
            # maintaining the aspect ratio), and then grab the image
            # dimensions
            frame = imutils.resize(frame, width=800, height=200)
            (h, w) = frame.shape[:2]

            # construct a blob from the image
            imageBlob = cv2.dnn.blobFromImage(
                cv2.resize(frame, (300, 300)), 1.0, (300, 300),
                (104.0, 177.0, 123.0), swapRB=False, crop=False)

            # apply OpenCV's deep learning-based face detector to localize
            # faces in the input image
            detector.setInput(imageBlob)
            detections = detector.forward()

            # TODO: if 2 faces are detected alert the user of a warning
            # loop over the detections
            for i in range(0, detections.shape[2]):
                # extract the confidence (i.e., probability) associated with
                # the prediction
                confidence = detections[0, 0, i, 2]

                # filter out weak detections
                if confidence > 0.5:
                    # compute the (x, y)-coordinates of the bounding box for
                    # the face
                    box = detections[0, 0, i, 3:7] * np.array([w, h, w, h])
                    (startX, startY, endX, endY) = box.astype("int")

                    # extract the face ROI
                    face = frame[startY:endY, startX:endX]
                    (fH, fW) = face.shape[:2]

                    # ensure the face width and height are sufficiently large
                    if fW < 20 or fH < 20:
                        continue

                    # construct a blob for the face ROI, then pass the blob
                    # through our face embedding model to obtain the 128-d
                    # quantification of the face
                    faceBlob = cv2.dnn.blobFromImage(face, 1.0 / 255,
                                                     (96, 96), (0, 0, 0), swapRB=True, crop=False)
                    embedder.setInput(faceBlob)
                    vec = embedder.forward()

                    # perform classification to recognize the face
                    preds = recognizer.predict_proba(vec)[0]
                    j = np.argmax(preds)
                    proba = preds[j]
                    name = le.classes_[j]

                    # # draw the bounding box of the face along with the
                    # # associated probability
                    # text = "{}: {:.2f}%".format(name, proba * 100)
                    # y = startY - 10 if startY - 10 > 10 else startY + 10
                    # cv2.rectangle(frame, (startX, startY), (endX, endY),
                    #     (0, 0, 255), 2)
                    # cv2.putText(frame, text, (startX, y),
                    #     cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 255), 2)
                    # TODO: Handle if 2 faces are given.
                    # Decision boundary
                    if (name =='unknown' ) or (proba * 100) < 50:
                        print("Fraud detected")
                        real_user_list.append(name)
                    else:
                        # cv2.destroyWindow("Frame")
                        real_user_list.append(name)
                        break;

            # update the FPS counter
            fps.update()

            # show the output frame
            cv2.imshow("Frame", frame)
            key = cv2.waitKey(1) & 0xFF

            # if the `q` key was pressed, break from the loop
            if key == ord("q"):
                break

        # stop the timer and display FPS information
        fps.stop()
        print("[INFO] elasped time: {:.2f}".format(fps.elapsed()))
        print("[INFO] approx. FPS: {:.2f}".format(fps.fps()))

        # do a bit of cleanup
        cv2.destroyAllWindows()
        vs.stop()
        print(real_user_list)

        try:
            Counter(real_user_list).most_common(1)[0][0] == 'unknown'
        except IndexError:
            if self.countter != 0:
                messagebox._show("Verification Info!",
                                 "Face Id match failed! You have {} trials left".format(self.countter))
                self.countter = self.countter - 1
                self.video_check()
            else:
                messagebox._show("Verification Info!",
                                 "Face Id match failed! You cannot withdraw at this time, try again later")
                self.begin_page()
                self.countter = 2


        else:
            if Counter(real_user_list).most_common(1)[0][0] == 'unknown':
                if self.countter != 0:
                    messagebox._show("Verification Info!",
                                     "Face Id match failed! You have {} trials left".format(self.countter))
                    self.countter = self.countter - 1
                    self.video_check()
                else:
                    messagebox._show("Verification Info!",
                                     "Face Id match failed! You cannot withdraw at this time, try again later")
                    self.begin_page()
                    self.countter = 2

            else:
                self.real_user = int(Counter(real_user_list).most_common(1)[0][0])
                messagebox._show("Verification Info!", "Face Id match!")
                self.password_verification()
                self.selected_verification = "Face Recognition"


root = Tk()
root.title("Unilag Bank")
root.geometry("800x500")
root.configure(bg="white")
# icon = PhotoImage(file="IMG-f-WA0011 copy.png")
# root.tk.call("wm",'iconphoto',root._w,icon)
obj = BankUi(root)
root.mainloop()