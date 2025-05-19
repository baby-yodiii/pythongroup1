#Group 1 Project -- Dzhan,
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import hashlib
import re
from datetime import datetime
import os # For basic notification placeholder

# --- Optional Calendar Import ---
try:
    from tkcalendar import DateEntry
    HAS_TKCALENDAR = True
    print("tkcalendar found. Using DateEntry for date selection.")
except ImportError:
    HAS_TKCALENDAR = False
    print("Warning: tkcalendar not found. Using simple text entry for dates.")
    print("Install using: pip install tkcalendar")

# --- Constants ---
DATABASE_NAME = "healthcare_app_singlefile.db"

# --- Database Setup ---
def initialize_database():
    """Creates the database and necessary tables if they don't exist."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'provider' CHECK(role IN ('patient', 'provider', 'admin'))
    )
    ''')

    # Patients Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        dob TEXT, -- Store as TEXT YYYY-MM-DD
        gender TEXT,
        contact TEXT,
        address TEXT,
        medical_history TEXT,
        surgical_history TEXT
    )
    ''')

    # Appointments Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS appointments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        provider_name TEXT NOT NULL,
        appointment_datetime TEXT NOT NULL, -- Store as TEXT YYYY-MM-DD HH:MM
        reason TEXT,
        status TEXT DEFAULT 'Scheduled' CHECK(status IN ('Scheduled', 'Completed', 'Cancelled')),
        FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE
    )
    ''')

    # Insurance Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS insurance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        provider_name TEXT NOT NULL,
        policy_number TEXT NOT NULL,
        expiry_date TEXT, -- Store as TEXT YYYY-MM-DD
        coverage_details TEXT,
        FOREIGN KEY (patient_id) REFERENCES patients (id) ON DELETE CASCADE
    )
    ''')

    # Enable foreign keys every time a connection is made (important!)
    # This PRAGMA needs to be executed for each connection typically.
    # For simplicity here, we ensure tables exist. In functions below,
    # we could use a context manager or ensure it's set on each cursor.
    # cursor.execute("PRAGMA foreign_keys = ON;") # Less effective here than per-connection

    conn.commit()
    conn.close()
    print("Database initialized.")

# --- Utility Functions ---
def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(stored_hash, provided_password):
    """Verifies a provided password against a stored hash."""
    return stored_hash == hash_password(provided_password)

def send_notification(recipient_info, subject, body):
    """Placeholder for sending notifications (prints to console)."""
    print("-" * 30)
    print(f"--- NOTIFICATION ---")
    print(f"To: {recipient_info}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")
    print("-" * 30)
    # In a real app, integrate email/desktop notifications here

def is_valid_date_format(date_str):
    """Checks if a string is a valid YYYY-MM-DD date format."""
    return bool(re.match(r'^\d{4}-\d{2}-\d{2}$', date_str))

def is_valid_contact(contact_str):
    """Checks if contact is exactly 11 digits."""
    return contact_str.isdigit() and len(contact_str) == 11

# --- Authentication Logic ---
def register_user(username, password, role='provider'):
    """Registers a new user."""
    # Validation moved to RegisterScreen's attempt_register
    hashed_pw = hash_password(password)
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, hashed_pw, role))
        conn.commit()
        return True, f"User '{username}' registered successfully."
    except sqlite3.IntegrityError:
        return False, f"Username '{username}' already exists."
    except Exception as e:
        return False, f"An unexpected database error occurred: {e}"
    finally:
        conn.close()

def authenticate_user(username, password):
    """Authenticates a user."""
    if not username or not password:
        return None, "Please enter both username and password."

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            stored_hash, role = result
            if verify_password(stored_hash, password):
                return role, "Login successful." # Return role and success message
            else:
                return None, "Incorrect password."
        else:
            return None, "Username not found."
    except Exception as e:
        return None, f"An unexpected database error occurred: {e}"
    finally:
        conn.close()


# --- GUI Application ---
class HealthCareApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Health Care Management System (Single File)")
        self.minsize(900, 650) # Set minimum size
        self.eval('tk::PlaceWindow . center') # Center window

        # Apply a theme
        style = ttk.Style(self)
        try:
            available_themes = style.theme_names()
            if 'clam' in available_themes: style.theme_use('clam')
            elif 'vista' in available_themes: style.theme_use('vista')
        except tk.TclError: pass # Ignore if themes aren't available


        self.current_user = None
        self.current_user_role = None

        # Initialize Database
        initialize_database()

        # --- Main Container ---
        self.container = tk.Frame(self)
        self.container.pack(side="top", fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        self._create_frames()
        self.show_frame("LoginScreen")

        self.protocol("WM_DELETE_WINDOW", self.on_closing) # Handle window close

    def _create_frames(self):
        """Creates all the frames for the application."""
        for F in (LoginScreen, RegisterScreen, MainScreen):
            page_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

    def show_frame(self, page_name):
        """Shows the specified frame."""
        if page_name not in self.frames:
            print(f"Error: Frame '{page_name}' not found.")
            return
        frame = self.frames[page_name]
        if page_name == "MainScreen":
            if self.current_user:
                 frame.update_welcome_message(self.current_user)
                 frame.refresh_data() # Refresh data when showing main screen
            else:
                 # Redirect to login if no user
                 self.show_frame("LoginScreen")
                 return
        frame.tkraise()

    def login_success(self, username, role):
        """Handles successful login."""
        self.current_user = username
        self.current_user_role = role
        self.show_frame("MainScreen")

    def logout(self):
        """Handles user logout."""
        self.current_user = None
        self.current_user_role = None
        self.show_frame("LoginScreen")
        self.frames["LoginScreen"].username_entry.focus()

    def on_closing(self):
        """Handles window closing action."""
        if messagebox.askokcancel("Quit", "Do you want to exit the application?"):
            self.destroy()

    def refresh_dependent_dropdowns(self):
         """Refreshes patient dropdowns in appointment/insurance tabs."""
         if "MainScreen" in self.frames:
             main_screen = self.frames["MainScreen"]
             if hasattr(main_screen, 'appointment_frame'):
                 main_screen.appointment_frame.load_patients_for_dropdown()
             if hasattr(main_screen, 'insurance_frame'):
                 main_screen.insurance_frame.load_patients_for_dropdown()

# --- Login Screen ---
class LoginScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        container = ttk.Frame(self, padding="30 30 30 30")
        container.pack(expand=True)

        ttk.Label(container, text="Login", font=("Arial", 18)).grid(row=0, column=0, columnspan=2, pady=20)

        ttk.Label(container, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = ttk.Entry(container, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(container, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = ttk.Entry(container, show="*", width=30)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)
        self.password_entry.bind("<Return>", self.attempt_login)

        button_frame = ttk.Frame(container)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)

        login_button = ttk.Button(button_frame, text="Login", command=self.attempt_login, width=15)
        login_button.pack(side=tk.LEFT, padx=10)

        register_button = ttk.Button(button_frame, text="Register New User",
                                     command=lambda: controller.show_frame("RegisterScreen"), width=15)
        register_button.pack(side=tk.LEFT, padx=10)

        self.username_entry.focus()

    def attempt_login(self, event=None):
        username = self.username_entry.get()
        password = self.password_entry.get()

        role, message = authenticate_user(username, password)

        if role:
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.controller.login_success(username, role)
        else:
             messagebox.showerror("Login Failed", message)
             self.password_entry.delete(0, tk.END)
             self.password_entry.focus()


# --- Registration Screen ---
class RegisterScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        container = ttk.Frame(self, padding="30 30 30 30")
        container.pack(expand=True)

        ttk.Label(container, text="Register New User", font=("Arial", 18)).grid(row=0, column=0, columnspan=2, pady=20)

        ttk.Label(container, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_entry = ttk.Entry(container, width=30)
        self.username_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(container, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_entry = ttk.Entry(container, show="*", width=30)
        self.password_entry.grid(row=2, column=1, padx=5, pady=5)

        ttk.Label(container, text="Confirm Password:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.confirm_password_entry = ttk.Entry(container, show="*", width=30)
        self.confirm_password_entry.grid(row=3, column=1, padx=5, pady=5)
        self.confirm_password_entry.bind("<Return>", self.attempt_register)

        button_frame = ttk.Frame(container)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)

        register_button = ttk.Button(button_frame, text="Register", command=self.attempt_register, width=15)
        register_button.pack(side=tk.LEFT, padx=10)

        back_button = ttk.Button(button_frame, text="Back to Login",
                                 command=lambda: controller.show_frame("LoginScreen"), width=15)
        back_button.pack(side=tk.LEFT, padx=10)

    def attempt_register(self, event=None):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        # Input Validation
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return
        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters long.")
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            self.password_entry.delete(0, tk.END)
            self.confirm_password_entry.delete(0, tk.END)
            self.password_entry.focus()
            return

        # Call registration logic
        success, message = register_user(username, password)

        if success:
             messagebox.showinfo("Success", message)
             self.username_entry.delete(0, tk.END)
             self.password_entry.delete(0, tk.END)
             self.confirm_password_entry.delete(0, tk.END)
             self.controller.show_frame("LoginScreen")
        else:
             messagebox.showerror("Registration Failed", message)
             self.password_entry.delete(0, tk.END)
             self.confirm_password_entry.delete(0, tk.END)
             self.password_entry.focus()


# --- Main Application Screen (Post-Login) ---
class MainScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        # --- Top Bar ---
        top_frame = ttk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        self.welcome_label = ttk.Label(top_frame, text="Welcome!", font=("Arial", 12), anchor="w")
        self.welcome_label.pack(side=tk.LEFT, padx=10, pady=5)

        logout_button = ttk.Button(top_frame, text="Logout", command=controller.logout, width=10)
        logout_button.pack(side=tk.RIGHT, padx=10, pady=5)

        # --- Main Content Area (Notebook Tabs) ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(pady=10, padx=10, expand=True, fill="both")

        # Create instances of the tab frames
        self.patient_frame = PatientManagementScreen(self.notebook, self.controller)
        self.appointment_frame = AppointmentScreen(self.notebook, self.controller)
        self.insurance_frame = InsuranceScreen(self.notebook, self.controller)
        self.diagnostic_frame = DiagnosticToolsScreen(self.notebook, self.controller)

        # Add frames to the notebook
        self.notebook.add(self.patient_frame, text="Patient Management")
        self.notebook.add(self.appointment_frame, text="Appointments")
        self.notebook.add(self.insurance_frame, text="Insurance Info")
        self.notebook.add(self.diagnostic_frame, text="Diagnostic Tools")

    def update_welcome_message(self, username):
        self.welcome_label.config(text=f"Welcome, {username}!")

    def refresh_data(self):
        """Refreshes data in all relevant tabs."""
        if hasattr(self, 'patient_frame'):
            self.patient_frame.load_patients_to_treeview()
        if hasattr(self, 'appointment_frame'):
            self.appointment_frame.load_patients_for_dropdown()
            self.appointment_frame.load_appointments()
        if hasattr(self, 'insurance_frame'):
             self.insurance_frame.load_patients_for_dropdown()
             self.insurance_frame.load_insurance_records()


# --- Patient Management Screen ---
class PatientManagementScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.selected_patient_id = None

        # Configure grid weights for resizing
        self.grid_columnconfigure(0, weight=1) # List frame
        self.grid_columnconfigure(1, weight=1) # Form frame
        self.grid_rowconfigure(0, weight=1)

        # --- Patient List ---
        list_frame = ttk.LabelFrame(self, text="Patients")
        list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        cols = ("ID", "Name", "DOB", "Gender", "Contact")
        self.patient_tree = ttk.Treeview(list_frame, columns=cols, show='headings', height=15)
        for col in cols:
            self.patient_tree.heading(col, text=col)
            self.patient_tree.column(col, width=100, anchor=tk.W, stretch=tk.NO)
        self.patient_tree.column("ID", width=50, stretch=tk.NO)
        self.patient_tree.column("Name", width=150, stretch=tk.YES)
        self.patient_tree.column("Contact", width=120, stretch=tk.YES)
        self.patient_tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.patient_tree.yview)
        self.patient_tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.patient_tree.bind('<<TreeviewSelect>>', self.on_patient_select)

        # --- Patient Details Form ---
        form_frame = ttk.LabelFrame(self, text="Patient Details")
        form_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        form_frame.grid_columnconfigure(1, weight=1) # Make entry column resize

        # Use DB column names as keys where possible
        labels_fields = {
            "Name:": "name",
            "Date of Birth:": "dob", # Label changed slightly
            "Gender:": "gender",
            "Contact (11 digits):": "contact", # Label updated
            "Address:": "address",
            "Medical History:": "medical_history",
            "Surgical History:": "surgical_history"
        }
        self.patient_entries = {} # Stores the input widgets

        row_num = 0
        for label_text, field_key in labels_fields.items():
            label = ttk.Label(form_frame, text=label_text)
            label.grid(row=row_num, column=0, padx=5, pady=5, sticky="w")

            widget = None # Initialize widget placeholder
            if field_key == "gender":
                # *** Use Combobox for Gender ***
                widget = ttk.Combobox(form_frame, values=["Male", "Female", "Other", ""], state="readonly", width=38) # Added "" for clearing
                widget.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
            elif field_key == "dob":
                # *** Use DateEntry for DOB if available ***
                if HAS_TKCALENDAR:
                    widget = DateEntry(form_frame, width=38, background='darkblue', foreground='white',
                                       borderwidth=2, date_pattern='yyyy-mm-dd', state="readonly")
                    widget.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
                else: # Fallback to Entry
                    widget = ttk.Entry(form_frame, width=40)
                    widget.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
                    widget.insert(0, "YYYY-MM-DD") # Add placeholder
            elif "history" in field_key: # Check for history fields
                 # Frame for Text widget and its scrollbar
                text_frame = ttk.Frame(form_frame)
                text_frame.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
                text_frame.grid_columnconfigure(0, weight=1)
                text_frame.grid_rowconfigure(0, weight=1)

                widget = tk.Text(text_frame, height=4, width=35, wrap=tk.WORD)
                widget.grid(row=0, column=0, sticky="ew")
                txt_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=widget.yview)
                widget.configure(yscrollcommand=txt_scroll.set)
                txt_scroll.grid(row=0, column=1, sticky='ns')
            else: # Default to Entry for other fields
                widget = ttk.Entry(form_frame, width=40)
                widget.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")

            if widget: # Ensure widget was created before storing
                self.patient_entries[field_key] = widget
            row_num += 1

        # --- Buttons ---
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=row_num, column=0, columnspan=2, pady=15, sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ttk.Button(button_frame, text="Add New", command=self.add_patient).grid(row=0, column=0, padx=5, sticky="ew")
        ttk.Button(button_frame, text="Update", command=self.update_patient).grid(row=0, column=1, padx=5, sticky="ew")
        ttk.Button(button_frame, text="Delete", command=self.delete_patient).grid(row=0, column=2, padx=5, sticky="ew")
        ttk.Button(button_frame, text="Clear", command=self.clear_patient_form).grid(row=0, column=3, padx=5, sticky="ew")

        self.load_patients_to_treeview() # Load initial data

    def _get_patient_data_from_form(self):
        """Helper to get data from the form entries/text widgets, including validation."""
        data = {}
        has_error = False
        error_msg = ""

        for key, widget in self.patient_entries.items():
            value = ""
            if isinstance(widget, tk.Text):
                value = widget.get("1.0", tk.END).strip()
            elif HAS_TKCALENDAR and isinstance(widget, DateEntry) and key == "dob":
                try:
                    # Get date only if a date is selected, otherwise it's None
                    date_obj = widget.get_date()
                    value = date_obj.strftime('%Y-%m-%d') if date_obj else ""
                except Exception: # Handle potential errors getting date
                    value = "" # Treat as empty if error
            elif isinstance(widget, (ttk.Entry, ttk.Combobox)):
                value = widget.get().strip()
            data[key] = value

        # --- Validation ---
        if not data.get('name'):
             error_msg = "Patient name cannot be empty."
             self.patient_entries['name'].focus()
             has_error = True
        elif data.get('contact') and not is_valid_contact(data['contact']): # Use helper
             error_msg = "Contact number must be exactly 11 digits."
             self.patient_entries['contact'].focus()
             has_error = True
        elif not HAS_TKCALENDAR and data.get('dob') and not is_valid_date_format(data['dob']):
             # Validate format only if using the fallback Entry for DOB
             error_msg = "Invalid Date of Birth format. Use YYYY-MM-DD."
             self.patient_entries['dob'].focus()
             has_error = True
        # Add more validation as needed

        if has_error:
             messagebox.showwarning("Input Error", error_msg)
             return None
        else:
             return data

    def load_patients_to_treeview(self):
        """Fetches patients from DB and populates the Treeview."""
        selected_items = self.patient_tree.selection()
        scroll_pos = self.patient_tree.yview()

        for i in self.patient_tree.get_children():
            self.patient_tree.delete(i)

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id, name, dob, gender, contact FROM patients ORDER BY name")
            rows = cursor.fetchall()
            for row in rows:
                # Format None values for display
                display_row = [val if val is not None else "N/A" for val in row]
                self.patient_tree.insert('', tk.END, values=display_row)
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load patients: {e}")
        finally:
            conn.close()

        if selected_items:
             self.patient_tree.selection_set(selected_items)
        self.patient_tree.yview_moveto(scroll_pos[0])


    def on_patient_select(self, event):
        """Handles selection change in the patient Treeview."""
        selected_items = self.patient_tree.selection()
        if not selected_items:
            self.clear_patient_form()
            return

        selected_item = selected_items[0]
        selected_id = self.patient_tree.item(selected_item)['values'][0]

        # Avoid reloading if same patient clicked (optional optimization)
        # if selected_id == self.selected_patient_id:
        #     return
        self.selected_patient_id = selected_id

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        try:
            # Fetch all columns needed for the form
            cursor.execute("SELECT name, dob, gender, contact, address, medical_history, surgical_history FROM patients WHERE id = ?",
                           (self.selected_patient_id,))
            patient_data = cursor.fetchone() # Returns a tuple in order
            if patient_data:
                # Map tuple data to form keys based on the SELECT order
                form_keys = ['name', 'dob', 'gender', 'contact', 'address', 'medical_history', 'surgical_history']
                self.clear_patient_form(clear_id=False) # Keep selected ID

                for i, key in enumerate(form_keys):
                    widget = self.patient_entries.get(key)
                    value = patient_data[i] if patient_data[i] is not None else ""

                    if isinstance(widget, tk.Text):
                        widget.delete("1.0", tk.END)
                        widget.insert("1.0", value)
                    elif isinstance(widget, ttk.Combobox):
                         widget.set(value) # Set value for Combobox
                    elif HAS_TKCALENDAR and isinstance(widget, DateEntry) and key == "dob":
                        if value and is_valid_date_format(value):
                            try:
                                date_obj = datetime.strptime(value, '%Y-%m-%d').date()
                                widget.set_date(date_obj)
                            except ValueError:
                                widget.delete(0, tk.END) # Clear if invalid format somehow
                        else:
                             widget.delete(0, tk.END) # Clear if no date
                    elif isinstance(widget, ttk.Entry): # Handle Entry and DateEntry fallback
                        widget.delete(0, tk.END)
                        widget.insert(0, value)
            else:
                messagebox.showerror("Error", f"Could not find details for patient ID {self.selected_patient_id}.")
                self.clear_patient_form()

        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load patient details: {e}")
            self.clear_patient_form()
        finally:
            conn.close()

    def add_patient(self):
        """Adds a new patient record to the database."""
        patient_data = self._get_patient_data_from_form()
        if not patient_data: return # Validation failed

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        # Ensure PRAGMA is enabled for this connection
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            # Use tuple with correct order matching INSERT statement
            data_tuple = (
                patient_data['name'],
                patient_data['dob'] if patient_data['dob'] else None, # Handle empty date
                patient_data['gender'] if patient_data['gender'] else None, # Handle empty gender
                patient_data['contact'],
                patient_data['address'],
                patient_data['medical_history'],
                patient_data['surgical_history']
            )
            cursor.execute("""
                INSERT INTO patients (name, dob, gender, contact, address, medical_history, surgical_history)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, data_tuple)
            conn.commit()
            messagebox.showinfo("Success", f"Patient '{patient_data['name']}' added successfully.")
            self.load_patients_to_treeview()
            self.clear_patient_form()
            self.controller.refresh_dependent_dropdowns() # Update dropdowns in other tabs
        except Exception as e:
            conn.rollback() # Rollback on error
            messagebox.showerror("Database Error", f"Failed to add patient: {e}")
        finally:
            conn.close()

    def update_patient(self):
        """Updates the selected patient record."""
        if self.selected_patient_id is None:
            messagebox.showwarning("Selection Error", "Please select a patient to update.")
            return

        patient_data = self._get_patient_data_from_form()
        if not patient_data: return

        if not messagebox.askyesno("Confirm Update", f"Are you sure you want to update patient ID {self.selected_patient_id}?"):
            return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            # Use tuple with correct order matching UPDATE statement, plus ID at the end
            data_tuple = (
                patient_data['name'],
                patient_data['dob'] if patient_data['dob'] else None,
                patient_data['gender'] if patient_data['gender'] else None,
                patient_data['contact'],
                patient_data['address'],
                patient_data['medical_history'],
                patient_data['surgical_history'],
                self.selected_patient_id # ID for the WHERE clause
            )
            cursor.execute("""
                UPDATE patients
                SET name = ?, dob = ?, gender = ?, contact = ?, address = ?,
                    medical_history = ?, surgical_history = ?
                WHERE id = ?
            """, data_tuple)
            conn.commit()
            if cursor.rowcount > 0:
                messagebox.showinfo("Success", f"Patient ID {self.selected_patient_id} updated successfully.")
                # Preserve selection after refresh
                original_selection = self.patient_tree.selection()
                self.load_patients_to_treeview()
                if original_selection:
                    self.patient_tree.selection_set(original_selection)
                self.controller.refresh_dependent_dropdowns() # Update dropdowns
            else:
                 messagebox.showwarning("Update Warning", f"Patient ID {self.selected_patient_id} not found or no changes detected.")
        except Exception as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to update patient: {e}")
        finally:
            conn.close()

    def delete_patient(self):
        """Deletes the selected patient record."""
        if self.selected_patient_id is None:
            messagebox.showwarning("Selection Error", "Please select a patient to delete.")
            return

        patient_name = ""
        selected_item = self.patient_tree.selection()
        if selected_item:
            try: # Get name from treeview for confirmation message
                 patient_name = self.patient_tree.item(selected_item[0])['values'][1]
            except IndexError: pass # Ignore if columns change

        confirm_msg = f"Are you sure you want to permanently delete patient '{patient_name}' (ID: {self.selected_patient_id})?\n\nThis will also delete ALL associated appointments and insurance records."
        if not messagebox.askyesno("Confirm Delete", confirm_msg, icon='warning'):
            return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;") # Ensure cascade delete works
        try:
            cursor.execute("DELETE FROM patients WHERE id = ?", (self.selected_patient_id,))
            conn.commit()
            if cursor.rowcount > 0:
                messagebox.showinfo("Success", f"Patient ID {self.selected_patient_id} deleted successfully.")
                self.load_patients_to_treeview()
                self.clear_patient_form()
                self.controller.refresh_dependent_dropdowns() # Update dropdowns
            else:
                 messagebox.showwarning("Delete Warning", f"Patient ID {self.selected_patient_id} not found.")

        except sqlite3.Error as e:
            # Foreign key errors might manifest here if cascade isn't working as expected
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to delete patient (ID: {self.selected_patient_id}).\nError: {e}\n\nCheck if associated records exist or if foreign key constraints are active.")
        except Exception as e:
             conn.rollback()
             messagebox.showerror("Error", f"An unexpected error occurred during deletion: {e}")
        finally:
            conn.close()

    def clear_patient_form(self, clear_id=True):
        """Clears all entries in the patient form."""
        if clear_id:
            self.selected_patient_id = None

        for key, widget in self.patient_entries.items():
            if isinstance(widget, tk.Text):
                widget.delete("1.0", tk.END)
            elif isinstance(widget, ttk.Combobox):
                 widget.set("") # Clear combobox selection
            elif HAS_TKCALENDAR and isinstance(widget, DateEntry) and key == "dob":
                 # Clearing DateEntry: Set underlying Entry to empty
                 # Or set date to None if method exists - simpler to clear text
                 widget.delete(0, tk.END)
                 # widget.set_date(None) # Might cause issues if underlying var linked
            elif isinstance(widget, ttk.Entry): # Handles Entry and DateEntry fallback
                widget.delete(0, tk.END)
                # Add back placeholder for fallback DOB entry
                if not HAS_TKCALENDAR and key == 'dob':
                     widget.insert(0, "YYYY-MM-DD")

        if clear_id:
             self.patient_tree.selection_remove(self.patient_tree.selection()) # Deselect tree


# --- Appointment Screen ---
class AppointmentScreen(tk.Frame):
    # ... (AppointmentScreen code remains largely the same as the previous single-file version) ...
    # ... (Make sure it uses load_patients_for_dropdown and load_appointments correctly) ...
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.patients_dict = {} # To map patient names to IDs

        self.grid_rowconfigure(0, weight=3) # List takes more space
        self.grid_rowconfigure(1, weight=1) # Form takes less
        self.grid_columnconfigure(0, weight=1)

        # --- Appointment List ---
        list_frame = ttk.LabelFrame(self, text="Upcoming & Recent Appointments")
        list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        cols = ("ID", "Patient Name", "Provider", "Date & Time", "Reason", "Status")
        self.appt_tree = ttk.Treeview(list_frame, columns=cols, show='headings', height=10)
        for col in cols:
            self.appt_tree.heading(col, text=col)
            self.appt_tree.column(col, width=120, anchor=tk.W, stretch=tk.NO)
        self.appt_tree.column("ID", width=50, stretch=tk.NO)
        self.appt_tree.column("Patient Name", width=150, stretch=tk.YES)
        self.appt_tree.column("Date & Time", width=150, stretch=tk.YES)
        self.appt_tree.column("Reason", width=180, stretch=tk.YES)
        self.appt_tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.appt_tree.yview)
        self.appt_tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        # --- Scheduling Form ---
        form_frame = ttk.LabelFrame(self, text="Schedule New Appointment")
        form_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        form_frame.grid_columnconfigure(1, weight=1)
        form_frame.grid_columnconfigure(3, weight=1)

        ttk.Label(form_frame, text="Patient:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.patient_var = tk.StringVar()
        self.patient_dropdown = ttk.Combobox(form_frame, textvariable=self.patient_var, state="readonly", width=30)
        self.patient_dropdown.grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky="ew")

        ttk.Label(form_frame, text="Provider Name:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.provider_entry = ttk.Entry(form_frame, width=30)
        self.provider_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky="ew")

        ttk.Label(form_frame, text="Date:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        if HAS_TKCALENDAR:
             self.date_entry = DateEntry(form_frame, width=12, background='darkblue',
                                        foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd', state="readonly")
             self.date_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        else:
             self.date_entry = ttk.Entry(form_frame, width=15) # Simple entry if tkcalendar not found
             self.date_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
             self.date_entry.insert(0, "YYYY-MM-DD") # Prompt


        ttk.Label(form_frame, text="Time (HH:MM):").grid(row=2, column=2, padx=(15, 5), pady=5, sticky="w")
        self.time_entry = ttk.Entry(form_frame, width=8)
        self.time_entry.grid(row=2, column=3, padx=5, pady=5, sticky="w")
        self.time_entry.insert(0, "09:00") # Default time

        ttk.Label(form_frame, text="Reason:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.reason_entry = ttk.Entry(form_frame, width=50)
        self.reason_entry.grid(row=3, column=1, columnspan=3, padx=5, pady=5, sticky="ew")

        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=4, column=0, columnspan=4, pady=10, sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ttk.Button(button_frame, text="Schedule Appointment", command=self.schedule_appointment).grid(row=0, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
        ttk.Button(button_frame, text="Cancel Selected Appt", command=self.cancel_appointment).grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        ttk.Button(button_frame, text="Clear Form", command=self.clear_appointment_form).grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        self.load_patients_for_dropdown()
        self.load_appointments()

    def load_patients_for_dropdown(self):
        """Loads patient names and IDs for the Combobox."""
        current_selection = self.patient_var.get() # Preserve selection if possible
        self.patients_dict = {}
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        patient_names = []
        try:
            cursor.execute("SELECT id, name FROM patients ORDER BY name")
            patients = cursor.fetchall()
            for patient_id, name in patients:
                display_name = f"{name} (ID: {patient_id})"
                self.patients_dict[display_name] = patient_id
                patient_names.append(display_name)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load patients for dropdown: {e}")
        finally:
            conn.close()

        self.patient_dropdown['values'] = patient_names
        # Try to restore selection or default to first/empty
        if current_selection in patient_names:
             self.patient_dropdown.set(current_selection)
        elif patient_names:
             self.patient_dropdown.current(0)
        else:
             self.patient_dropdown.set('')


    def load_appointments(self):
        """Loads appointments into the Treeview."""
        for i in self.appt_tree.get_children():
            self.appt_tree.delete(i)
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        try:
            # Fetch appointments joining patient name for display
            cursor.execute("""
                SELECT a.id, p.name as patient_name, a.provider_name, a.appointment_datetime, a.reason, a.status
                FROM appointments a
                JOIN patients p ON a.patient_id = p.id
                WHERE a.status = 'Scheduled' OR a.status = 'Completed' -- Filter out cancelled maybe?
                ORDER BY a.appointment_datetime
            """)
            rows = cursor.fetchall()
            for row in rows:
                # row is now a tuple: (appt_id, patient_name, provider, dt_str, reason, status)
                self.appt_tree.insert('', tk.END, values=row)
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load appointments: {e}")
        finally:
            conn.close()

    def check_conflict(self, provider, dt_str):
        """Basic check for appointment conflict (same provider, same time)."""
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        conflict = False
        try:
            cursor.execute("""
                SELECT id FROM appointments
                WHERE provider_name = ? AND appointment_datetime = ? AND status = 'Scheduled'
            """, (provider, dt_str))
            result = cursor.fetchone()
            conflict = result is not None # True if a conflicting appointment exists
        except Exception as e:
            messagebox.showerror("Database Error", f"Error checking for conflicts: {e}")
            conflict = True # Assume conflict if error occurs during check
        finally:
            conn.close()
        return conflict


    def schedule_appointment(self):
        """Schedules a new appointment."""
        patient_display_name = self.patient_var.get()
        if not patient_display_name or patient_display_name not in self.patients_dict:
            messagebox.showerror("Error", "Please select a valid patient.")
            return
        patient_id = self.patients_dict.get(patient_display_name)

        provider = self.provider_entry.get().strip()
        if not provider:
            messagebox.showerror("Error", "Please enter a provider name.")
            return

        # Get date and time, combine them
        date_str = ""
        if HAS_TKCALENDAR:
            try:
                date_str = self.date_entry.get_date().strftime('%Y-%m-%d')
            except AttributeError: # Handle case where date isn't set in DateEntry
                 messagebox.showerror("Input Error", "Please select a valid appointment date.")
                 return
        else:
             date_str = self.date_entry.get().strip()
             if not is_valid_date_format(date_str):
                  messagebox.showerror("Input Error", "Invalid date format. Use YYYY-MM-DD.")
                  return

        time_str = self.time_entry.get().strip()
        if not re.match(r'^\d{2}:\d{2}$', time_str):
            messagebox.showerror("Input Error", "Invalid time format. Use HH:MM (24-hour).")
            return
        try: # Validate time values
            hour, minute = map(int, time_str.split(':'))
            if not (0 <= hour <= 23 and 0 <= minute <= 59): raise ValueError()
        except ValueError:
             messagebox.showerror("Input Error", "Invalid time value (HH 00-23, MM 00-59).")
             return

        appointment_datetime = f"{date_str} {time_str}"
        reason = self.reason_entry.get().strip()

        # Check for conflicts
        if self.check_conflict(provider, appointment_datetime):
             messagebox.showwarning("Conflict Detected", f"An appointment already exists for {provider} at {appointment_datetime}. Please choose a different time.")
             return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            cursor.execute("""
                INSERT INTO appointments (patient_id, provider_name, appointment_datetime, reason)
                VALUES (?, ?, ?, ?)
            """, (patient_id, provider, appointment_datetime, reason))
            conn.commit()
            messagebox.showinfo("Success", "Appointment scheduled successfully.")
            self.load_appointments() # Refresh list
            # Send notification placeholder
            patient_name_only = patient_display_name.split(" (ID:")[0]
            send_notification(
                recipient_info=f"Patient: {patient_name_only}, Provider: {provider}",
                subject="Appointment Confirmation",
                body=f"Your appointment with {provider} is scheduled for {appointment_datetime}. Reason: {reason if reason else 'N/A'}"
            )
            self.reason_entry.delete(0, tk.END) # Clear reason field

        except Exception as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to schedule appointment: {e}")
        finally:
            conn.close()

    def cancel_appointment(self):
        """Changes the status of the selected appointment to 'Cancelled'."""
        selected_items = self.appt_tree.selection()
        if not selected_items:
            messagebox.showwarning("Selection Error", "Please select an appointment to cancel.")
            return

        selected_item = selected_items[0]
        try:
            appointment_id = self.appt_tree.item(selected_item)['values'][0]
            patient_name = self.appt_tree.item(selected_item)['values'][1]
            appt_datetime = self.appt_tree.item(selected_item)['values'][3]
            current_status = self.appt_tree.item(selected_item)['values'][5]
        except IndexError:
             messagebox.showerror("Error", "Could not retrieve appointment details from selection.")
             return

        if current_status != 'Scheduled':
            messagebox.showwarning("Action Not Allowed", f"Cannot cancel an appointment with status '{current_status}'.")
            return

        if not messagebox.askyesno("Confirm Cancel", f"Are you sure you want to cancel appointment ID {appointment_id} for {patient_name} at {appt_datetime}?", icon='warning'):
             return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            cursor.execute("UPDATE appointments SET status = 'Cancelled' WHERE id = ?", (appointment_id,))
            conn.commit()
            if cursor.rowcount > 0:
                 messagebox.showinfo("Success", f"Appointment ID {appointment_id} cancelled.")
                 self.load_appointments() # Refresh list
                 send_notification(
                      recipient_info=f"Patient: {patient_name}",
                      subject="Appointment Cancellation",
                      body=f"Your appointment scheduled for {appt_datetime} has been cancelled."
                 )
            else:
                 messagebox.showwarning("Cancellation Failed", f"Appointment ID {appointment_id} not found or already cancelled.")

        except Exception as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to cancel appointment: {e}")
        finally:
            conn.close()

    def clear_appointment_form(self):
        """Clears the scheduling form fields."""
        # Decide which fields to clear - keep patient/provider?
        # self.patient_var.set('')
        # self.provider_entry.delete(0, tk.END)
        if not HAS_TKCALENDAR:
             self.date_entry.delete(0, tk.END)
             self.date_entry.insert(0, "YYYY-MM-DD")
        # self.time_entry.delete(0, tk.END) # Maybe reset to default?
        # self.time_entry.insert(0, "09:00")
        self.reason_entry.delete(0, tk.END)


# --- Insurance Screen ---
class InsuranceScreen(tk.Frame):
     def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self.patients_dict = {} # Map patient names to IDs
        self.selected_insurance_id = None

        # Configure grid weights
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Insurance Records List ---
        list_frame = ttk.LabelFrame(self, text="Insurance Records")
        list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        cols = ("ID", "Patient Name", "Insurance Provider", "Policy No.", "Expiry Date")
        self.insurance_tree = ttk.Treeview(list_frame, columns=cols, show='headings', height=15)
        for col in cols:
            self.insurance_tree.heading(col, text=col)
            self.insurance_tree.column(col, width=120, anchor=tk.W, stretch=tk.NO)
        self.insurance_tree.column("ID", width=50, stretch=tk.NO)
        self.insurance_tree.column("Patient Name", width=150, stretch=tk.YES)
        self.insurance_tree.column("Insurance Provider", width=150, stretch=tk.YES)
        self.insurance_tree.column("Policy No.", width=120, stretch=tk.YES)
        self.insurance_tree.column("Expiry Date", width=100, stretch=tk.NO)
        self.insurance_tree.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.insurance_tree.yview)
        self.insurance_tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.insurance_tree.bind('<<TreeviewSelect>>', self.on_insurance_select)

        # --- Insurance Details Form ---
        form_frame = ttk.LabelFrame(self, text="Insurance Details")
        form_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        form_frame.grid_columnconfigure(1, weight=1) # Make entry column resize

        row_num = 0
        ttk.Label(form_frame, text="Patient:").grid(row=row_num, column=0, padx=5, pady=5, sticky="w")
        self.patient_var = tk.StringVar()
        self.patient_dropdown = ttk.Combobox(form_frame, textvariable=self.patient_var, state="readonly", width=35)
        self.patient_dropdown.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
        row_num += 1

        ttk.Label(form_frame, text="Insurance Provider:").grid(row=row_num, column=0, padx=5, pady=5, sticky="w")
        self.ins_provider_entry = ttk.Entry(form_frame, width=40)
        self.ins_provider_entry.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
        row_num += 1

        ttk.Label(form_frame, text="Policy Number:").grid(row=row_num, column=0, padx=5, pady=5, sticky="w")
        self.policy_no_entry = ttk.Entry(form_frame, width=40)
        self.policy_no_entry.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
        row_num += 1

        ttk.Label(form_frame, text="Expiry Date (YYYY-MM-DD):").grid(row=row_num, column=0, padx=5, pady=5, sticky="w")
        self.expiry_date_entry = ttk.Entry(form_frame, width=40)
        self.expiry_date_entry.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
        row_num += 1

        ttk.Label(form_frame, text="Coverage Details:").grid(row=row_num, column=0, padx=5, pady=5, sticky="nw")
        text_frame = ttk.Frame(form_frame) # Frame for Text and Scrollbar
        text_frame.grid(row=row_num, column=1, padx=5, pady=5, sticky="ew")
        text_frame.grid_columnconfigure(0, weight=1)
        text_frame.grid_rowconfigure(0, weight=1)
        self.coverage_text = tk.Text(text_frame, height=5, width=35, wrap=tk.WORD)
        self.coverage_text.grid(row=0, column=0, sticky="ew")
        cov_scroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.coverage_text.yview)
        self.coverage_text.configure(yscrollcommand=cov_scroll.set)
        cov_scroll.grid(row=0, column=1, sticky="ns")
        row_num += 1

        # --- Buttons ---
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=row_num, column=0, columnspan=2, pady=15, sticky="ew")
        button_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ttk.Button(button_frame, text="Add New", command=self.add_insurance).grid(row=0, column=0, padx=5, sticky="ew")
        ttk.Button(button_frame, text="Update", command=self.update_insurance).grid(row=0, column=1, padx=5, sticky="ew")
        ttk.Button(button_frame, text="Delete", command=self.delete_insurance).grid(row=0, column=2, padx=5, sticky="ew")
        ttk.Button(button_frame, text="Clear", command=self.clear_insurance_form).grid(row=0, column=3, padx=5, sticky="ew")

        # Expiry check button
        expiry_button = ttk.Button(form_frame, text="Check Expiring Soon (30 days)", command=self.check_expiring_insurance)
        expiry_button.grid(row=row_num + 1, column=0, columnspan=2, pady=(0, 10), sticky="ew")

        self.load_patients_for_dropdown()
        self.load_insurance_records()


     def load_patients_for_dropdown(self):
        """Loads patient names and IDs for the Combobox."""
        current_selection = self.patient_var.get()
        self.patients_dict = {}
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        patient_names = []
        try:
            cursor.execute("SELECT id, name FROM patients ORDER BY name")
            patients = cursor.fetchall()
            for patient_id, name in patients:
                display_name = f"{name} (ID: {patient_id})"
                self.patients_dict[display_name] = patient_id
                patient_names.append(display_name)
        except Exception as e:
             messagebox.showerror("Error", f"Failed to load patients for dropdown: {e}")
        finally:
            conn.close()

        self.patient_dropdown['values'] = patient_names
        if current_selection in patient_names:
            self.patient_dropdown.set(current_selection)
        elif patient_names:
            self.patient_dropdown.current(0)
        else:
            self.patient_dropdown.set('')

     def _get_insurance_data_from_form(self):
        """Helper to get and validate data from the insurance form."""
        patient_display_name = self.patient_var.get()
        if not patient_display_name or patient_display_name not in self.patients_dict:
             messagebox.showwarning("Input Error", "Please select a valid patient.")
             return None

        patient_id = self.patients_dict.get(patient_display_name)
        provider = self.ins_provider_entry.get().strip()
        policy_no = self.policy_no_entry.get().strip()
        expiry_date_str = self.expiry_date_entry.get().strip()
        coverage = self.coverage_text.get("1.0", tk.END).strip()

        if not provider:
             messagebox.showwarning("Input Error", "Insurance Provider name is required.")
             self.ins_provider_entry.focus(); return None
        if not policy_no:
            messagebox.showwarning("Input Error", "Policy Number is required.")
            self.policy_no_entry.focus(); return None

        if expiry_date_str and not is_valid_date_format(expiry_date_str):
             messagebox.showwarning("Input Error", "Invalid expiry date format. Use YYYY-MM-DD or leave blank.")
             self.expiry_date_entry.focus(); return None

        return {
            'patient_id': patient_id,
            'provider_name': provider,
            'policy_number': policy_no,
            'expiry_date': expiry_date_str if expiry_date_str else None,
            'coverage_details': coverage
        }

     def load_insurance_records(self):
        """Loads insurance records into the Treeview."""
        selected_item = self.insurance_tree.selection()
        scroll_pos = self.insurance_tree.yview()

        for i in self.insurance_tree.get_children():
            self.insurance_tree.delete(i)

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        # Use a temporary dict mapping ID to Name for display
        temp_id_to_name = {pid: name.split(" (ID:")[0] for name, pid in self.patients_dict.items()}
        try:
            cursor.execute("""
                SELECT id, patient_id, provider_name, policy_number, expiry_date
                FROM insurance
                ORDER BY patient_id, provider_name
            """)
            rows = cursor.fetchall()
            for row in rows:
                ins_id, patient_id, provider, policy, expiry = row
                patient_name = temp_id_to_name.get(patient_id, f"Unknown (ID: {patient_id})")
                display_row = (ins_id, patient_name, provider, policy, expiry if expiry else "N/A")
                self.insurance_tree.insert('', tk.END, values=display_row)
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load insurance records: {e}")
        finally:
            conn.close()

        if selected_item: self.insurance_tree.selection_set(selected_item)
        self.insurance_tree.yview_moveto(scroll_pos[0])

     def on_insurance_select(self, event):
        """Handles selection change in the insurance Treeview."""
        selected_items = self.insurance_tree.selection()
        if not selected_items:
            self.selected_insurance_id = None
            return # Keep form populated maybe? Or clear: self.clear_insurance_form()

        selected_item = selected_items[0]
        selected_id = self.insurance_tree.item(selected_item)['values'][0]
        self.selected_insurance_id = selected_id

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT patient_id, provider_name, policy_number, expiry_date, coverage_details FROM insurance WHERE id = ?", (self.selected_insurance_id,))
            ins_data = cursor.fetchone() # Tuple
            if ins_data:
                patient_id, provider, policy, expiry, coverage = ins_data
                patient_display_name = ""
                for name, p_id in self.patients_dict.items():
                    if p_id == patient_id: patient_display_name = name; break

                self.clear_insurance_form(clear_id=False)
                self.patient_var.set(patient_display_name)
                self.ins_provider_entry.insert(0, provider if provider else "")
                self.policy_no_entry.insert(0, policy if policy else "")
                self.expiry_date_entry.insert(0, expiry if expiry else "")
                self.coverage_text.insert("1.0", coverage if coverage else "")
            else:
                 self.clear_insurance_form()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load insurance details: {e}")
            self.clear_insurance_form()
        finally:
            conn.close()

     def add_insurance(self):
        """Adds a new insurance record."""
        ins_data = self._get_insurance_data_from_form()
        if not ins_data: return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            data_tuple = (
                ins_data['patient_id'], ins_data['provider_name'], ins_data['policy_number'],
                ins_data['expiry_date'], ins_data['coverage_details']
            )
            cursor.execute("""
                INSERT INTO insurance (patient_id, provider_name, policy_number, expiry_date, coverage_details)
                VALUES (?, ?, ?, ?, ?)
            """, data_tuple)
            conn.commit()
            messagebox.showinfo("Success", "Insurance record added successfully.")
            self.load_insurance_records()
            self.clear_insurance_form()
        except Exception as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to add insurance record: {e}")
        finally:
            conn.close()

     def update_insurance(self):
        """Updates the selected insurance record."""
        if self.selected_insurance_id is None:
            messagebox.showwarning("Selection Error", "Please select an insurance record to update.")
            return
        ins_data = self._get_insurance_data_from_form()
        if not ins_data: return

        if not messagebox.askyesno("Confirm Update", f"Update insurance ID {self.selected_insurance_id}?"): return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            data_tuple = (
                ins_data['patient_id'], ins_data['provider_name'], ins_data['policy_number'],
                ins_data['expiry_date'], ins_data['coverage_details'], self.selected_insurance_id
            )
            cursor.execute("""
                UPDATE insurance SET patient_id = ?, provider_name = ?, policy_number = ?,
                                    expiry_date = ?, coverage_details = ?
                WHERE id = ?
            """, data_tuple)
            conn.commit()
            if cursor.rowcount > 0:
                messagebox.showinfo("Success", f"Insurance record ID {self.selected_insurance_id} updated.")
                original_selection = self.insurance_tree.selection()
                self.load_insurance_records()
                if original_selection: self.insurance_tree.selection_set(original_selection)
            else:
                 messagebox.showwarning("Update Warning", f"Record ID {self.selected_insurance_id} not found or no changes.")
        except Exception as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to update insurance record: {e}")
        finally:
            conn.close()

     def delete_insurance(self):
        """Deletes the selected insurance record."""
        if self.selected_insurance_id is None:
            messagebox.showwarning("Selection Error", "Please select an insurance record to delete.")
            return
        if not messagebox.askyesno("Confirm Delete", f"Delete insurance record ID {self.selected_insurance_id}?", icon='warning'):
            return

        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        try:
            cursor.execute("DELETE FROM insurance WHERE id = ?", (self.selected_insurance_id,))
            conn.commit()
            if cursor.rowcount > 0:
                messagebox.showinfo("Success", f"Insurance record ID {self.selected_insurance_id} deleted.")
                self.load_insurance_records()
                self.clear_insurance_form()
            else:
                 messagebox.showwarning("Delete Warning", f"Record ID {self.selected_insurance_id} not found.")
        except Exception as e:
            conn.rollback()
            messagebox.showerror("Database Error", f"Failed to delete insurance record: {e}")
        finally:
            conn.close()

     def clear_insurance_form(self, clear_id=True):
        """Clears the insurance details form."""
        if clear_id: self.selected_insurance_id = None
        self.patient_var.set('')
        self.ins_provider_entry.delete(0, tk.END)
        self.policy_no_entry.delete(0, tk.END)
        self.expiry_date_entry.delete(0, tk.END)
        self.coverage_text.delete("1.0", tk.END)
        if clear_id: self.insurance_tree.selection_remove(self.insurance_tree.selection())

     def check_expiring_insurance(self):
        """Checks for insurance expiring soon (e.g., within 30 days) and sends notifications."""
        days_threshold = 30
        today = datetime.now().date()
        expiring_count = 0
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        # Use temp dict for patient names
        temp_id_to_name = {pid: name.split(" (ID:")[0] for name, pid in self.patients_dict.items()}
        expiring_details = []
        try:
             cursor.execute("SELECT patient_id, provider_name, policy_number, expiry_date FROM insurance WHERE expiry_date IS NOT NULL AND expiry_date != ''")
             records = cursor.fetchall() # List of tuples
             for patient_id, ins_provider, policy_no, expiry_date_str in records:
                  try:
                       expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d').date()
                       days_left = (expiry_date - today).days
                       if 0 <= days_left <= days_threshold: # Expiring within threshold (incl. today)
                            patient_name = temp_id_to_name.get(patient_id, f"Unknown (ID: {patient_id})")
                            send_notification(
                                 recipient_info=f"Patient: {patient_name}",
                                 subject="Insurance Expiry Reminder",
                                 body=f"Policy '{policy_no}' with {ins_provider} expires on {expiry_date_str} ({days_left} days left)."
                            )
                            expiring_details.append(f"- {patient_name}: Policy {policy_no} expires {expiry_date_str} ({days_left} days)")
                            expiring_count += 1
                       elif days_left < 0: # Already expired
                            patient_name = temp_id_to_name.get(patient_id, f"Unknown (ID: {patient_id})")
                            send_notification(
                                 recipient_info=f"Patient: {patient_name}",
                                 subject="Insurance Policy Expired",
                                 body=f"Policy '{policy_no}' with {ins_provider} expired on {expiry_date_str}."
                            )
                            expiring_details.append(f"- {patient_name}: Policy {policy_no} EXPIRED {expiry_date_str}")
                            expiring_count += 1 # Count expired too for summary
                  except ValueError: print(f"Skipping invalid date format for policy {policy_no}: {expiry_date_str}")
                  except Exception as inner_e: print(f"Error processing expiry for policy {policy_no}: {inner_e}")

             if expiring_count > 0:
                  details_str = "\n".join(expiring_details)
                  if len(details_str) > 600: details_str = details_str[:600] + "\n..." # Truncate for messagebox
                  messagebox.showinfo("Expiry Check Complete", f"{expiring_count} insurance policies expiring soon or expired.\nNotifications sent (check console).\n\nDetails:\n{details_str}")
             else:
                  messagebox.showinfo("Expiry Check Complete", "No insurance policies found expiring within the next 30 days or already expired.")

        except Exception as e:
             messagebox.showerror("Database Error", f"Failed to check expiring insurance: {e}")
        finally:
             conn.close()


# --- Diagnostic Tools Screen ---
class DiagnosticToolsScreen(tk.Frame):
    # ... (DiagnosticToolsScreen code remains the same as the previous single-file version) ...
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller

        container = ttk.Frame(self, padding="20 20 20 20")
        container.pack(expand=True, fill=tk.BOTH, anchor="n") # Pack at top

        # --- BMI Calculator ---
        bmi_frame = ttk.LabelFrame(container, text="BMI Calculator", padding="10 10 10 10")
        bmi_frame.pack(pady=10, padx=10, fill="x", anchor="n") # Anchor north

        ttk.Label(bmi_frame, text="Height (cm):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.height_entry = ttk.Entry(bmi_frame, width=10)
        self.height_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(bmi_frame, text="Weight (kg):").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.weight_entry = ttk.Entry(bmi_frame, width=10)
        self.weight_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Button(bmi_frame, text="Calculate BMI", command=self.calculate_bmi).grid(row=2, column=0, columnspan=2, pady=10)

        self.bmi_result_label = ttk.Label(bmi_frame, text="BMI Result: ", font=("Arial", 11))
        self.bmi_result_label.grid(row=3, column=0, columnspan=2, pady=5, sticky="w")

        # --- Placeholder for Blood Pressure Tracker ---
        bp_frame = ttk.LabelFrame(container, text="Blood Pressure Tracker (Placeholder)", padding="10 10 10 10")
        bp_frame.pack(pady=10, padx=10, fill="x", anchor="n")
        # ... (BP widgets - not functional) ...

        # --- Placeholder for Calorie Counter ---
        cal_frame = ttk.LabelFrame(container, text="Calorie Counter (Placeholder)", padding="10 10 10 10")
        cal_frame.pack(pady=10, padx=10, fill="x", anchor="n")
        # ... (Calorie widgets - not functional) ...

    def calculate_bmi(self):
        """Calculates and displays the Body Mass Index."""
        try:
            height_str = self.height_entry.get()
            weight_str = self.weight_entry.get()
            if not height_str or not weight_str:
                 messagebox.showerror("Input Error", "Please enter both height and weight.")
                 return

            height_cm = float(height_str)
            weight_kg = float(weight_str)

            if height_cm <= 0 or weight_kg <= 0:
                messagebox.showerror("Input Error", "Height and Weight must be positive numbers.")
                return

            height_m = height_cm / 100
            bmi = weight_kg / (height_m ** 2)

            # Determine category
            if bmi < 18.5: category = "Underweight"
            elif 18.5 <= bmi < 24.9: category = "Normal weight"
            elif 25 <= bmi < 29.9: category = "Overweight"
            else: category = "Obesity"

            result_text = f"BMI Result: {bmi:.2f} ({category})"
            self.bmi_result_label.config(text=result_text)

        except ValueError:
            messagebox.showerror("Input Error", "Please enter valid numbers for height and weight.")
            self.bmi_result_label.config(text="BMI Result: Error")
        except Exception as e:
             messagebox.showerror("Calculation Error", f"An error occurred: {e}")
             self.bmi_result_label.config(text="BMI Result: Error")


# --- Main Execution ---
if __name__ == "__main__":
    app = HealthCareApp()
    app.mainloop()