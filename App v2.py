# --- START OF FILE App v1.py ---

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import sqlite3
from datetime import datetime, timedelta, time
import logging
import bcrypt # For password hashing
import os # To ensure log directory exists
from tkcalendar import DateEntry
# from twilio.rest import Client
# from twilio.base.exceptions import TwilioRestException
# import configparser # For reading credentials from a file


# --- Logging Setup ---
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "healthcare_app.log")

# Ensure log directory exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configure logging
logging.basicConfig(
    # ---> CHANGE THIS LINE <---
    level=logging.DEBUG, # Set to DEBUG to see detailed logs
    format='%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(message)s', # Added %(name)s
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logging.info("Application starting up.")

# --- Database Setup ---

DATABASE_NAME = 'healthcare.db'

def initialize_database():
    """Creates the database and tables if they don't exist."""
    logging.info("Initializing database...")
    conn = None
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON") # Ensure foreign keys are enforced

        # Users Table (for login) - Password stored as BLOB for hash
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password BLOB NOT NULL, -- Store hash as bytes (NEVER PLAINTEXT)
                role TEXT NOT NULL CHECK(role IN ('Patient', 'Staff', 'Admin'))
            )
        ''')
        logging.debug("Users table checked/created.")

        # Patients Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Patients (
                patient_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE, -- Link to Users table for patient login
                name TEXT NOT NULL,
                date_of_birth TEXT,
                gender TEXT,
                contact_number TEXT,
                address TEXT,
                medical_history TEXT,
                surgery_history TEXT,
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE SET NULL
            )
        ''')
        logging.debug("Patients table checked/created.")

        # Staff Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Staff (
                staff_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE, -- Link to Users table for staff login
                name TEXT NOT NULL,
                speciality TEXT,
                contact_info TEXT,
                FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE SET NULL
            )
        ''')
        logging.debug("Staff table checked/created.")

        # Treatments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Treatments (
                treatment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                recommending_staff_id INTEGER,
                treatment_date TEXT,
                medications TEXT,
                details TEXT,
                FOREIGN KEY (patient_id) REFERENCES Patients(patient_id) ON DELETE CASCADE,
                FOREIGN KEY (recommending_staff_id) REFERENCES Staff(staff_id) ON DELETE SET NULL
            )
        ''')
        logging.debug("Treatments table checked/created.")

        # Appointments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Appointments (
                appointment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                staff_id INTEGER NOT NULL, -- Specialist
                appointment_datetime TEXT NOT NULL,
                reason TEXT,
                status TEXT CHECK(status IN ('Scheduled', 'Completed', 'Cancelled', 'No Show')),
                details TEXT,
                FOREIGN KEY (patient_id) REFERENCES Patients(patient_id) ON DELETE CASCADE,
                FOREIGN KEY (staff_id) REFERENCES Staff(staff_id) ON DELETE CASCADE
            )
        ''')
        logging.debug("Appointments table checked/created.")

        # Insurance Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Insurance (
                insurance_id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL UNIQUE,
                provider_name TEXT,
                policy_number TEXT,
                expiry_date TEXT,
                coverage_details TEXT,
                FOREIGN KEY (patient_id) REFERENCES Patients(patient_id) ON DELETE CASCADE
            )
        ''')
        logging.debug("Insurance table checked/created.")

        # --- Add Default Admin User (if none exists) ---
        cursor.execute("SELECT 1 FROM Users WHERE username = 'admin'")
        if cursor.fetchone() is None:
            logging.info("Default admin user not found. Creating...")
            try:
                # Hash the default password
                default_password = 'admin123'
                hashed_password = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt())
                cursor.execute("INSERT INTO Users (username, password, role) VALUES (?, ?, ?)",
                               ('admin', hashed_password, 'Admin'))
                logging.info("Default admin user ('admin'/'admin123') created successfully.")
            except Exception as e:
                logging.error(f"Failed to create default admin user: {e}")

        conn.commit()
        logging.info(f"Database '{DATABASE_NAME}' initialized successfully.")

    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
        messagebox.showerror("Database Error", f"An error occurred during database setup: {e}")
    finally:
        if conn:
            conn.close()
            logging.debug("Database connection closed.")

# --- Utility Functions ---
def hash_password(password):
    """Hashes a given password using bcrypt."""
    logging.debug("Hashing password.")
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(plain_password, hashed_password):
    """Checks if a plain text password matches a stored bcrypt hash."""
    logging.debug("Checking password hash.")
    if not isinstance(hashed_password, bytes):
        logging.error("Hashed password provided is not bytes.")
        return False # Cannot compare if hash is not bytes
    try:
        # Use bcrypt's checkpw function for secure comparison
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
    except ValueError: # Handle cases where the stored hash might be invalid
        logging.warning("Invalid hash format encountered during password check.")
        return False
    except Exception as e:
        logging.error(f"Error during password check: {e}")
        return False

# --- Database Interaction Functions ---

# Added error tracking attribute for specific checks
class ExecuteQueryState:
    last_error = None

def execute_query(query, params=(), fetch_one=False, fetch_all=False, commit=False):
    """Executes a given SQL query and returns results if needed."""
    conn = None
    ExecuteQueryState.last_error = None
    logging.debug(f"Executing query: {query} with params: {params}")
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)

        if commit:
            conn.commit()
            # *** FIX: Get lastrowid *specifically* for INSERT, otherwise check success ***
            # Determine if it's likely an INSERT statement
            is_insert = query.strip().upper().startswith("INSERT")
            last_id = cursor.lastrowid if is_insert else None

            rows_affected = cursor.rowcount # Get row count (might be useful)

            if is_insert:
                 log_msg = f"INSERT query committed successfully. Last row ID: {last_id}"
                 logging.info(log_msg)
                 # Return the actual ID for INSERT
                 return last_id
            else:
                 # For UPDATE/DELETE, commit success is the key indicator
                 log_msg = f"UPDATE/DELETE query committed successfully."
                 if rows_affected >= 0:
                     log_msg += f" Rows affected: {rows_affected}"
                 logging.info(log_msg)
                 # Return True for successful UPDATE/DELETE commit
                 return True

        if fetch_one:
            result = cursor.fetchone()
            logging.debug(f"Query fetched one row: {'Data found' if result else 'No data'}")
            return result
        elif fetch_all:
            results = cursor.fetchall()
            logging.debug(f"Query fetched {len(results)} rows.")
            return results
        else:
            logging.debug("Query executed successfully (no fetch/commit requested by caller).")
            return True # Indicate success

    except sqlite3.Error as e:
        ExecuteQueryState.last_error = e
        logging.error(f"Database Query Error: {e}\nQuery: {query}\nParams: {params}")
        if conn and commit:
            try: conn.rollback(); logging.warning("Transaction rolled back.")
            except Exception as rb_e: logging.error(f"Failed to rollback: {rb_e}")
        return None # Indicate failure
    finally:
        if conn:
            conn.close()
            logging.debug("Database connection closed after query execution.")


def verify_login(username, password):
    """Verifies login credentials against the Users table using hashed passwords."""
    logging.info(f"Attempting login for user: {username}")
    query = "SELECT user_id, password, role FROM Users WHERE username = ?"
    user_data = execute_query(query, (username,), fetch_one=True)

    if user_data:
        stored_hash = user_data['password']
        # Check if stored_hash exists and is of type bytes
        if stored_hash and isinstance(stored_hash, bytes):
            if check_password(password, stored_hash):
                logging.info(f"Login successful for user: {username}, Role: {user_data['role']}")
                return {'user_id': user_data['user_id'], 'role': user_data['role']}
            else:
                logging.warning(f"Login failed for user: {username} - Incorrect password.")
                return None
        else:
            # This case indicates a problem with data integrity (missing/invalid hash)
            logging.error(f"Login failed for user: {username} - Stored password hash is invalid or missing in the database.")
            return None
    else:
        logging.warning(f"Login failed for user: {username} - User not found.")
        return None


def get_patient_details_by_user_id(user_id):
    """Fetches patient details linked to a user ID."""
    logging.debug(f"Fetching patient details for user_id: {user_id}")
    query = "SELECT * FROM Patients WHERE user_id = ?"
    return execute_query(query, (user_id,), fetch_one=True)

def get_staff_details_by_user_id(user_id):
    """Fetches staff details linked to a user ID."""
    logging.debug(f"Fetching staff details for user_id: {user_id}")
    query = "SELECT * FROM Staff WHERE user_id = ?"
    return execute_query(query, (user_id,), fetch_one=True)

def get_all_patients():
    """Fetches all patient records (basic info)."""
    logging.debug("Fetching all patient records.")
    query = "SELECT patient_id, name, date_of_birth, gender, contact_number FROM Patients ORDER BY name"
    return execute_query(query, fetch_all=True)

def get_all_staff():
    """Fetches all staff records including linked username."""
    logging.debug("Fetching all staff records with linked username.")
    # Joins with Users table to get username associated with staff's user_id
    query = """
        SELECT s.staff_id, s.name, s.speciality, s.contact_info, s.user_id, u.username
        FROM Staff s
        LEFT JOIN Users u ON s.user_id = u.user_id
        ORDER BY s.name
        """
    return execute_query(query, fetch_all=True)


def get_all_users():
    """Fetches all user login records with linked profile info (name and ID)."""
    logging.debug("Fetching all user records with linked profiles.")
    # This query correctly identifies the linked profile name and ID (patient_id or staff_id)
    query = """
        SELECT
            u.user_id,
            u.username,
            u.role,
            CASE
                WHEN u.role = 'Patient' THEN p.name
                WHEN u.role = 'Staff' THEN s.name
                ELSE NULL -- Or 'N/A' if preferred for display
            END AS linked_name,
            CASE
                WHEN u.role = 'Patient' THEN p.patient_id
                WHEN u.role = 'Staff' THEN s.staff_id
                ELSE NULL -- Or 'N/A'
            END AS linked_profile_id
        FROM Users u
        LEFT JOIN Patients p ON u.user_id = p.user_id AND u.role = 'Patient'
        LEFT JOIN Staff s ON u.user_id = s.user_id AND u.role = 'Staff'
        ORDER BY u.role, u.username
    """
    return execute_query(query, fetch_all=True)


def check_username_exists(username):
    """Checks if a username already exists in the Users table."""
    logging.debug(f"Checking if username exists: {username}")
    query = "SELECT 1 FROM Users WHERE username = ?"
    result = execute_query(query, (username,), fetch_one=True)
    exists = result is not None
    logging.debug(f"Username '{username}' exists: {exists}")
    return exists

def get_all_patients_for_selection():
    """Fetches patient ID and name for dropdown/selection lists."""
    logging.debug("Fetching all patients (ID, Name) for selection.")
    query = "SELECT patient_id, name FROM Patients ORDER BY name"
    return execute_query(query, fetch_all=True)

def get_all_staff_for_selection():
    """Fetches staff ID and name for dropdown/selection lists."""
    logging.debug("Fetching all staff (ID, Name) for selection.")
    query = "SELECT staff_id, name FROM Staff ORDER BY name"
    return execute_query(query, fetch_all=True)

def get_appointments_for_view(staff_id=None, patient_id=None):
    """Fetches appointments, optionally filtered by staff or patient."""
    # Staff users likely see their own, Admins see all? Start with staff perspective.
    logging.debug(f"Fetching appointments for view (staff_id={staff_id}, patient_id={patient_id})")
    base_query = """
        SELECT a.appointment_id, p.name AS patient_name, s.name AS staff_name,
               a.appointment_datetime, a.reason, a.status, a.patient_id, a.staff_id
        FROM Appointments a
        JOIN Patients p ON a.patient_id = p.patient_id
        JOIN Staff s ON a.staff_id = s.staff_id
    """
    filters = []
    params = []
    if staff_id is not None:
        filters.append("a.staff_id = ?")
        params.append(staff_id)
    if patient_id is not None:
        filters.append("a.patient_id = ?")
        params.append(patient_id)

    if filters:
        base_query += " WHERE " + " AND ".join(filters)

    base_query += " ORDER BY a.appointment_datetime DESC"
    return execute_query(base_query, tuple(params), fetch_all=True)


def get_treatments_for_view(staff_id=None, patient_id=None):
    """Fetches treatments, optionally filtered by staff or patient."""
    logging.debug(f"Fetching treatments for view (staff_id={staff_id}, patient_id={patient_id})")
    base_query = """
        SELECT t.treatment_id, p.name AS patient_name, t.treatment_date,
               t.medications, t.details, t.patient_id, t.recommending_staff_id
        FROM Treatments t
        JOIN Patients p ON t.patient_id = p.patient_id
        LEFT JOIN Staff s ON t.recommending_staff_id = s.staff_id -- Allow for NULL staff
    """
    filters = []
    params = []
    if staff_id is not None: # Filter by recommending staff
        filters.append("t.recommending_staff_id = ?")
        params.append(staff_id)
    if patient_id is not None:
        filters.append("t.patient_id = ?")
        params.append(patient_id)

    if filters:
        base_query += " WHERE " + " AND ".join(filters)

    base_query += " ORDER BY t.treatment_date DESC, t.treatment_id DESC"
    return execute_query(base_query, tuple(params), fetch_all=True)

# --- Function to get full appointment details by ID ---
def get_appointment_details_by_id(appointment_id):
    logging.debug(f"Fetching full details for appointment_id: {appointment_id}")
    query = """
        SELECT a.*, p.name AS patient_name, s.name AS staff_name
        FROM Appointments a
        JOIN Patients p ON a.patient_id = p.patient_id
        JOIN Staff s ON a.staff_id = s.staff_id
        WHERE a.appointment_id = ?
    """
    return execute_query(query, (appointment_id,), fetch_one=True)

# --- Function to get full treatment details by ID ---
def get_treatment_details_by_id(treatment_id):
    logging.debug(f"Fetching full details for treatment_id: {treatment_id}")
    query = """
        SELECT t.*, p.name AS patient_name
        FROM Treatments t
        JOIN Patients p ON t.patient_id = p.patient_id
        WHERE t.treatment_id = ?
    """
    return execute_query(query, (treatment_id,), fetch_one=True)


# --- Simulated SMS Notification Function ---

def send_sms_reminder(patient_phone_number, patient_name, appointment_datetime_str, staff_name):
    """
    Simulates sending an SMS reminder. Logs the action and optionally shows a message box.
    Does NOT actually send an SMS.
    """
    if not patient_phone_number:
        # Log that we can't send because number is missing
        logging.warning(f"Simulated SMS not 'sent': No phone number provided for patient {patient_name}.")
        # Return False to indicate it wasn't 'sent' due to missing info
        # Or return True if you just want to log it and not fail the booking? Let's return False.
        return False

    try:
        # Format the appointment time for the message/log (same as before)
        try:
            appt_dt = datetime.strptime(appointment_datetime_str, '%Y-%m-%d %H:%M:%S')
            friendly_time = appt_dt.strftime('%I:%M %p on %A, %B %d, %Y')
        except ValueError:
            friendly_time = appointment_datetime_str # Fallback

        message_body = (f"Hi {patient_name}, reminder: Your appointment with {staff_name} "
                        f"is scheduled for {friendly_time}. "
                        f"- Healthcare Clinic")

        # --- Simulation Actions ---
        # 1. Log the simulated action
        log_message = f"SIMULATED SMS: To={patient_phone_number}, Body='{message_body}'"
        logging.info(log_message)

        # 2. (Optional) Show a confirmation message box
        # You can comment this out if you only want logging
        confirmation_title = "Simulated SMS Reminder"
        confirmation_message = (f"Reminder for {patient_name} 'sent' successfully (Simulated).\n\n"
                                f"To: {patient_phone_number}\n"
                                f"Time: {friendly_time}")
        messagebox.showinfo(confirmation_title, confirmation_message)
        # --- End Simulation Actions ---

        return True # Indicate simulated success

    except Exception as e:
        # Catch errors during formatting or logging (should be rare)
        logging.exception(f"Error during SMS simulation for patient {patient_name}: {e}")
        messagebox.showerror("Simulation Error", f"An unexpected error occurred during SMS simulation:\n{e}")
        return False # Indicate simulation failure



# --- GUI Application ---

class HealthcareApp(tk.Tk):
    """Main application class."""
    def __init__(self):
        super().__init__()
        logging.info("Initializing GUI application.")
        self.title("Healthcare Clinic Management")
        self.geometry("1500x1750") # Increased size further for better viewing

        self.eval('tk::PlaceWindow . center')

        self.style = ttk.Style(self)
        self.style.theme_use('clam') # Or 'alt', 'default', 'vista' etc.

        # Define Styles
        self.style.configure('TLabel', font=('Helvetica', 12))
        self.style.configure('TButton', font=('Helvetica', 12), padding=6)
        self.style.configure('TEntry', font=('Helvetica', 12), padding=5)
        self.style.configure('Treeview.Heading', font=('Helvetica', 12, 'bold'))
        self.style.configure('Treeview', font=('Helvetica', 11), rowheight=25)
        # Custom style for the main login button
        self.style.configure('Accent.TButton', font=('Helvetica', 12, 'bold'), foreground='white', background='#007bff')
        self.style.map('Accent.TButton', background=[('active', '#0056b3')]) # Hover effect
        # Style for Read-only Text widgets in Patient View
        self.style.configure('ReadOnly.TText', relief=tk.FLAT, background=self.cget('bg'))

        self._current_frame = None
        self._user_info = None

        self.show_login_frame()

        # Handle window close event
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def switch_frame(self, frame_class, *args):
        """Destroys current frame and shows the new one."""
        frame_name = frame_class.__name__
        logging.info(f"Switching frame to: {frame_name}")
        if self._current_frame:
            self._current_frame.destroy()
            logging.debug("Destroyed previous frame.")

        # Create and pack the new frame
        self._current_frame = frame_class(self, *args)
        self._current_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        logging.debug(f"Packed new frame: {frame_name}")

    def show_login_frame(self):
        """Displays the login screen."""
        logging.info("Displaying Login Frame.")
        self._user_info = None # Clear user info on logout/return to login
        self.title("Healthcare Clinic Management - Login")
        self.switch_frame(LoginFrame)

    def login_successful(self, user_info):
        """Handles successful login and navigates to the appropriate frame."""
        self._user_info = user_info
        role = self._user_info['role']
        user_id = self._user_info['user_id']
        logging.info(f"Login successful. User ID: {user_id}, Role: {role}. Navigating to role frame.")
        self.title(f"Healthcare Clinic Management - {role} Panel") # Update title

        try:
            if role == 'Patient':
                patient_data = get_patient_details_by_user_id(user_id)
                if patient_data:
                    self.switch_frame(PatientFrame, patient_data)
                else:
                    # Handle case where user exists but patient profile doesn't (data inconsistency)
                    logging.error(f"Login Error: Patient record not found for user_id: {user_id}, though user login exists.")
                    messagebox.showerror("Login Error", "Your login is valid, but your patient record could not be found.\nPlease contact administration.")
                    self.show_login_frame() # Return to login
            elif role == 'Staff':
                staff_data = get_staff_details_by_user_id(user_id)
                if staff_data:
                     self.switch_frame(StaffFrame, staff_data)
                else:
                    # Handle case where user exists but staff profile doesn't
                    logging.error(f"Login Error: Staff record not found for user_id: {user_id}, though user login exists.")
                    messagebox.showerror("Login Error", "Your login is valid, but your staff record could not be found.\nPlease contact administration.")
                    self.show_login_frame() # Return to login
            elif role == 'Admin':
                self.switch_frame(AdminFrame)
            else:
                # Should not happen due to DB constraints, but good practice to check
                logging.error(f"Unknown user role encountered after login: {role} for user_id: {user_id}")
                messagebox.showerror("Login Error", f"Invalid user role ('{role}') detected. Please contact administration.")
                self.show_login_frame()
        except Exception as e:
            logging.exception(f"Error switching frame after login for role {role}, user_id {user_id}: {e}")
            messagebox.showerror("Application Error", f"An error occurred while loading your view: {e}")
            self.show_login_frame() # Attempt to return to login safely


    def logout(self):
        """Logs out the current user and returns to the login screen."""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            user_id = self._user_info['user_id'] if self._user_info else 'Unknown'
            role = self._user_info['role'] if self._user_info else 'Unknown'
            logging.info(f"User logged out: User ID {user_id}, Role {role}")
            self.show_login_frame()
        else:
            logging.debug("Logout cancelled by user.")

    def on_closing(self):
        """Handles the event when the user closes the window."""
        logging.info("Application window closing.")
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            logging.info("Application shutting down.")
            self.destroy() # Close the Tkinter application
        else:
            logging.debug("Quit cancelled by user.")

# --- Login Frame ---
# (No changes needed from previous version - it's functional)
class LoginFrame(ttk.Frame):
    """GUI Frame for user login."""
    def __init__(self, master):
        super().__init__(master, padding="20 20 20 20")
        self.master = master
        logging.debug("Initializing LoginFrame.")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1) # Spacer row above
        self.rowconfigure(4, weight=1) # Spacer row below

        # Container to center login elements vertically and horizontally
        center_container = ttk.Frame(self)
        center_container.grid(row=1, column=0, rowspan=3, sticky="") # Centered

        lbl_title = ttk.Label(center_container, text="Login", font=("Helvetica", 24, "bold")) # Larger title
        lbl_title.grid(row=0, column=0, columnspan=2, pady=(0, 30))

        lbl_username = ttk.Label(center_container, text="Username:")
        lbl_username.grid(row=1, column=0, padx=10, pady=10, sticky="e") # Align labels right
        self.entry_username = ttk.Entry(center_container, width=35, font=('Helvetica', 12)) # Consistent font
        self.entry_username.grid(row=1, column=1, padx=10, pady=10)
        self.entry_username.focus()

        lbl_password = ttk.Label(center_container, text="Password:")
        lbl_password.grid(row=2, column=0, padx=10, pady=10, sticky="e") # Align labels right
        self.entry_password = ttk.Entry(center_container, width=35, show="*", font=('Helvetica', 12)) # Consistent font
        self.entry_password.grid(row=2, column=1, padx=10, pady=10)
        self.entry_password.bind("<Return>", self.attempt_login) # Bind Enter key

        btn_login = ttk.Button(center_container, text="Login", command=self.attempt_login, style='Accent.TButton', width=15) # Button width
        btn_login.grid(row=3, column=0, columnspan=2, pady=(30, 0)) # More space before button

    def attempt_login(self, event=None): # Added event=None for Enter key binding
        """Attempts to log the user in."""
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not username or not password:
            logging.warning("Login attempt failed: Username or password empty.")
            messagebox.showwarning("Login Failed", "Please enter both username and password.")
            return

        user_info = verify_login(username, password)

        if user_info:
            # Successful login, master handles navigation
            self.master.login_successful(user_info)
        else:
            # verify_login logs the specific failure reason (not found vs wrong password)
            messagebox.showerror("Login Failed", "Invalid username or password.")
            self.entry_password.delete(0, tk.END) # Clear only password on failure

# --- Patient Frame ---
# (No changes needed from previous version - it's functional)
class PatientFrame(ttk.Frame):
    """GUI Frame for logged-in Patients."""
    def __init__(self, master, patient_data):
        super().__init__(master, padding="10")
        self.master = master
        self.patient_data = patient_data
        self.patient_id = self.patient_data['patient_id']
        logging.info(f"Initializing PatientFrame for patient_id: {self.patient_id}")

        self.create_widgets()
        self.load_patient_info()
        self.load_appointments()
        self.load_treatments()

    def create_widgets(self):
        """Creates the widgets for the patient view."""
        logging.debug(f"Creating widgets for PatientFrame (patient_id: {self.patient_id})")
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane: Patient Info ---
        info_frame = ttk.LabelFrame(main_pane, text="Your Information (Read-Only)", padding="15")
        main_pane.add(info_frame, weight=1)

        labels = ["Patient ID:", "Name:", "Date of Birth:", "Gender:", "Contact Number:", "Address:", "Medical History:", "Surgery History:"]
        self.info_vars = {}

        for i, label_text in enumerate(labels):
            lbl = ttk.Label(info_frame, text=label_text)
            lbl.grid(row=i, column=0, padx=5, pady=8, sticky="nw" if "History" in label_text or "Address" in label_text else "w")
            # Use a Text widget for multiline fields but make it look like a label
            if "History" in label_text or "Address" in label_text:
                text_widget = tk.Text(info_frame, height=5 if "History" in label_text else 3, width=40,
                                     wrap="word", font=('Helvetica', 11),
                                     relief=tk.FLAT, # Make border flat
                                     borderwidth=0,  # Remove border width
                                     # REMOVED: background=info_frame.cget('bg'), # <<< This caused the error
                                     state=tk.DISABLED, # Make read-only
                                     cursor="") # Remove the text cursor
                text_widget.grid(row=i, column=1, padx=5, pady=8, sticky="ew")
                self.info_vars[label_text] = text_widget # Store widget directly
            else:
                 # Use a standard label for single-line info
                 var = tk.StringVar(info_frame)
                 self.info_vars[label_text] = var
                 val = ttk.Label(info_frame, textvariable=var, wraplength=350, anchor="w") # Allow wrapping, align left
                 val.grid(row=i, column=1, padx=5, pady=8, sticky="ew")

        info_frame.columnconfigure(1, weight=1) # Allow value column to expand

        # --- Right Pane: Appointments and Treatments ---
        # ... (rest of the function remains unchanged from the previous version with HScrollbars) ...
        right_pane = ttk.Frame(main_pane, padding="10")
        main_pane.add(right_pane, weight=2)
        right_pane.rowconfigure(1, weight=1) # Appointment treeview row expands
        right_pane.rowconfigure(4, weight=1) # Treatment treeview row expands
        right_pane.columnconfigure(0, weight=1) # Treeview column expands

        # Appointments Section
        lbl_app = ttk.Label(right_pane, text="Your Appointments", font=("Helvetica", 14, "bold"))
        lbl_app.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

        # --- Treeview Frame for Appointments (to hold scrollbars) ---
        app_tree_frame = ttk.Frame(right_pane)
        app_tree_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        app_tree_frame.rowconfigure(0, weight=1)
        app_tree_frame.columnconfigure(0, weight=1)

        app_cols = ('appt_id', 'specialist', 'datetime', 'reason', 'status')
        self.tv_appointments = ttk.Treeview(app_tree_frame, columns=app_cols, show='headings', height=10)
        self.tv_appointments.heading('appt_id', text='ID')
        self.tv_appointments.heading('specialist', text='Specialist')
        self.tv_appointments.heading('datetime', text='Date & Time')
        self.tv_appointments.heading('reason', text='Reason')
        self.tv_appointments.heading('status', text='Status')
        self.tv_appointments.column('appt_id', width=60, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_appointments.column('specialist', width=180)
        self.tv_appointments.column('datetime', width=160)
        self.tv_appointments.column('reason', width=300)
        self.tv_appointments.column('status', width=100, anchor=tk.CENTER)
        self.tv_appointments.grid(row=0, column=0, sticky="nsew")

        # Scrollbars for Appointments
        app_vsb = ttk.Scrollbar(app_tree_frame, orient="vertical", command=self.tv_appointments.yview)
        app_hsb = ttk.Scrollbar(app_tree_frame, orient="horizontal", command=self.tv_appointments.xview)
        self.tv_appointments.configure(yscrollcommand=app_vsb.set, xscrollcommand=app_hsb.set)
        app_vsb.grid(row=0, column=1, sticky="ns")
        app_hsb.grid(row=1, column=0, sticky="ew")

        # Treatments Section Separator
        ttk.Separator(right_pane, orient=tk.HORIZONTAL).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(20, 15))

        lbl_treat = ttk.Label(right_pane, text="Your Treatments", font=("Helvetica", 14, "bold"))
        lbl_treat.grid(row=3, column=0, columnspan=2, pady=(0, 10), sticky="w")

        # --- Treeview Frame for Treatments ---
        treat_tree_frame = ttk.Frame(right_pane)
        treat_tree_frame.grid(row=4, column=0, columnspan=2, sticky="nsew")
        treat_tree_frame.rowconfigure(0, weight=1)
        treat_tree_frame.columnconfigure(0, weight=1)

        treat_cols = ('treat_id', 'staff', 'date', 'meds', 'details')
        self.tv_treatments = ttk.Treeview(treat_tree_frame, columns=treat_cols, show='headings', height=10)
        self.tv_treatments.heading('treat_id', text='ID')
        self.tv_treatments.heading('staff', text='Staff')
        self.tv_treatments.heading('date', text='Date')
        self.tv_treatments.heading('meds', text='Medications')
        self.tv_treatments.heading('details', text='Details')
        self.tv_treatments.column('treat_id', width=60, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_treatments.column('staff', width=180)
        self.tv_treatments.column('date', width=120)
        self.tv_treatments.column('meds', width=250)
        self.tv_treatments.column('details', width=350)
        self.tv_treatments.grid(row=0, column=0, sticky="nsew")

        # Scrollbars for Treatments
        treat_vsb = ttk.Scrollbar(treat_tree_frame, orient="vertical", command=self.tv_treatments.yview)
        treat_hsb = ttk.Scrollbar(treat_tree_frame, orient="horizontal", command=self.tv_treatments.xview)
        self.tv_treatments.configure(yscrollcommand=treat_vsb.set, xscrollcommand=treat_hsb.set)
        treat_vsb.grid(row=0, column=1, sticky="ns")
        treat_hsb.grid(row=1, column=0, sticky="ew")

        bottom_button_frame = ttk.Frame(self)
        bottom_button_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(15, 5))

        # Book Appointment Button
        btn_book = ttk.Button(bottom_button_frame, text="Book New Appointment", command=self.show_booking_view)
        btn_book.pack(side=tk.LEFT, padx=10, pady=5)

        # Logout Button (bottom centered)
        btn_logout_frame = ttk.Frame(self)
        btn_logout_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(25, 0))
        btn_logout = ttk.Button(btn_logout_frame, text="Logout", command=self.master.logout, width=12)
        btn_logout.pack(pady=5)

    def show_booking_view(self):
        """Opens the appointment booking view in a new Toplevel window."""
        logging.debug(f"Opening booking window for patient ID: {self.patient_id}")
        # self.master is the HealthcareApp instance (which acts as the app_controller)
        # self.patient_data contains the necessary info about the current patient
        try:
            # Pass self.master as BOTH the master for the Toplevel window
            # AND as the app_controller argument.
            booking_window = PatientBookingView(
                master=self.master,                 # Master for the Toplevel window
                app_controller=self.master,         # Pass HealthcareApp as the controller
                patient_data=self.patient_data      # Pass the patient's data
            )
            # Optional: center the new window relative to the main window
            # booking_window.geometry(f"+{self.master.winfo_x()+50}+{self.master.winfo_y()+50}")
        except Exception as e:
            logging.exception(f"Error creating PatientBookingView: {e}")
            messagebox.showerror("Error", f"Could not open booking window: {e}")


    def load_patient_info(self):
        """Populates the information labels/text widgets."""
        logging.debug(f"Loading patient info for patient_id: {self.patient_id}")
        if self.patient_data: # self.patient_data is an sqlite3.Row object here
            try:
                # Set single-line labels via StringVars using dictionary access
                self.info_vars["Patient ID:"].set(self.patient_data['patient_id'])
                self.info_vars["Name:"].set(self.patient_data['name'])
                self.info_vars["Date of Birth:"].set(self.patient_data['date_of_birth'] or 'N/A')
                self.info_vars["Gender:"].set(self.patient_data['gender'] or 'N/A')
                self.info_vars["Contact Number:"].set(self.patient_data['contact_number'] or 'N/A')

                # Update multi-line Text widgets
                for key_label in ["Address:", "Medical History:", "Surgery History:"]:
                    widget = self.info_vars[key_label]
                    # Convert label "Medical History:" to column name "medical_history"
                    column_name = key_label.replace(":", "").lower().replace(" ", "_")

                    # Access using dictionary style []
                    # Use a default value if the column might be None in the DB
                    content = self.patient_data[column_name] if self.patient_data[column_name] is not None else 'N/A'

                    widget.config(state=tk.NORMAL) # Enable writing
                    widget.delete('1.0', tk.END)    # Clear existing content
                    widget.insert('1.0', content)   # Insert new content
                    widget.config(state=tk.DISABLED)# Disable again for read-only

            except KeyError as e:
                # This might happen if the database column name doesn't match expected
                logging.error(f"KeyError accessing patient_data for patient_id {self.patient_id}: Missing key {e}")
                messagebox.showerror("Data Error", f"Failed to load some patient details (Missing key: {e}).")
                # Optionally clear fields or show error message in UI
            except Exception as e:
                # Catch other potential errors during UI update
                logging.exception(f"Error populating patient info UI for patient_id {self.patient_id}: {e}")
                messagebox.showerror("UI Error", f"An error occurred displaying patient information: {e}")

        else:
            # Handle case where patient_data is missing entirely
            logging.warning(f"No patient data available (patient_data is None) when trying to load info for patient_id: {self.patient_id}")
            error_msg = "Error: Patient data not found"
            for key, var_or_widget in self.info_vars.items():
                 if isinstance(var_or_widget, tk.StringVar):
                     var_or_widget.set(error_msg)
                 elif isinstance(var_or_widget, tk.Text):
                     # Safely update Text widget state
                     try:
                         var_or_widget.config(state=tk.NORMAL)
                         var_or_widget.delete('1.0', tk.END)
                         var_or_widget.insert('1.0', error_msg)
                         var_or_widget.config(state=tk.DISABLED)
                     except tk.TclError: # Catch error if widget already destroyed
                         pass


    def load_appointments(self):
        """Loads appointments for the current patient into the Treeview."""
        logging.debug(f"Loading appointments for patient_id: {self.patient_id}")
        # Clear existing items
        for item in self.tv_appointments.get_children():
            self.tv_appointments.delete(item)

        if not self.patient_id: return # Should not happen if frame loaded correctly

        query = """
            SELECT a.appointment_id, s.name AS specialist_name, a.appointment_datetime, a.reason, a.status
            FROM Appointments a
            JOIN Staff s ON a.staff_id = s.staff_id
            WHERE a.patient_id = ?
            ORDER BY a.appointment_datetime DESC
        """
        appointments = execute_query(query, (self.patient_id,), fetch_all=True)

        if appointments:
            logging.info(f"Found {len(appointments)} appointments for patient_id: {self.patient_id}")
            for appt in appointments:
                # Ensure all values passed are strings or numbers suitable for Treeview
                self.tv_appointments.insert('', tk.END, values=(
                    appt['appointment_id'],
                    appt['specialist_name'] or 'Unknown Staff',
                    appt['appointment_datetime'] or 'N/A',
                    appt['reason'] or 'N/A',
                    appt['status'] or 'N/A'
                ))
        else:
            logging.info(f"No appointments found for patient_id: {self.patient_id}")
            # Optionally insert a message row?
            # self.tv_appointments.insert('', tk.END, values=('', '', 'No appointments found.', '', ''))

    def load_treatments(self):
        """Loads treatments for the current patient into the Treeview."""
        logging.debug(f"Loading treatments for patient_id: {self.patient_id}")
        # Clear existing items
        for item in self.tv_treatments.get_children():
            self.tv_treatments.delete(item)

        if not self.patient_id: return

        query = """
            SELECT t.treatment_id, s.name AS staff_name, t.treatment_date, t.medications, t.details
            FROM Treatments t
            LEFT JOIN Staff s ON t.recommending_staff_id = s.staff_id -- Use LEFT JOIN to show treatment even if staff deleted
            WHERE t.patient_id = ?
            ORDER BY t.treatment_date DESC
        """
        treatments = execute_query(query, (self.patient_id,), fetch_all=True)

        if treatments:
            logging.info(f"Found {len(treatments)} treatments for patient_id: {self.patient_id}")
            for treat in treatments:
                self.tv_treatments.insert('', tk.END, values=(
                    treat['treatment_id'],
                    treat['staff_name'] or 'Unknown Staff', # Handle NULL if staff deleted
                    treat['treatment_date'] or 'N/A',
                    treat['medications'] or 'N/A',
                    treat['details'] or 'N/A'
                ))
        else:
             logging.info(f"No treatments found for patient_id: {self.patient_id}")
             # Optionally insert a message row?
             # self.tv_treatments.insert('', tk.END, values=('', '', 'No treatments found.', '', ''))



# --- Staff Frame ---
# (No significant changes needed from previous version)
class StaffFrame(ttk.Frame):
    """GUI Frame for logged-in Staff."""
    def __init__(self, master, staff_data):
        super().__init__(master, padding="10")
        self.master = master
        self.staff_data = staff_data
        self.staff_id = self.staff_data['staff_id']
        logging.info(f"Initializing StaffFrame for staff_id: {self.staff_id}")

        self.create_widgets()
        self.show_patient_management_view() # Default view


    def create_widgets(self):
        """Creates the main layout and navigation for the staff view."""
        logging.debug(f"Creating widgets for StaffFrame (staff_id: {self.staff_id})")
        top_frame = ttk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 15)) # Increased bottom padding

        staff_info_text = f"Logged in as: {self.staff_data['name']} (ID: {self.staff_id}) | Speciality: {self.staff_data['speciality'] or 'General'}" # Default Speciality
        lbl_staff_info = ttk.Label(top_frame, text=staff_info_text, font=("Helvetica", 13, "italic")) # Slightly larger font
        lbl_staff_info.pack(side=tk.LEFT, padx=10, pady=5)

        btn_logout = ttk.Button(top_frame, text="Logout", command=self.master.logout)
        btn_logout.pack(side=tk.RIGHT, padx=10, pady=5)

        nav_frame = ttk.Frame(self, padding=(0, 10))
        nav_frame.pack(side=tk.TOP, fill=tk.X)

        btn_manage_patients = ttk.Button(nav_frame, text="Manage Patients", command=self.show_patient_management_view)
        btn_manage_patients.pack(side=tk.LEFT, padx=5)

        btn_manage_appointments = ttk.Button(nav_frame, text="Manage Appointments", command=self.show_appointment_management_view)
        btn_manage_appointments.pack(side=tk.LEFT, padx=5)

        btn_manage_treatments = ttk.Button(nav_frame, text="Manage Treatments", command=self.show_treatment_management_view)
        btn_manage_treatments.pack(side=tk.LEFT, padx=5)

        btn_view_schedule = ttk.Button(nav_frame, text="View Schedule", command=self.show_schedule_view)
        btn_view_schedule.pack(side=tk.LEFT, padx=10)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X, pady=(5,10)) # Separator

        self.content_frame = ttk.Frame(self)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

    def show_schedule_view(self):
        logging.info(f"Staff {self.staff_id} switching to Schedule View.")
        self.clear_content_frame()  # Clear the main content area
        # Pass the content frame, controller, and staff data to the new view
        StaffScheduleView(self.content_frame, self.app_controller, self.staff_data).pack(fill=tk.BOTH, expand=True)

    def clear_content_frame(self):
        """Removes all widgets from the content frame."""
        logging.debug("Clearing content frame in StaffFrame.")
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_patient_management_view(self):
        logging.info(f"Staff {self.staff_id} switching to Patient Management view.")
        self.clear_content_frame()
        # Staff access this view too, passing their staff_data
        PatientManagementView(self.content_frame, self.master, self.staff_data).pack(fill=tk.BOTH, expand=True)

    def show_appointment_management_view(self):
        logging.info(f"Staff {self.staff_id} switching to Appointment Management view.")
        self.clear_content_frame()
        AppointmentManagementView(self.content_frame, self.master, self.staff_data).pack(fill=tk.BOTH, expand=True)

    def show_treatment_management_view(self):
        logging.info(f"Staff {self.staff_id} switching to Treatment Management view.")
        self.clear_content_frame()
        TreatmentManagementView(self.content_frame, self.master, self.staff_data).pack(fill=tk.BOTH, expand=True)

class StaffScheduleView(ttk.Frame):
    """Frame for Staff to view their schedule by date."""
    def __init__(self, master, app_controller, staff_data):
        super().__init__(master, padding="15")
        self.app_controller = app_controller
        self.staff_data = staff_data
        self.staff_id = staff_data['staff_id']
        self.staff_name = staff_data['name']
        self.caller_context = f"Staff {self.staff_id} Schedule"
        logging.debug(f"Initializing StaffScheduleView ({self.caller_context})")

        # Store appointments for the currently viewed date
        self.appointments_on_date = []

        self.create_widgets()
        # Load today's schedule initially
        self.load_schedule_for_date()

    def create_widgets(self):
        logging.debug(f"Creating widgets for StaffScheduleView ({self.caller_context})")
        self.columnconfigure(1, weight=1) # Allow list/calendar area to expand
        self.rowconfigure(2, weight=1)    # Allow appointment list to expand vertically

        # Title
        lbl_title = ttk.Label(self, text=f"{self.staff_name}'s Schedule", font=("Helvetica", 16, "bold"))
        lbl_title.grid(row=0, column=0, columnspan=3, pady=(0, 15), sticky="w")

        # Date Selection
        lbl_date = ttk.Label(self, text="Select Date:")
        lbl_date.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.date_entry = DateEntry(
            self,
            width=15,
            borderwidth=2,
            date_pattern='y-mm-dd',
            state='readonly',
            command=self.load_schedule_for_date # Call load function when date changes
            )
        # Set initial date to today
        self.date_entry.set_date(datetime.now().date())
        self.date_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Add button to quickly jump back to today
        btn_today = ttk.Button(self, text="Today", command=self.go_to_today, width=8)
        btn_today.grid(row=1, column=2, padx=10, pady=5, sticky="w")


        # Appointments List Frame
        list_frame = ttk.LabelFrame(self, text="Appointments on Selected Date", padding=10)
        list_frame.grid(row=2, column=0, columnspan=3, pady=(15, 0), sticky="nsew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        cols = ('time', 'patient', 'reason', 'status')
        self.tv_schedule = ttk.Treeview(list_frame, columns=cols, show='headings', height=15)
        self.tv_schedule.heading('time', text='Time')
        self.tv_schedule.heading('patient', text='Patient')
        self.tv_schedule.heading('reason', text='Reason')
        self.tv_schedule.heading('status', text='Status')
        self.tv_schedule.column('time', width=80, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_schedule.column('patient', width=200)
        self.tv_schedule.column('reason', width=300)
        self.tv_schedule.column('status', width=100, anchor=tk.CENTER)
        self.tv_schedule.grid(row=0, column=0, sticky="nsew")

        # Scrollbar for Treeview
        schedule_vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tv_schedule.yview)
        schedule_vsb.grid(row=0, column=1, sticky="ns")
        self.tv_schedule.configure(yscrollcommand=schedule_vsb.set)
        # Horizontal scrollbar might not be needed if columns are reasonably sized
        # schedule_hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.tv_schedule.xview)
        # schedule_hsb.grid(row=1, column=0, sticky="ew")
        # self.tv_schedule.configure(xscrollcommand=schedule_hsb.set)

        # (Could add double-click binding to view full details later)
        # self.tv_schedule.bind('<Double-1>', self.view_appointment_details)


    def go_to_today(self):
        """Sets the calendar to today and reloads the schedule."""
        self.date_entry.set_date(datetime.now().date())
        self.load_schedule_for_date()

    def load_schedule_for_date(self, event=None): # Added event=None for binding if needed
        """Fetches and displays appointments for the selected date."""
        selected_date_str = self.date_entry.get()
        logging.info(f"Loading schedule for Staff {self.staff_id} on {selected_date_str}")

        # Clear current list
        for item in self.tv_schedule.get_children():
            self.tv_schedule.delete(item)

        try:
            # Fetch appointments for this staff member on this specific day
            # Modify query slightly to filter by date part only
            query = """
                SELECT appointment_id, p.name AS patient_name, appointment_datetime, reason, status
                FROM Appointments a
                JOIN Patients p ON a.patient_id = p.patient_id
                WHERE a.staff_id = ? AND date(a.appointment_datetime) = date(?)
                ORDER BY a.appointment_datetime ASC
            """
            params = (self.staff_id, selected_date_str)
            self.appointments_on_date = execute_query(query, params, fetch_all=True)

            if self.appointments_on_date:
                logging.debug(f"Found {len(self.appointments_on_date)} appointments.")
                for appt in self.appointments_on_date:
                    try:
                        # Extract time part for display
                        dt_obj = datetime.strptime(appt['appointment_datetime'], '%Y-%m-%d %H:%M:%S')
                        time_display = dt_obj.strftime('%H:%M') # 24-hour format
                    except (ValueError, TypeError):
                        time_display = 'Invalid Time'

                    self.tv_schedule.insert('', tk.END, values=(
                        time_display,
                        appt['patient_name'] or 'Unknown',
                        appt['reason'] or '',
                        appt['status'] or 'N/A'
                    ), iid=appt['appointment_id']) # Use appt ID as item ID if needed later
            else:
                logging.info("No appointments found for this date.")
                self.tv_schedule.insert('', tk.END, values=('','No appointments scheduled.', '', ''))

        except Exception as e:
            logging.exception(f"Error loading schedule for {selected_date_str}: {e}")
            messagebox.showerror("Error", f"Failed to load schedule for {selected_date_str}.")

# --- Staff/Admin Sub-Views ---

# --- Patient Management View (Used by Staff & Admin) ---
# (Incorporates previous changes + horizontal scrollbar)
class PatientManagementView(ttk.Frame):
    """Frame for Staff/Admin to view, add, edit patient details, and create logins when adding."""
    # ... (rest of the PatientManagementView class code from the previous good version) ...
    # INCLUDING: __init__, create_widgets (with horizontal scrollbar added),
    # load_patient_list, on_patient_select, clear_form, add_patient,
    # update_patient, delete_patient (with admin check)
    def __init__(self, master, app_controller, staff_data): # staff_data is None if Admin
        super().__init__(master, padding="10")
        self.app_controller = app_controller
        self.staff_data = staff_data
        self.is_admin = staff_data is None # Check if accessed by Admin
        self.caller_context = "Admin" if self.is_admin else f"Staff {staff_data['staff_id']}"
        logging.debug(f"Initializing PatientManagementView ({self.caller_context})")

        self.selected_patient_id = None

        # Variables for the details/add form
        self.entry_vars = {} # Keep this for patient details
        self.add_username = tk.StringVar()
        self.add_password = tk.StringVar()

        self.create_widgets()
        self.load_patient_list()

    def create_widgets(self):
        logging.debug(f"Creating widgets for PatientManagementView ({self.caller_context})")
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane: Patient List (No changes needed here) ---
        list_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(list_frame, weight=1)
        list_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        # ... (lbl_list, tree_frame, tv_patients, scrollbars, refresh button setup as before) ...
        lbl_list = ttk.Label(list_frame, text="Patients", font=("Helvetica", 14, "bold"))
        lbl_list.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")
        tree_frame = ttk.Frame(list_frame)
        tree_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)
        cols = ('id', 'name', 'dob', 'gender', 'contact')
        self.tv_patients = ttk.Treeview(tree_frame, columns=cols, show='headings', height=20)
        self.tv_patients.heading('id', text='ID')
        self.tv_patients.heading('name', text='Name')
        self.tv_patients.heading('dob', text='DOB')
        self.tv_patients.heading('gender', text='Gender')
        self.tv_patients.heading('contact', text='Contact')
        self.tv_patients.column('id', width=50, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_patients.column('name', width=160)
        self.tv_patients.column('dob', width=100)
        self.tv_patients.column('gender', width=70)
        self.tv_patients.column('contact', width=150)
        self.tv_patients.grid(row=0, column=0, sticky="nsew")
        pt_vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tv_patients.yview)
        pt_vsb.grid(row=0, column=1, sticky="ns")
        pt_hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tv_patients.xview)
        pt_hsb.grid(row=1, column=0, sticky="ew")
        self.tv_patients.configure(yscrollcommand=pt_vsb.set, xscrollcommand=pt_hsb.set)
        self.tv_patients.bind('<<TreeviewSelect>>', self.on_patient_select)
        list_btn_frame = ttk.Frame(list_frame)
        list_btn_frame.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        btn_refresh = ttk.Button(list_btn_frame, text="Refresh List", command=self.load_patient_list)
        btn_refresh.pack(side=tk.LEFT, padx=5)


        # --- Right Pane: Scrollable Details / Add Form ---
        # Outer frame for the details section (parent in the PanedWindow)
        self.details_outer_frame = ttk.LabelFrame(main_pane, text="Patient Details / Add New", padding=(10, 5))  # *** ADD self. ***
        main_pane.add(self.details_outer_frame, weight=2)
        # **Configure outer frame's grid to make canvas expand**
        self.details_outer_frame.rowconfigure(0, weight=1)
        self.details_outer_frame.columnconfigure(0, weight=1)

        # Create Canvas
        canvas = tk.Canvas(self.details_outer_frame, borderwidth=0, highlightthickness=0)    # Parent is self.details_outer_frame
        # Create Scrollbar linked to Canvas
        scrollbar = ttk.Scrollbar(self.details_outer_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        # Grid Canvas and Scrollbar
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Create the Inner Frame INSIDE the Canvas
        self.inner_details_frame = ttk.Frame(canvas, padding="15")
        # Put the Inner Frame onto the Canvas using create_window
        # Important: Store the ID returned by create_window
        self.canvas_frame_id = canvas.create_window((0, 0), window=self.inner_details_frame, anchor="nw")

        # Configure the inner frame's column weights (as before)
        self.inner_details_frame.columnconfigure(1, weight=1)

        # --- Binding function to update scroll region ---
        def configure_scroll_region(event=None):
            # Update the scrollregion to encompass the inner frame's whole area
            bbox = canvas.bbox("all")
            logging.debug(f"Updating scrollregion: {bbox}") # Add logging
            canvas.configure(scrollregion=bbox)
            # Optionally: Adjust canvas window width if needed
            canvas.itemconfig(self.canvas_frame_id, width=canvas.winfo_width())

        # --- Binding function for mouse wheel ---
        def on_mousewheel(event):
            # Determine scroll direction and amount based on OS
            scroll_amount = 0
            if event.num == 5 or event.delta < 0:  # Scroll down (Linux event.num, Windows event.delta)
                scroll_amount = 1
            if event.num == 4 or event.delta > 0:  # Scroll up
                scroll_amount = -1
            canvas.yview_scroll(scroll_amount, "units")

        # --- Bind events ---
        # Update scroll region when the inner frame's size changes
        self.inner_details_frame.bind("<Configure>", configure_scroll_region)
        # Bind mouse wheel scrolling to the canvas, inner frame, and the outer frame for wider coverage
        # Binding to canvas should usually be sufficient if it fills the outer frame
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", on_mousewheel)) # Bind when mouse enters canvas
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))            # Unbind when mouse leaves
        # You might also need to bind to the inner frame for elements like Text that can grab focus:
        # self.inner_details_frame.bind("<MouseWheel>", on_mousewheel)


        # --- Populate the inner_details_frame with widgets ---
        # Make sure ALL subsequent widgets have self.inner_details_frame as their parent

        row_idx = 0
        # Login Credentials Frame (Parent: self.inner_details_frame)
        self.login_details_frame = ttk.Frame(self.inner_details_frame)
        self.login_details_frame.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=(0,15))
        self.login_details_frame.columnconfigure(1, weight=1)
        # ... (widgets inside login_details_frame) ...
        lbl_login_sec = ttk.Label(self.login_details_frame, text="Login Credentials (for New Patient):", font=('Helvetica', 11, 'italic'))
        lbl_login_sec.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0,5))
        lbl_user = ttk.Label(self.login_details_frame, text="Username:")
        lbl_user.grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.entry_add_username = ttk.Entry(self.login_details_frame, textvariable=self.add_username, width=35)
        self.entry_add_username.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        lbl_pass = ttk.Label(self.login_details_frame, text="Password:")
        lbl_pass.grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.entry_add_password = ttk.Entry(self.login_details_frame, textvariable=self.add_password, width=35, show="*")
        self.entry_add_password.grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        lbl_pass_req = ttk.Label(self.login_details_frame, text="(Min 8 chars)", font=('Helvetica', 9))
        lbl_pass_req.grid(row=2, column=2, padx=(5,0), pady=2, sticky="w")
        row_idx +=1

        # Separator (Parent: self.inner_details_frame)
        ttk.Separator(self.inner_details_frame, orient=tk.HORIZONTAL).grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=(0, 15))
        row_idx += 1

        # Patient Detail Fields (Parent: self.inner_details_frame)
        patient_detail_labels = ["Name:", "DOB (YYYY-MM-DD):", "Gender:", "Contact:", "Address:", "Medical History:", "Surgery History:", "Insurance Provider:", "Policy Number:", "Expiry (YYYY-MM-DD):", "Coverage Details:"]
        self.entry_vars = {}

        for i, text in enumerate(patient_detail_labels):
            label_row = row_idx + i
            lbl = ttk.Label(self.inner_details_frame, text=text) # PARENT
            lbl.grid(row=label_row, column=0, padx=5, pady=6, sticky="nw" if "History" in text or "Details" in text or "Address" in text else "w")

            if "History" in text or "Details" in text or "Address" in text:
                text_frame = ttk.Frame(self.inner_details_frame) # PARENT
                text_frame.grid(row=label_row, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
                text_frame.columnconfigure(0, weight=1)
                widget_height = 5 if "History" in text else (3 if "Address" in text else 4)
                text_widget = tk.Text(text_frame, height=widget_height, width=45, font=('Helvetica', 11), wrap="word", borderwidth=1, relief="sunken")
                text_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
                text_widget.configure(yscrollcommand=text_scroll.set)
                text_widget.grid(row=0, column=0, sticky="ew")
                text_scroll.grid(row=0, column=1, sticky="ns")
                self.entry_vars[text] = text_widget
                # Also bind mousewheel here if needed, but canvas binding should handle most cases
                # text_widget.bind("<MouseWheel>", on_mousewheel, add='+') # Maybe uncomment if scroll fails on Text focus
            else:
                var = tk.StringVar()
                entry = ttk.Entry(self.inner_details_frame, textvariable=var, width=45) # PARENT
                entry.grid(row=label_row, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
                self.entry_vars[text] = var
        row_idx += len(patient_detail_labels)

        # --- Buttons Frame --- (Parent: self.inner_details_frame)
        btn_frame = ttk.Frame(self.inner_details_frame)
        btn_frame.grid(row=row_idx, column=0, columnspan=3, pady=(25, 15))  # Add bottom padding
        # ... (packing buttons inside btn_frame as before) ...
        self.btn_add = ttk.Button(btn_frame, text="Add Patient & Create Login", command=self.add_patient)
        self.btn_add.pack(side=tk.LEFT, padx=5)
        self.btn_update = ttk.Button(btn_frame, text="Update Details", command=self.update_patient, state=tk.DISABLED)
        self.btn_update.pack(side=tk.LEFT, padx=5)
        self.btn_clear = ttk.Button(btn_frame, text="Clear Form", command=self.clear_form)
        self.btn_clear.pack(side=tk.LEFT, padx=5)
        if self.is_admin:
            self.btn_delete_patient = ttk.Button(btn_frame, text="Delete Patient Record", command=self.delete_patient, state=tk.DISABLED)
            self.btn_delete_patient.pack(side=tk.LEFT, padx=10)

        # ** Crucial: Force an initial update of the layout **
        self.inner_details_frame.update_idletasks()
        # ** Then configure the scroll region **
        canvas.configure(scrollregion=canvas.bbox("all"))
        # Optional: Adjust canvas window width
        canvas.itemconfig(self.canvas_frame_id, width=canvas.winfo_width())
        self.after(10, lambda c=canvas, cf_id=self.canvas_frame_id: self._finish_scroll_setup(c, cf_id))

        def _finish_scroll_setup(self, canvas, canvas_frame_id):
            """Final setup for scroll region after widgets are drawn."""
            logging.debug(f"Running _finish_scroll_setup for {self.__class__.__name__}")
            try:
                # Ensure widgets are drawn and sizes calculated
                self.inner_details_frame.update_idletasks()
                # Calculate the bounding box of all items within the inner frame
                bbox = canvas.bbox(tk.ALL)  # Or canvas.bbox("all") should also work
                if bbox:
                    logging.debug(f"  Final scrollregion bbox: {bbox}")
                    canvas.configure(scrollregion=bbox)
                    # Adjust the canvas window width to match the canvas visible width
                    # This helps prevent horizontal shifting if content is narrower than canvas
                    canvas.itemconfig(canvas_frame_id, width=canvas.winfo_width())
                    logging.debug(f"  Set scrollregion to {bbox}, canvas window width to {canvas.winfo_width()}")
                else:
                    logging.warning("  _finish_scroll_setup: Bbox calculation returned None. Scrollregion not set.")

                # Ensure the scrollbar starts at the top
                canvas.yview_moveto(0)

            except tk.TclError as e:
                # Catch errors like window not visible yet
                logging.warning(f"TclError during _finish_scroll_setup (likely window not ready yet): {e}. Retrying...")
                # Retry after a slightly longer delay if the first one failed
                self.after(50, lambda c=canvas, cf_id=canvas_frame_id: self._finish_scroll_setup(c, cf_id))
            except Exception as e:
                logging.exception(f"Unexpected error during _finish_scroll_setup: {e}")


    # ... Keep load_patient_list, on_patient_select, clear_form, add_patient, update_patient, delete_patient methods
    #     exactly as they were in the *previous correctly functioning version*.
    #     No changes needed to their logic based on the latest request.
    # (Paste the methods from the previous version here)
    def load_patient_list(self):
        """Fetches patients from DB and populates the Treeview."""
        logging.info(f"Loading patient list in PatientManagementView ({self.caller_context})")
        for item in self.tv_patients.get_children():
            self.tv_patients.delete(item)

        patients = get_all_patients()
        if patients:
            logging.debug(f"Populating patient list with {len(patients)} records.")
            for patient in patients:
                self.tv_patients.insert('', tk.END, values=(
                    patient['patient_id'], patient['name'], patient['date_of_birth'] or 'N/A',
                    patient['gender'] or 'N/A', patient['contact_number'] or 'N/A'
                ))
        else:
            logging.info("No patients found in database.")
        self.clear_form() # Ensure form is clear and buttons are reset

    def on_patient_select(self, event):
        """Handles selection change in the patient list Treeview."""
        selected_items = self.tv_patients.selection()
        if not selected_items:
            logging.debug(f"Patient list selection cleared ({self.caller_context}).")
            self.clear_form() # Resets buttons and fields
            return

        selected_item = selected_items[0]
        try:
            patient_id = int(self.tv_patients.item(selected_item)['values'][0])
        except (ValueError, IndexError):
            logging.error(f"Could not get valid patient ID from selected treeview item: {self.tv_patients.item(selected_item)['values']}")
            self.clear_form()
            return

        logging.info(f"Patient selected: ID {patient_id} ({self.caller_context})")
        self.selected_patient_id = patient_id

        # --- Disable and clear login fields when editing ---
        self.entry_add_username.config(state=tk.DISABLED)
        self.entry_add_password.config(state=tk.DISABLED)
        self.add_username.set("")
        self.add_password.set("")
        # --- ---

        patient_details = execute_query("SELECT * FROM Patients WHERE patient_id = ?", (patient_id,), fetch_one=True)
        insurance_details = execute_query("SELECT * FROM Insurance WHERE patient_id = ?", (patient_id,), fetch_one=True)

        if patient_details:
            logging.debug(f"Loading details for patient ID: {patient_id}")
            # Populate StringVars
            self.entry_vars["Name:"].set(patient_details['name'] or '')
            self.entry_vars["DOB (YYYY-MM-DD):"].set(patient_details['date_of_birth'] or '')
            self.entry_vars["Gender:"].set(patient_details['gender'] or '')
            self.entry_vars["Contact:"].set(patient_details['contact_number'] or '')

            # Populate Text widgets
            self.entry_vars["Address:"].delete('1.0', tk.END)
            self.entry_vars["Address:"].insert('1.0', patient_details['address'] or '')
            self.entry_vars["Medical History:"].delete('1.0', tk.END)
            self.entry_vars["Medical History:"].insert('1.0', patient_details['medical_history'] or '')
            self.entry_vars["Surgery History:"].delete('1.0', tk.END)
            self.entry_vars["Surgery History:"].insert('1.0', patient_details['surgery_history'] or '')

            if insurance_details:
                logging.debug(f"Loading insurance details for patient ID: {patient_id}")
                self.entry_vars["Insurance Provider:"].set(insurance_details['provider_name'] or '')
                self.entry_vars["Policy Number:"].set(insurance_details['policy_number'] or '')
                self.entry_vars["Expiry (YYYY-MM-DD):"].set(insurance_details['expiry_date'] or '')
                self.entry_vars["Coverage Details:"].delete('1.0', tk.END)
                self.entry_vars["Coverage Details:"].insert('1.0', insurance_details['coverage_details'] or '')
            else:
                logging.debug(f"No insurance details found for patient ID: {patient_id}")
                self.entry_vars["Insurance Provider:"].set('')
                self.entry_vars["Policy Number:"].set('')
                self.entry_vars["Expiry (YYYY-MM-DD):"].set('')
                self.entry_vars["Coverage Details:"].delete('1.0', tk.END)

            # --- Update form state for editing ---
            self.details_outer_frame.config(text=f"Details for Patient ID: {patient_id}") # Use outer_frame
            self.btn_update.config(state=tk.NORMAL)
            if self.is_admin: self.btn_delete_patient.config(state=tk.NORMAL)
            self.btn_add.config(state=tk.DISABLED) # Disable add when selected
            # --- ---
        else:
            logging.error(f"Could not fetch details for patient ID {patient_id} after selection ({self.caller_context}).")
            messagebox.showerror("Error", f"Could not fetch details for selected patient ID {patient_id}")
            self.clear_form()

    def clear_form(self):
        """Clears all entry fields and resets buttons/state for adding."""
        logging.debug(f"Clearing patient details form ({self.caller_context}).")
        # Clear patient details
        for key, var_or_widget in self.entry_vars.items():
            if isinstance(var_or_widget, tk.StringVar):
                var_or_widget.set("")
            elif isinstance(var_or_widget, tk.Text):
                 var_or_widget.delete('1.0', tk.END)

        # Clear and ENABLE login fields
        self.add_username.set("")
        self.add_password.set("")
        self.entry_add_username.config(state=tk.NORMAL)
        self.entry_add_password.config(state=tk.NORMAL)

        # Reset selection and buttons
        if self.tv_patients.selection():
            self.tv_patients.selection_remove(self.tv_patients.selection()) # Deselect
        self.selected_patient_id = None
        self.details_outer_frame.config(text="Patient Details / Add New") # Use outer_frame
        self.btn_update.config(state=tk.DISABLED)
        if self.is_admin: self.btn_delete_patient.config(state=tk.DISABLED)
        self.btn_add.config(state=tk.NORMAL)

    def add_patient(self):
        """Adds a new patient record AND creates a corresponding user login."""
        logging.info(f"Attempting to add new patient and create login ({self.caller_context}).")

        # 1. Get Login Credentials
        username = self.add_username.get().strip()
        password = self.add_password.get()
        role = "Patient" # Fixed role

        # 2. Get Patient Details
        name = self.entry_vars["Name:"].get().strip()
        dob = self.entry_vars["DOB (YYYY-MM-DD):"].get().strip() or None # Strip whitespace
        gender = self.entry_vars["Gender:"].get().strip() or None
        contact = self.entry_vars["Contact:"].get().strip() or None
        address = self.entry_vars["Address:"].get("1.0", tk.END).strip() or None
        med_history = self.entry_vars["Medical History:"].get("1.0", tk.END).strip() or None
        surg_history = self.entry_vars["Surgery History:"].get("1.0", tk.END).strip() or None

        # 3. Get Insurance Details (Optional)
        ins_provider = self.entry_vars["Insurance Provider:"].get().strip() or None
        ins_policy = self.entry_vars["Policy Number:"].get().strip() or None
        ins_expiry = self.entry_vars["Expiry (YYYY-MM-DD):"].get().strip() or None
        ins_coverage = self.entry_vars["Coverage Details:"].get("1.0", tk.END).strip() or None

        # 4. Validation
        if not username or not password:
            messagebox.showwarning("Missing Information", "Username and Password are required to create the patient login.")
            logging.warning("Add patient failed: Username or password empty.")
            return
        if len(password) < 8:
             messagebox.showwarning("Input Error", "Password should be at least 8 characters long.")
             logging.warning(f"Add patient failed for '{username}': Password too short.")
             return
        if check_username_exists(username):
            messagebox.showwarning("Input Error", f"Username '{username}' already exists. Please choose another.")
            logging.warning(f"Add patient failed: Username '{username}' already exists.")
            return
        if not name:
            messagebox.showwarning("Missing Information", "Patient Name is required.")
            logging.warning("Add patient failed: Patient Name is required.")
            return

        # 5. Database Operations
        new_user_id = None
        new_patient_id = None
        try:
            # 5a. Hash Password
            hashed_password = hash_password(password)
            logging.debug(f"Password hashed for new user '{username}'.")

            # 5b. Insert User Login
            user_query = "INSERT INTO Users (username, password, role) VALUES (?, ?, ?)"
            new_user_id = execute_query(user_query, (username, hashed_password, role), commit=True)
            if new_user_id is None or ExecuteQueryState.last_error:
                err_msg = f"Failed to insert new user '{username}' into Users table."
                logging.error(err_msg)
                db_err = ExecuteQueryState.last_error if ExecuteQueryState.last_error else "Unknown DB error"
                messagebox.showerror("Database Error", f"{err_msg}\n{db_err}")
                return # Stop execution

            logging.info(f"User login created for '{username}'. User ID: {new_user_id}")

            # 5c. Insert Patient Record (linking User ID)
            patient_query = """
                INSERT INTO Patients (user_id, name, date_of_birth, gender, contact_number, address, medical_history, surgery_history)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            patient_params = (new_user_id, name, dob, gender, contact, address, med_history, surg_history)
            new_patient_id = execute_query(patient_query, patient_params, commit=True)

            if new_patient_id is None or ExecuteQueryState.last_error:
                 err_msg = f"CRITICAL: User {new_user_id} ('{username}') created, but failed to insert patient record!"
                 logging.critical(err_msg)
                 # Try cleanup
                 cleanup_query = "DELETE FROM Users WHERE user_id = ?"
                 cleanup_success = execute_query(cleanup_query, (new_user_id,), commit=True)
                 logging.warning(f"Attempted cleanup of orphaned user {new_user_id}. Success: {cleanup_success is not None}")
                 db_err = ExecuteQueryState.last_error if ExecuteQueryState.last_error else "Unknown DB error"
                 messagebox.showerror("Critical Database Error", f"{err_msg}\nPlease contact administrator.\n{db_err}")
                 return # Stop execution

            logging.info(f"Patient record created for '{name}'. Patient ID: {new_patient_id}, Linked to User ID: {new_user_id}")

            # 5d. Insert Insurance (if provided)
            if ins_provider or ins_policy or ins_expiry or ins_coverage: # Check if any insurance detail exists
                logging.debug(f"Adding insurance details for new patient ID: {new_patient_id}")
                insurance_query = """
                    INSERT INTO Insurance (patient_id, provider_name, policy_number, expiry_date, coverage_details)
                    VALUES (?, ?, ?, ?, ?)
                """
                insurance_params = (new_patient_id, ins_provider, ins_policy, ins_expiry, ins_coverage)
                ins_result = execute_query(insurance_query, insurance_params, commit=True)

                if ins_result is None and ExecuteQueryState.last_error:
                    logging.warning(f"Failed to add insurance details for patient ID {new_patient_id}. Error: {ExecuteQueryState.last_error}")
                    messagebox.showwarning("Insurance Warning", f"Patient '{name}' registered, but failed to save insurance. Edit record manually.")
                else:
                    logging.debug(f"Insurance details added for patient ID: {new_patient_id}")

            messagebox.showinfo("Success", f"Patient '{name}' registered with login '{username}' successfully (Patient ID: {new_patient_id}).")
            self.load_patient_list() # Refresh list which calls clear_form

        except Exception as e: # Catch broader exceptions
            logging.exception(f"Unexpected error during patient registration for '{username}': {e}")
            messagebox.showerror("Application Error", f"An unexpected error occurred during registration: {e}")


    def update_patient(self):
        """Updates the selected patient's *details* record (not login info)."""
        if not self.selected_patient_id:
            logging.warning(f"Update patient attempt failed: No patient selected ({self.caller_context}).")
            messagebox.showwarning("No Selection", "Please select a patient from the list to update.")
            return

        logging.info(f"Attempting to update patient details for ID: {self.selected_patient_id} ({self.caller_context})")
        # Get data from form... (same as before)
        name = self.entry_vars["Name:"].get().strip()
        dob = self.entry_vars["DOB (YYYY-MM-DD):"].get().strip() or None
        gender = self.entry_vars["Gender:"].get().strip() or None
        contact = self.entry_vars["Contact:"].get().strip() or None
        address = self.entry_vars["Address:"].get("1.0", tk.END).strip() or None
        med_history = self.entry_vars["Medical History:"].get("1.0", tk.END).strip() or None
        surg_history = self.entry_vars["Surgery History:"].get("1.0", tk.END).strip() or None
        ins_provider = self.entry_vars["Insurance Provider:"].get().strip() or None
        ins_policy = self.entry_vars["Policy Number:"].get().strip() or None
        ins_expiry = self.entry_vars["Expiry (YYYY-MM-DD):"].get().strip() or None
        ins_coverage = self.entry_vars["Coverage Details:"].get("1.0", tk.END).strip() or None


        if not name: # Basic validation
            logging.warning(f"Update patient failed for ID {self.selected_patient_id}: Name cannot be empty.")
            messagebox.showwarning("Missing Information", "Patient Name cannot be empty.")
            return

        try:
            # Update Patients table
            patient_query = """
                UPDATE Patients SET
                    name = ?, date_of_birth = ?, gender = ?, contact_number = ?,
                    address = ?, medical_history = ?, surgery_history = ?
                WHERE patient_id = ?
            """
            patient_params = (name, dob, gender, contact, address, med_history, surg_history, self.selected_patient_id)
            p_update_success = execute_query(patient_query, patient_params, commit=True)

            if not p_update_success and ExecuteQueryState.last_error:
                 raise ExecuteQueryState.last_error # Propagate DB error

            logging.debug(f"Patient details updated for ID: {self.selected_patient_id}")

            # Update/Insert/Delete Insurance table
            existing_insurance = execute_query("SELECT insurance_id FROM Insurance WHERE patient_id = ?", (self.selected_patient_id,), fetch_one=True)
            has_insurance_info = any([ins_provider, ins_policy, ins_expiry, ins_coverage])
            insurance_query = None
            ins_params = ()

            if existing_insurance:
                if has_insurance_info: # Update
                    logging.debug(f"Updating existing insurance record for patient ID: {self.selected_patient_id}")
                    insurance_query = "UPDATE Insurance SET provider_name = ?, policy_number = ?, expiry_date = ?, coverage_details = ? WHERE patient_id = ?"
                    ins_params = (ins_provider, ins_policy, ins_expiry, ins_coverage, self.selected_patient_id)
                else: # Delete
                     logging.debug(f"Deleting existing empty insurance record for patient ID: {self.selected_patient_id}")
                     insurance_query = "DELETE FROM Insurance WHERE patient_id = ?"
                     ins_params = (self.selected_patient_id,)
            elif has_insurance_info: # Insert
                logging.debug(f"Inserting new insurance record for patient ID: {self.selected_patient_id}")
                insurance_query = "INSERT INTO Insurance (patient_id, provider_name, policy_number, expiry_date, coverage_details) VALUES (?, ?, ?, ?, ?)"
                ins_params = (self.selected_patient_id, ins_provider, ins_policy, ins_expiry, ins_coverage)

            if insurance_query:
                ins_update_success = execute_query(insurance_query, ins_params, commit=True)
                if not ins_update_success and ExecuteQueryState.last_error:
                     logging.warning(f"Patient details updated, but failed insurance update/insert/delete for patient ID {self.selected_patient_id}. Error: {ExecuteQueryState.last_error}")
                     messagebox.showwarning("Database Warning", "Patient details updated, but issue saving insurance info.")
                     # Continue, main update was successful

            logging.info(f"Patient details ID {self.selected_patient_id} updated successfully.")
            messagebox.showinfo("Success", f"Patient details for ID {self.selected_patient_id} updated successfully.")
            self.load_patient_list() # Refresh list

            # Re-select the updated patient
            for item in self.tv_patients.get_children():
                 try:
                    current_id = int(self.tv_patients.item(item)['values'][0])
                    if current_id == self.selected_patient_id:
                        self.tv_patients.selection_set(item)
                        self.tv_patients.focus(item)
                        self.entry_add_username.config(state=tk.DISABLED) # Keep disabled
                        self.entry_add_password.config(state=tk.DISABLED)
                        break
                 except (ValueError, IndexError):
                     continue

        except sqlite3.Error as e:
            logging.error(f"Database error during patient detail update ID {self.selected_patient_id}: {e}")
            messagebox.showerror("Database Error", f"Failed to update patient details: {e}")
        except Exception as e:
             logging.exception(f"Unexpected error during patient detail update ID {self.selected_patient_id}: {e}")
             messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")

    def delete_patient(self):
        """(Admin Only) Deletes the selected patient *record* (incl. related data via CASCADE). DOES NOT delete the user login."""
        if not self.is_admin:
            logging.warning(f"Non-admin ({self.caller_context}) attempted to delete patient record.")
            messagebox.showerror("Permission Denied", "Only Administrators can delete patient records.")
            return

        if not self.selected_patient_id:
            logging.warning("Delete patient record attempt failed: No patient selected.")
            messagebox.showwarning("No Selection", "Please select a patient record to delete.")
            return

        # Get name for confirmation... (same as before)
        try:
            patient_name = self.entry_vars["Name:"].get().strip()
            if not patient_name and self.tv_patients.selection(): # If form was cleared, try treeview
                selected_item = self.tv_patients.selection()[0]
                patient_name = self.tv_patients.item(selected_item)['values'][1]
            elif not patient_name:
                 patient_name = f"ID {self.selected_patient_id}"
        except Exception:
            patient_name = f"ID {self.selected_patient_id}" # Fallback name

        logging.warning(f"Admin attempting to delete patient RECORD ID: {self.selected_patient_id}, Name: {patient_name}")

        # Fetch linked user info for warning message (same as before)
        linked_user_info = execute_query("SELECT user_id, username FROM Users WHERE user_id = (SELECT user_id FROM Patients WHERE patient_id = ?)", (self.selected_patient_id,), fetch_one=True)

        confirm_msg = (f"Are you sure you want to permanently delete the patient record for '{patient_name}' (ID: {self.selected_patient_id})?\n\n"
                       "--- WARNING ---\n"
                       "This action will also permanently delete:\n"
                       "  - Associated Insurance record\n"
                       "  - Associated Appointments\n"
                       "  - Associated Treatments\n\n"
                       "(This is due to database CASCADE settings).\n\n")

        if linked_user_info:
             confirm_msg += f"The user login ('{linked_user_info['username']}', ID: {linked_user_info['user_id']}) will become UNLINKED but **will NOT be deleted**.\n"
             confirm_msg += "Delete the login separately via 'Manage User Logins' if required."
        else:
             confirm_msg += "This patient record does not appear to have a linked user login."

        if messagebox.askyesno("Confirm Patient Record Deletion", confirm_msg):
            try:
                query = "DELETE FROM Patients WHERE patient_id = ?"
                delete_success = execute_query(query, (self.selected_patient_id,), commit=True)

                if not delete_success and ExecuteQueryState.last_error:
                    raise ExecuteQueryState.last_error # Propagate DB error

                logging.info(f"Patient record ID {self.selected_patient_id} deleted successfully by Admin.")
                messagebox.showinfo("Record Deleted", f"Patient record ID {self.selected_patient_id} ('{patient_name}') deleted.")
                self.load_patient_list() # Refreshes list and clears form

            except sqlite3.Error as e:
                logging.error(f"Database error during patient record deletion for ID {self.selected_patient_id}: {e}")
                messagebox.showerror("Database Error", f"Failed to delete patient record: {e}")
            except Exception as e:
                logging.exception(f"Unexpected error during patient record deletion for ID {self.selected_patient_id}: {e}")
                messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")
        else:
            logging.info(f"Deletion cancelled for patient record ID: {self.selected_patient_id}")

# --- Placeholder Appointment/Treatment Views ---
# (No changes needed from previous version)
class AppointmentManagementView(ttk.Frame):
    """Frame for Staff/Admin to view and manage appointments."""
    def __init__(self, master, app_controller, staff_data):
        super().__init__(master, padding="10")
        self.app_controller = app_controller
        self.staff_data = staff_data # Will be None for Admin, contains dict for Staff
        self.is_admin = staff_data is None
        self.staff_id = None if self.is_admin else staff_data['staff_id']
        self.caller_context = "Admin" if self.is_admin else f"Staff {self.staff_id}"
        logging.debug(f"Initializing AppointmentManagementView ({self.caller_context})")

        self.selected_appointment_id = None
        self.patients_dict = {} # To map patient name display to ID
        self.staff_dict = {}    # To map staff name display to ID

        # Form variables
        self.patient_var = tk.StringVar()
        self.staff_var = tk.StringVar() # For admin, might be selectable. For staff, maybe fixed?
        self.date_var = tk.StringVar()  # Underlying variable for DateEntry (optional but can be useful)
        self.hour_var = tk.StringVar()
        self.minute_var = tk.StringVar()
        self.reason_var = tk.StringVar() # Using StringVar for reason Entry
        self.status_var = tk.StringVar()
        # Details text widget doesn't use a StringVar

        self.create_widgets()
        self.load_patient_dropdown()
        self.load_staff_dropdown()
        # Load appointments relevant to the user (e.g., their own if staff)
        self.load_appointment_list()


    def create_widgets(self):
        logging.debug(f"Creating widgets for AppointmentManagementView ({self.caller_context})")
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane: Appointment List ---
        list_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(list_frame, weight=1)
        list_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)

        lbl_list = ttk.Label(list_frame, text="Appointments", font=("Helvetica", 14, "bold"))
        lbl_list.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

        # Treeview Frame
        appt_tree_frame = ttk.Frame(list_frame)
        appt_tree_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        appt_tree_frame.rowconfigure(0, weight=1)
        appt_tree_frame.columnconfigure(0, weight=1)

        cols = ('id', 'patient', 'staff', 'datetime', 'reason', 'status')
        self.tv_appointments = ttk.Treeview(appt_tree_frame, columns=cols, show='headings', height=20)
        self.tv_appointments.heading('id', text='ID')
        self.tv_appointments.heading('patient', text='Patient')
        self.tv_appointments.heading('staff', text='Staff')
        self.tv_appointments.heading('datetime', text='Date & Time')
        self.tv_appointments.heading('reason', text='Reason')
        self.tv_appointments.heading('status', text='Status')
        self.tv_appointments.column('id', width=50, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_appointments.column('patient', width=150)
        self.tv_appointments.column('staff', width=150)
        self.tv_appointments.column('datetime', width=160)
        self.tv_appointments.column('reason', width=200)
        self.tv_appointments.column('status', width=100, anchor=tk.CENTER)
        self.tv_appointments.grid(row=0, column=0, sticky="nsew")

        # Scrollbars
        appt_vsb = ttk.Scrollbar(appt_tree_frame, orient="vertical", command=self.tv_appointments.yview)
        appt_hsb = ttk.Scrollbar(appt_tree_frame, orient="horizontal", command=self.tv_appointments.xview)
        self.tv_appointments.configure(yscrollcommand=appt_vsb.set, xscrollcommand=appt_hsb.set)
        appt_vsb.grid(row=0, column=1, sticky="ns")
        appt_hsb.grid(row=1, column=0, sticky="ew")

        self.tv_appointments.bind('<<TreeviewSelect>>', self.on_appointment_select)

        # Refresh button
        appt_btn_frame = ttk.Frame(list_frame)
        appt_btn_frame.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        btn_refresh_appt = ttk.Button(appt_btn_frame, text="Refresh List", command=self.load_appointment_list)
        btn_refresh_appt.pack(side=tk.LEFT, padx=5)

        # Cancel Button
        self.btn_cancel_appt = ttk.Button(appt_btn_frame, text="Cancel Selected",
                                          command=self.cancel_appointment, state=tk.DISABLED)
        self.btn_cancel_appt.pack(side=tk.LEFT, padx=5)

        # Remove Button
        self.btn_remove_appt = ttk.Button(appt_btn_frame, text="Remove Selected",
                                          command=self.remove_appointment, state=tk.DISABLED)
        self.btn_remove_appt.pack(side=tk.LEFT, padx=5)
        # --- End Buttons ---

        # --- Right Pane: Details / Schedule Form ---
        self.details_frame = ttk.LabelFrame(main_pane, text="Appointment Details / Schedule New", padding="15")
        main_pane.add(self.details_frame, weight=1) # Adjusted weight
        self.details_frame.columnconfigure(1, weight=1)

        row_idx = 0
        # Patient Selection
        ttk.Label(self.details_frame, text="Patient:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        self.combo_patient = ttk.Combobox(self.details_frame, textvariable=self.patient_var, state='readonly', width=35)
        self.combo_patient.grid(row=row_idx, column=1, padx=5, pady=6, sticky="ew")
        row_idx += 1

        # Staff Selection/Display
        ttk.Label(self.details_frame, text="Staff:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        self.combo_staff = ttk.Combobox(self.details_frame, textvariable=self.staff_var, state='readonly', width=35)
        self.combo_staff.grid(row=row_idx, column=1, padx=5, pady=6, sticky="ew")
        row_idx += 1
        # (Logic to disable/set for staff is handled elsewhere)

        # --- Date Entry ---
        # Verify this block is present and correct
        ttk.Label(self.details_frame, text="Date:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        # Use DateEntry from tkcalendar - Simplified arguments slightly
        self.date_entry = DateEntry(
            self.details_frame,
            width=18, # Slightly wider maybe?
            borderwidth=2,
            date_pattern='y-mm-dd', # Standard database format
            textvariable=self.date_var, # Link to variable
            state='readonly', # Prevent manual typing, force calendar use
            # Optional: style='primary' or other ttkbootstrap styles if using it
            )
        self.date_entry.grid(row=row_idx, column=1, padx=5, pady=6, sticky="w") # Grid placement
        row_idx += 1 # Increment row index *after* placing date

        # --- Time Entry ---
        ttk.Label(self.details_frame, text="Time:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        time_frame = ttk.Frame(self.details_frame)
        time_frame.grid(row=row_idx, column=1, padx=5, pady=6, sticky="w") # Align time frame left

        # Hour Combobox
        hours = [f"{h:02}" for h in range(0, 24)] # 00-23
        self.combo_hour = ttk.Combobox(time_frame, textvariable=self.hour_var, values=hours,
                                         width=4, state='readonly')
        self.combo_hour.pack(side=tk.LEFT, padx=(0,2)) # Add padding after

        ttk.Label(time_frame, text=":").pack(side=tk.LEFT, padx=2) # Colon separator

        # Minute Combobox
        minutes = [f"{m:02}" for m in range(0, 60, 5)] # Use 5-minute intervals
        # Or use all minutes: minutes = [f"{m:02}" for m in range(0, 60)]
        self.combo_minute = ttk.Combobox(time_frame, textvariable=self.minute_var, values=minutes,
                                           width=4, state='readonly')
        self.combo_minute.pack(side=tk.LEFT, padx=(2,0)) # Add padding before
        row_idx += 1 # Increment row index *after* placing time frame
        # --- End Date/Time ---

        # Reason (adjust row index)
        ttk.Label(self.details_frame, text="Reason:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="nw")
        reason_frame = ttk.Frame(self.details_frame)
        reason_frame.grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        reason_frame.columnconfigure(0, weight=1)
        self.text_reason = tk.Text(reason_frame, height=4, width=40, wrap="word", font=('Helvetica', 11))
        reason_scroll = ttk.Scrollbar(reason_frame, orient="vertical", command=self.text_reason.yview)
        self.text_reason.configure(yscrollcommand=reason_scroll.set)
        self.text_reason.grid(row=0, column=0, sticky="nsew")
        reason_scroll.grid(row=0, column=1, sticky="ns")
        row_idx += 1

        # Status (adjust row index)
        ttk.Label(self.details_frame, text="Status:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        status_options = ['Scheduled', 'Completed', 'Cancelled', 'No Show']
        self.combo_status = ttk.Combobox(self.details_frame, textvariable=self.status_var, values=status_options, state='readonly', width=35)
        self.combo_status.grid(row=row_idx, column=1, padx=5, pady=6, sticky="ew")
        # (Default set in clear_form)
        row_idx += 1

        # Details/Notes (adjust row index)
        ttk.Label(self.details_frame, text="Notes:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="nw")
        details_frame = ttk.Frame(self.details_frame)
        details_frame.grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        details_frame.columnconfigure(0, weight=1)
        self.text_details = tk.Text(details_frame, height=5, width=40, wrap="word", font=('Helvetica', 11))
        details_scroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.text_details.yview)
        self.text_details.configure(yscrollcommand=details_scroll.set)
        self.text_details.grid(row=0, column=0, sticky="nsew")
        details_scroll.grid(row=0, column=1, sticky="ns")
        row_idx += 1

        # Buttons Frame (adjust row index)
        appt_form_btn_frame = ttk.Frame(self.details_frame)
        appt_form_btn_frame.grid(row=row_idx, column=0, columnspan=3, pady=(25, 0))

        self.btn_schedule = ttk.Button(appt_form_btn_frame, text="Schedule New", command=self.schedule_appointment)
        self.btn_schedule.pack(side=tk.LEFT, padx=5)

        self.btn_update = ttk.Button(appt_form_btn_frame, text="Update Selected", command=self.update_appointment, state=tk.DISABLED)
        self.btn_update.pack(side=tk.LEFT, padx=5)

        self.btn_clear = ttk.Button(appt_form_btn_frame, text="Clear Form", command=self.clear_form)
        self.btn_clear.pack(side=tk.LEFT, padx=5)


    def load_appointment_list(self):
        """Loads appointments into the Treeview."""
        logging.info(f"Loading appointment list ({self.caller_context})")
        for item in self.tv_appointments.get_children():
            self.tv_appointments.delete(item)

        # For staff, filter by their ID. For admin, show all (staff_id=None).
        staff_filter_id = self.staff_id # None if admin, specific ID if staff
        appointments = get_appointments_for_view(staff_id=staff_filter_id)

        if appointments:
            logging.debug(f"Displaying {len(appointments)} appointments.")
            for appt in appointments:
                self.tv_appointments.insert('', tk.END, values=(
                    appt['appointment_id'],
                    appt['patient_name'] or 'Unknown',
                    appt['staff_name'] or 'Unknown',
                    appt['appointment_datetime'] or 'N/A',
                    appt['reason'] or '', # Use empty string for easier viewing if None
                    appt['status'] or 'N/A'
                ))
        else:
            logging.info(f"No appointments found for display ({self.caller_context}).")
        self.clear_form() # Reset form after loading list


    def load_patient_dropdown(self):
        """Populates the patient combobox."""
        patients = get_all_patients_for_selection()
        self.patients_dict = {} # Clear previous mapping
        patient_display_list = []
        if patients:
            for patient in patients:
                display_name = f"{patient['name']} (ID: {patient['patient_id']})"
                self.patients_dict[display_name] = patient['patient_id']
                patient_display_list.append(display_name)
        self.combo_patient['values'] = patient_display_list
        if patient_display_list:
            self.patient_var.set('') # Clear selection initially


    def load_staff_dropdown(self):
        """Populates the staff combobox (only relevant for Admin)."""
        if self.is_admin: # Only admin needs the full list
            staff_list = get_all_staff_for_selection()
            self.staff_dict = {} # Clear previous mapping
            staff_display_list = []
            if staff_list:
                for staff in staff_list:
                    display_name = f"{staff['name']} (ID: {staff['staff_id']})"
                    self.staff_dict[display_name] = staff['staff_id']
                    staff_display_list.append(display_name)
            self.combo_staff['values'] = staff_display_list
            self.staff_var.set('') # Clear selection
            self.combo_staff.config(state='readonly')
        elif self.staff_data: # Staff member logged in
            # Set to self and disable
            display_name = f"{self.staff_data['name']} (ID: {self.staff_id})"
            self.staff_var.set(display_name)
            self.staff_dict[display_name] = self.staff_id # Add self to dict
            self.combo_staff['values'] = [display_name] # Only option is self
            self.combo_staff.config(state='disabled')


    def on_appointment_select(self, event):
        """Handles selection change in the appointment list."""
        # ... (previous code: clear buttons, check selection, get ID) ...
        selected_items = self.tv_appointments.selection()
        can_cancel = False
        can_remove = False
        self.btn_cancel_appt.config(state=tk.DISABLED)
        self.btn_remove_appt.config(state=tk.DISABLED)

        if not selected_items:
            self.clear_form()
            return

        selected_item = selected_items[0]
        try:
            self.selected_appointment_id = int(self.tv_appointments.item(selected_item)['values'][0])
        except (ValueError, IndexError, TypeError):
            logging.error("Could not get valid appointment ID from selection.")
            self.clear_form()
            return

        logging.info(f"Appointment selected: ID {self.selected_appointment_id} ({self.caller_context})")

        details = get_appointment_details_by_id(self.selected_appointment_id)

        if details:
            # --- Populate form fields ---
            # ... (Code to populate patient, staff, date, time, reason, notes...) ...
            patient_display = f"{details['patient_name']} (ID: {details['patient_id']})"
            if patient_display in self.patients_dict: self.patient_var.set(patient_display)
            else: self.patient_var.set("")

            staff_display = f"{details['staff_name']} (ID: {details['staff_id']})"
            if self.is_admin:
                 if staff_display in self.staff_dict: self.staff_var.set(staff_display)
                 else: self.staff_var.set("")
                 self.combo_staff.config(state='disabled')
            else:
                 self_display = f"{self.staff_data['name']} (ID: {self.staff_id})"
                 self.staff_var.set(self_display)
                 self.combo_staff.config(state='disabled')

            datetime_str = details['appointment_datetime']
            dt_obj = None
            if datetime_str:
                try:
                    possible_formats = ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M']
                    for fmt in possible_formats:
                        try:
                            dt_obj = datetime.strptime(datetime_str, fmt)
                            break
                        except ValueError: continue
                    if dt_obj:
                        self.date_entry.set_date(dt_obj.date())
                        self.hour_var.set(f"{dt_obj.hour:02}")
                        self.minute_var.set(f"{dt_obj.minute:02}")
                    else: # Failed parsing
                        self.date_entry.delete(0, tk.END); self.hour_var.set(""); self.minute_var.set("")
                except Exception as e: # Other error
                    self.date_entry.delete(0, tk.END); self.hour_var.set(""); self.minute_var.set("")
            else: # datetime_str is None
                self.date_entry.delete(0, tk.END); self.hour_var.set(""); self.minute_var.set("")

            self.text_reason.delete('1.0', tk.END)
            self.text_reason.insert('1.0', details['reason'] or '')
            current_status = details['status'] or 'Scheduled' # Get current status
            self.status_var.set(current_status)
            self.text_details.delete('1.0', tk.END)
            self.text_details.insert('1.0', details['details'] or '')
            # --- End Populate ---

            # --- Button State Logic + Debugging ---
            self.btn_schedule.config(state=tk.DISABLED)
            self.btn_update.config(state=tk.NORMAL)

            appt_staff_id = details['staff_id']
            permission_to_modify = self.is_admin or (self.staff_id is not None and appt_staff_id == self.staff_id)

            # *** Modified Logic ***
            is_scheduled = (current_status == 'Scheduled')
            can_cancel_now = permission_to_modify and is_scheduled  # Can only cancel if scheduled
            # Allow remove if user has permission AND status is anything OTHER than scheduled?
            # Or maybe only allow remove for Cancelled/No Show? Let's choose Cancelled/No Show for now.
            can_remove_now = permission_to_modify and (current_status in ['Cancelled', 'No Show'])

            logging.debug(f"Button State Check: Appt ID={self.selected_appointment_id}, "
                          f"Appt Status='{current_status}', "
                          f"Appt Staff ID={appt_staff_id} (Type: {type(appt_staff_id)}), "
                          f"Logged-in Staff ID={self.staff_id} (Type: {type(self.staff_id)}), "
                          f"Is Admin={self.is_admin}, "
                          f"PermissionToModify={permission_to_modify}, "
                          f"IsScheduled={is_scheduled}")

            logging.debug(f"Enable Cancel: {can_cancel_now}, Enable Remove: {can_remove_now}")

            self.btn_cancel_appt.config(state=tk.NORMAL if can_cancel_now else tk.DISABLED)
            self.btn_remove_appt.config(state=tk.NORMAL if can_remove_now else tk.DISABLED)
            # *** End Modified Logic ***

            # Disable other fields
            self.combo_patient.config(state='disabled')
            self.combo_staff.config(state='disabled')

            self.details_frame.config(text=f"Details for Appointment ID: {self.selected_appointment_id}")
            # --- End Button States ---

        else:
            logging.error(f"Could not fetch details for appointment ID {self.selected_appointment_id}")
            messagebox.showerror("Error", "Could not load details for the selected appointment.")
            self.clear_form()

    def clear_form(self):
        """Clears the appointment form fields and resets button states."""
        logging.debug(f"Clearing appointment form ({self.caller_context})")
        self.selected_appointment_id = None
        # ... (clear patient, staff, date, time, reason, status, details fields - same as before) ...
        self.patient_var.set('')
        self.date_var.set("")
        self.hour_var.set('09')
        self.minute_var.set('00')
        if self.is_admin:
            self.staff_var.set('')
            self.combo_staff.config(state='readonly')

        self.text_reason.delete('1.0', tk.END)
        self.status_var.set('Scheduled')
        self.text_details.delete('1.0', tk.END)


        if self.tv_appointments.selection():
            self.tv_appointments.selection_remove(self.tv_appointments.selection())

        # Reset form state for adding
        self.details_frame.config(text="Appointment Details / Schedule New")
        self.btn_schedule.config(state=tk.NORMAL)
        self.btn_update.config(state=tk.DISABLED)
        # *** Disable Cancel/Remove buttons ***
        self.btn_cancel_appt.config(state=tk.DISABLED)
        self.btn_remove_appt.config(state=tk.DISABLED)
        # *** --- ***
        # Re-enable Patient/Staff combos for scheduling
        self.combo_patient.config(state='readonly')
        if self.is_admin:
            self.combo_staff.config(state='readonly')
        # else: staff combo remains disabled

    def schedule_appointment(self):
        """Schedules a new appointment."""
        logging.info(f"Attempting to schedule new appointment ({self.caller_context})")

        # Get data from form
        patient_display = self.patient_var.get()
        staff_display = self.staff_var.get()
        # Get date/time parts
        date_str = self.date_var.get().strip()  # From DateEntry's variable
        hour_str = self.hour_var.get()
        minute_str = self.minute_var.get()
        # Get other fields
        reason = self.text_reason.get("1.0", tk.END).strip() or None
        status = self.status_var.get()  # Should default to 'Scheduled'
        details = self.text_details.get("1.0", tk.END).strip() or None

        # Validation
        if not patient_display:
            messagebox.showwarning("Missing Information", "Please select a patient.")
            return
        if not staff_display:
            messagebox.showwarning("Missing Information", "Please select a staff member.")
            return
        if not date_str:
            messagebox.showwarning("Missing Information", "Please select an appointment date.")
            return
        if not hour_str or not minute_str:
            messagebox.showwarning("Missing Information", "Please select an appointment hour and minute.")
            return

        # Get IDs from display names (same as before)
        patient_id = self.patients_dict.get(patient_display)
        staff_id = self.staff_dict.get(staff_display)
        if not patient_id or not staff_id:
            messagebox.showerror("Selection Error", "Invalid patient or staff selection.")
            return

        # --- Combine Date and Time for Database ---
        try:
            # Ensure date format is correct just in case DateEntry allows typing
            valid_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            # Construct the full datetime string with seconds as 00
            datetime_db_str = f"{valid_date.strftime('%Y-%m-%d')} {hour_str}:{minute_str}:00"
            # Optional: Further validate the combined string if needed
            # datetime.strptime(datetime_db_str, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            messagebox.showerror("Invalid Date/Time", "Invalid date, hour, or minute selected.")
            return
        # --- End Date/Time Combination ---

        # Database Insert
        query = """
            INSERT INTO Appointments (patient_id, staff_id, appointment_datetime, reason, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        params = (patient_id, staff_id, datetime_db_str, reason, status, details)

        new_appt_id = execute_query(query, params, commit=True)

        if new_appt_id is not None: # Check if ID returned (indicates success)
            logging.info(f"Appointment scheduled successfully. ID: {new_appt_id}")
            messagebox.showinfo("Success", "Appointment scheduled successfully.")
            self.load_appointment_list() # Refreshes list and clears form
        else:
            logging.error(f"Failed to schedule appointment. DB Error: {ExecuteQueryState.last_error}")
            messagebox.showerror("Database Error", f"Failed to schedule appointment.\n{ExecuteQueryState.last_error or ''}")

    def update_appointment(self):
        """Updates the selected appointment."""
        if not self.selected_appointment_id:
            messagebox.showwarning("No Selection", "Please select an appointment to update.")
            return

        logging.info(f"Attempting to update appointment ID: {self.selected_appointment_id} ({self.caller_context})")

        # Get data from form
        # Patient and Staff shouldn't change typically, but could fetch IDs again for safety
        date_str = self.date_var.get().strip()
        hour_str = self.hour_var.get()
        minute_str = self.minute_var.get()
        reason = self.text_reason.get("1.0", tk.END).strip() or None
        status = self.status_var.get()
        details = self.text_details.get("1.0", tk.END).strip() or None

         # Validation
        if not status:
            messagebox.showwarning("Missing Information", "Please select a status.")
            return
        if not date_str:
            messagebox.showwarning("Missing Information", "Please enter the appointment date and time.")
            return
        # Validate datetime format
        try:
            valid_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            datetime_db_str = f"{valid_date.strftime('%Y-%m-%d')} {hour_str}:{minute_str}:00"
        except ValueError:
            try:
                valid_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                datetime_db_str = f"{valid_date.strftime('%Y-%m-%d')} {hour_str}:{minute_str}:00"
            except ValueError:
                 messagebox.showerror("Invalid Date/Time", "Invalid date, hour, or minute selected.")
                 return

        # Database Update
        query = """
            UPDATE Appointments SET
                appointment_datetime = ?, reason = ?, status = ?, details = ?
            WHERE appointment_id = ?
        """
        # Note: We generally don't allow changing patient_id or staff_id on update easily.
        params = (datetime_db_str, reason, status, details, self.selected_appointment_id) # Use combined datetime

        update_success = execute_query(query, params, commit=True)

        if update_success: # execute_query returns True/None on simple commits/updates
             # Check for error attribute just in case
             if ExecuteQueryState.last_error:
                 logging.error(f"Update query possibly succeeded (returned True), but error state was set: {ExecuteQueryState.last_error}")
                 messagebox.showerror("Database Error", f"Failed to update appointment.\n{ExecuteQueryState.last_error}")
             else:
                logging.info(f"Appointment ID {self.selected_appointment_id} updated successfully.")
                messagebox.showinfo("Success", "Appointment updated successfully.")
                self.load_appointment_list()  # Refreshes list and clears form
        else:
            # If update_success is None, execute_query definitely failed
            logging.error(f"Failed to update appointment ID {self.selected_appointment_id}. DB Error: {ExecuteQueryState.last_error}")
            messagebox.showerror("Database Error",f"Failed to update appointment.\n{ExecuteQueryState.last_error or ''}")

    def cancel_appointment(self):
        """Changes the status of the selected appointment to 'Cancelled'."""
        if not self.selected_appointment_id:
            messagebox.showwarning("No Selection", "Please select an appointment to cancel.")
            return

        logging.warning(f"{self.caller_context} attempting to cancel appointment ID: {self.selected_appointment_id}")

        # Optional: Double-check permission here again, although button state should handle it
        details = get_appointment_details_by_id(self.selected_appointment_id)
        if not details:
            messagebox.showerror("Error", "Could not retrieve appointment details to verify cancellation.")
            return
        permission_to_modify = self.is_admin or (self.staff_id is not None and details['staff_id'] == self.staff_id)
        if not permission_to_modify:
            messagebox.showerror("Permission Denied", "You do not have permission to cancel this appointment.")
            return
        if details['status'] != 'Scheduled':
            messagebox.showwarning("Action Invalid", f"Cannot cancel an appointment with status '{details['status']}'.")
            return

        # Confirmation
        if messagebox.askyesno("Confirm Cancel",
                               f"Are you sure you want to cancel appointment ID {self.selected_appointment_id}?"):
            try:
                query = "UPDATE Appointments SET status = ? WHERE appointment_id = ?"
                params = ('Cancelled', self.selected_appointment_id)
                # execute_query now returns True on success, None on failure
                update_success = execute_query(query, params, commit=True)

                # Check explicitly for True or implicitly if not None
                if update_success:  # This check now works correctly
                    # Log success, show message, refresh list
                    logging.info(f"Appointment ID {self.selected_appointment_id} cancelled successfully.")
                    messagebox.showinfo("Success", "Appointment cancelled successfully.")
                    self.load_appointment_list()  # Refresh list and clear form
                else:
                    # Failure path (execute_query returned None)
                    logging.error(
                        f"Failed to cancel appointment ID {self.selected_appointment_id}. DB Error: {ExecuteQueryState.last_error}")
                    messagebox.showerror("Database Error",
                                         f"Failed to cancel appointment.\n{ExecuteQueryState.last_error or 'Unknown DB Error'}")

            except sqlite3.Error as e:
                logging.error(f"Database error cancelling appointment ID {self.selected_appointment_id}: {e}")
                messagebox.showerror("Database Error", f"Failed to cancel appointment: {e}")
            except Exception as e:  # Keep catching broader exceptions
                logging.exception(f"Unexpected error cancelling appointment ID {self.selected_appointment_id}: {e}")
                messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")
        else:
            logging.info(f"Cancellation cancelled by user for appointment ID: {self.selected_appointment_id}")

    def remove_appointment(self):
        """Permanently removes the selected appointment from the database."""
        if not self.selected_appointment_id:
            messagebox.showwarning("No Selection", "Please select an appointment to remove.")
            return

        logging.warning(f"{self.caller_context} attempting to REMOVE appointment ID: {self.selected_appointment_id}")

        # Re-fetch details for verification
        logging.debug("Re-fetching details inside remove_appointment...")
        details = get_appointment_details_by_id(self.selected_appointment_id)
        if not details:
             logging.error("Failed to re-fetch details inside remove_appointment.")
             messagebox.showerror("Error", "Could not retrieve appointment details to verify removal.")
             return
        logging.debug(f"Re-fetched details status: {details['status']}")

        # Permission check
        permission_to_modify = self.is_admin or (self.staff_id is not None and details['staff_id'] == self.staff_id)
        if not permission_to_modify:
             logging.warning("Permission check failed inside remove_appointment.")
             messagebox.showerror("Permission Denied", "You do not have permission to remove this appointment.")
             return

        # *** CORRECTED STATUS CHECK FOR REMOVAL ***
        # Define which statuses are eligible for removal
        allowed_remove_statuses = ['Scheduled', 'Cancelled', 'No Show'] # Allow removal for these
        current_status = details['status']

        logging.debug(f"Checking if status '{current_status}' is in allowed remove list: {allowed_remove_statuses}")
        if current_status not in allowed_remove_statuses:
             # Use a more general message if removal isn't allowed for the status
             logging.warning(f"Removal blocked due to status: {current_status}")
             messagebox.showwarning("Action Invalid", f"Appointments with status '{current_status}' cannot be removed directly.")
             return
        logging.debug("Status check passed for removal.")
        # *** END STATUS CHECK ***


        # Confirmation dialog
        confirm_msg = (f"Are you sure you want to PERMANENTLY REMOVE appointment ID {self.selected_appointment_id}?\n\n"
                       "This action cannot be undone.")
        logging.debug("Displaying confirmation dialog for removal...")
        confirmed = messagebox.askyesno("Confirm Removal", confirm_msg)
        logging.debug(f"Confirmation result: {confirmed}")

        if confirmed:
            try:
                logging.debug("Attempting database DELETE operation...")
                query = "DELETE FROM Appointments WHERE appointment_id = ?"
                params = (self.selected_appointment_id,)
                # execute_query returns True on success, None on failure for DELETE/UPDATE
                delete_success = execute_query(query, params, commit=True)
                logging.debug(f"Result of execute_query for DELETE: {delete_success}")

                if delete_success: # Check if True was returned
                    if ExecuteQueryState.last_error:
                         logging.error(f"execute_query returned True but error state was set: {ExecuteQueryState.last_error}")
                         raise ExecuteQueryState.last_error # Propagate error
                    logging.info(f"Appointment ID {self.selected_appointment_id} removed successfully.")
                    messagebox.showinfo("Success", "Appointment removed successfully.")
                    self.load_appointment_list() # Refresh
                else:
                    # execute_query returned None
                    logging.error(f"Failed to remove appointment ID {self.selected_appointment_id}. DB Error: {ExecuteQueryState.last_error}")
                    messagebox.showerror("Database Error", f"Failed to remove appointment.\n{ExecuteQueryState.last_error or 'Unknown DB Error'}")

            except sqlite3.Error as e:
                 logging.error(f"Database error removing appointment ID {self.selected_appointment_id}: {e}")
                 messagebox.showerror("Database Error", f"Failed to remove appointment: {e}")
            except Exception as e:
                 logging.exception(f"Unexpected error removing appointment ID {self.selected_appointment_id}: {e}")
                 messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")
        else:
            logging.info(f"Removal cancelled by user for appointment ID: {self.selected_appointment_id}")


class TreatmentManagementView(ttk.Frame):
    """Frame for Staff/Admin to view and manage treatments."""
    def __init__(self, master, app_controller, staff_data):
        super().__init__(master, padding="10")
        self.app_controller = app_controller
        self.staff_data = staff_data # Will be None for Admin
        self.is_admin = staff_data is None
        self.staff_id = None if self.is_admin else staff_data['staff_id']
        self.caller_context = "Admin" if self.is_admin else f"Staff {self.staff_id}"
        logging.debug(f"Initializing TreatmentManagementView ({self.caller_context})")

        self.selected_treatment_id = None
        self.patients_dict = {} # To map patient name display to ID

        # Form variables
        self.patient_var = tk.StringVar()
        # Medication and Details will use Text widgets

        self.create_widgets()
        self.load_patient_dropdown()
        # Load treatments (filtered for staff, all for admin?)
        self.load_treatment_list()

    def create_widgets(self):
        logging.debug(f"Creating widgets for TreatmentManagementView ({self.caller_context})")
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane: Treatment List ---
        list_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(list_frame, weight=1)
        list_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)

        # Title - Show context (e.g., "Treatments Recommended By You")
        list_title = "Treatments"
        if not self.is_admin:
            list_title = f"Treatments Recommended By You ({self.staff_data['name']})"
        lbl_list = ttk.Label(list_frame, text=list_title, font=("Helvetica", 14, "bold"))
        lbl_list.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")

        # Treeview Frame
        treat_tree_frame = ttk.Frame(list_frame)
        treat_tree_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        treat_tree_frame.rowconfigure(0, weight=1)
        treat_tree_frame.columnconfigure(0, weight=1)

        cols = ('id', 'patient', 'date', 'meds_summary') # Show only summary of meds
        self.tv_treatments = ttk.Treeview(treat_tree_frame, columns=cols, show='headings', height=20)
        self.tv_treatments.heading('id', text='ID')
        self.tv_treatments.heading('patient', text='Patient')
        self.tv_treatments.heading('date', text='Date')
        self.tv_treatments.heading('meds_summary', text='Medications (Summary)')
        self.tv_treatments.column('id', width=50, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_treatments.column('patient', width=180)
        self.tv_treatments.column('date', width=120)
        self.tv_treatments.column('meds_summary', width=300) # Wider for summary
        self.tv_treatments.grid(row=0, column=0, sticky="nsew")

        # Scrollbars
        treat_vsb = ttk.Scrollbar(treat_tree_frame, orient="vertical", command=self.tv_treatments.yview)
        treat_hsb = ttk.Scrollbar(treat_tree_frame, orient="horizontal", command=self.tv_treatments.xview)
        self.tv_treatments.configure(yscrollcommand=treat_vsb.set, xscrollcommand=treat_hsb.set)
        treat_vsb.grid(row=0, column=1, sticky="ns")
        treat_hsb.grid(row=1, column=0, sticky="ew")

        self.tv_treatments.bind('<<TreeviewSelect>>', self.on_treatment_select)

        # Refresh button
        treat_btn_frame = ttk.Frame(list_frame)
        treat_btn_frame.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        btn_refresh_treat = ttk.Button(treat_btn_frame, text="Refresh List", command=self.load_treatment_list)
        btn_refresh_treat.pack(side=tk.LEFT, padx=5)


        # --- Right Pane: Details / Record Form ---
        self.details_frame = ttk.LabelFrame(main_pane, text="Treatment Details / Record New", padding="15")
        main_pane.add(self.details_frame, weight=1)
        self.details_frame.columnconfigure(1, weight=1)

        row_idx = 0
        # Patient Selection
        ttk.Label(self.details_frame, text="Patient:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        self.combo_patient = ttk.Combobox(self.details_frame, textvariable=self.patient_var, state='readonly', width=40)
        self.combo_patient.grid(row=row_idx, column=1, padx=5, pady=6, sticky="ew")
        row_idx += 1

        # Date
        ttk.Label(self.details_frame, text="Date:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        self.date_entry_treatment = DateEntry(  # Use a distinct name like self.date_entry_treatment
            self.details_frame,
            width=18,
            borderwidth=2,
            date_pattern='y-mm-dd',  # Ensure this matches DB expectation
            state='readonly'  # Force calendar use
            # No textvariable needed unless you explicitly want one
        )
        self.date_entry_treatment.grid(row=row_idx, column=1, padx=5, pady=6, sticky="w")  # Place the DateEntry
        row_idx += 1  # Increment row index *after* placing date
        # --- End New Date Entry ---

        # Medications
        ttk.Label(self.details_frame, text="Medications:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="nw")
        meds_frame = ttk.Frame(self.details_frame)
        meds_frame.grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        meds_frame.columnconfigure(0, weight=1)
        self.text_medications = tk.Text(meds_frame, height=6, width=45, wrap="word", font=('Helvetica', 11))
        meds_scroll = ttk.Scrollbar(meds_frame, orient="vertical", command=self.text_medications.yview)
        self.text_medications.configure(yscrollcommand=meds_scroll.set)
        self.text_medications.grid(row=0, column=0, sticky="nsew")
        meds_scroll.grid(row=0, column=1, sticky="ns")
        row_idx += 1

        # Details/Notes
        ttk.Label(self.details_frame, text="Details/Notes:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="nw")
        details_frame = ttk.Frame(self.details_frame)
        details_frame.grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        details_frame.columnconfigure(0, weight=1)
        self.text_details = tk.Text(details_frame, height=8, width=45, wrap="word", font=('Helvetica', 11))  # Larger details area
        details_scroll = ttk.Scrollbar(details_frame, orient="vertical", command=self.text_details.yview)
        self.text_details.configure(yscrollcommand=details_scroll.set)
        self.text_details.grid(row=0, column=0, sticky="nsew")
        details_scroll.grid(row=0, column=1, sticky="ns")
        row_idx += 1


        # Buttons Frame
        treat_form_btn_frame = ttk.Frame(self.details_frame)
        treat_form_btn_frame.grid(row=row_idx, column=0, columnspan=3, pady=(25, 0))

        self.btn_record = ttk.Button(treat_form_btn_frame, text="Record New", command=self.record_treatment)
        self.btn_record.pack(side=tk.LEFT, padx=5)

        self.btn_update = ttk.Button(treat_form_btn_frame, text="Update Selected", command=self.update_treatment, state=tk.DISABLED)
        self.btn_update.pack(side=tk.LEFT, padx=5)

        self.btn_clear = ttk.Button(treat_form_btn_frame, text="Clear Form", command=self.clear_form)
        self.btn_clear.pack(side=tk.LEFT, padx=5)
        # Delete button maybe for Admin later?


    def load_treatment_list(self):
        """Loads treatments into the Treeview."""
        logging.info(f"Loading treatment list ({self.caller_context})")
        for item in self.tv_treatments.get_children():
            self.tv_treatments.delete(item)

        # Staff see their recommended treatments, Admin sees all (staff_id=None)
        staff_filter_id = self.staff_id
        treatments = get_treatments_for_view(staff_id=staff_filter_id)

        if treatments:
            logging.debug(f"Displaying {len(treatments)} treatments.")
            for treat in treatments:
                 # Create a summary for meds column
                 meds = treat['medications'] or ''
                 meds_summary = (meds[:70] + '...') if len(meds) > 73 else meds # Limit length
                 self.tv_treatments.insert('', tk.END, values=(
                    treat['treatment_id'],
                    treat['patient_name'] or 'Unknown',
                    treat['treatment_date'] or 'N/A',
                    meds_summary
                 ))
        else:
            logging.info(f"No treatments found for display ({self.caller_context}).")
        self.clear_form()


    def load_patient_dropdown(self):
        """Populates the patient combobox (reusable)."""
        patients = get_all_patients_for_selection()
        self.patients_dict = {} # Clear mapping
        patient_display_list = []
        if patients:
            for patient in patients:
                display_name = f"{patient['name']} (ID: {patient['patient_id']})"
                self.patients_dict[display_name] = patient['patient_id']
                patient_display_list.append(display_name)
        self.combo_patient['values'] = patient_display_list
        self.patient_var.set('')


    def on_treatment_select(self, event):
        """Handles selection change in the treatment list."""
        selected_items = self.tv_treatments.selection()
        if not selected_items:
            self.clear_form()
            return

        selected_item = selected_items[0]
        try:
            self.selected_treatment_id = int(self.tv_treatments.item(selected_item)['values'][0])
        except (ValueError, IndexError, TypeError):
            logging.error("Could not get valid treatment ID from selection.")
            self.clear_form()
            return

        logging.info(f"Treatment selected: ID {self.selected_treatment_id} ({self.caller_context})")

        # Fetch full details
        details = get_treatment_details_by_id(self.selected_treatment_id)

        if details:
            # Populate form
            patient_display = f"{details['patient_name']} (ID: {details['patient_id']})"
            # Ensure patient exists in dropdown before setting
            if patient_display in self.combo_patient['values']:
                 self.patient_var.set(patient_display)
            else:
                 logging.warning(f"Patient {patient_display} for treatment {self.selected_treatment_id} not found in dropdown. Setting blank.")
                 self.patient_var.set('')

                # Date Entry Population
            date_str = details['treatment_date']
            if date_str:
                try:
                    # Assuming date is stored as YYYY-MM-DD
                    date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
                    self.date_entry_treatment.set_date(date_obj)
                except (ValueError, TypeError) as e:
                    logging.error(
                        f"Invalid date format '{date_str}' for Treatment ID {self.selected_treatment_id}: {e}")
                    # Clear the DateEntry or set to a default? Clearing might be safer.
                    self.date_entry_treatment.delete(0, tk.END)  # Clear the visible entry part
                    # Note: Setting date_var won't work directly if it's not linked
            else:
                # Clear if date is NULL/None in DB
                self.date_entry_treatment.delete(0, tk.END)
            # --- End Date Entry Population ---

            # Populate Medications and Details Text widgets
            self.text_medications.delete('1.0', tk.END)
            self.text_medications.insert('1.0', details['medications'] or '')
            self.text_details.delete('1.0', tk.END)
            self.text_details.insert('1.0', details['details'] or '')

            # Update button states
            self.btn_record.config(state=tk.DISABLED)
            self.btn_update.config(state=tk.NORMAL)
            self.details_frame.config(text=f"Details for Treatment ID: {self.selected_treatment_id}")
            self.combo_patient.config(state='disabled') # Don't allow changing patient on update

        else:
            logging.error(f"Could not fetch details for treatment ID {self.selected_treatment_id}")
            messagebox.showerror("Error", "Could not load details for the selected treatment.")
            self.clear_form()

    def clear_form(self):
        """Clears the treatment form fields and resets button states."""
        logging.debug(f"Clearing treatment form ({self.caller_context})")
        self.selected_treatment_id = None
        self.patient_var.set('')

        # ---  Clear Date Entry ---
        # self.date_entry_treatment.set_date(datetime.now().date())
        self.date_entry_treatment.delete(0, tk.END)  # Clear displayed text
        # You might still need to handle the internal date if not using delete
        # --- End Date Entry Clear ---
        self.text_medications.delete('1.0', tk.END)
        self.text_details.delete('1.0', tk.END)

        if self.tv_treatments.selection():
            self.tv_treatments.selection_remove(self.tv_treatments.selection())

        self.details_frame.config(text="Treatment Details / Record New")
        self.btn_record.config(state=tk.NORMAL)
        self.btn_update.config(state=tk.DISABLED)
        self.combo_patient.config(state='readonly') # Re-enable patient selection

    def record_treatment(self):
        """Records a new treatment."""
        logging.info(f"Attempting to record new treatment ({self.caller_context})")

        # Get data
        patient_display = self.patient_var.get()
        # --- NEW: Get date from DateEntry ---
        date_str = self.date_entry_treatment.get().strip() # Use get() for DateEntry
        # --- End Date Get ---
        medications = self.text_medications.get("1.0", tk.END).strip() or None
        details = self.text_details.get("1.0", tk.END).strip() or None

        # Validation
        if not patient_display:
            messagebox.showwarning("Missing Information", "Please select a patient.")
            return
        if not date_str:
             messagebox.showwarning("Missing Information", "Please select the treatment date.")
             return
        # Validate date format (get() should return in the specified pattern)
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            # This might happen if DateEntry somehow returns an unexpected format
            messagebox.showwarning("Invalid Format", "Invalid date selected. Please use the calendar.")
            return
        if self.is_admin: # Admin check
             messagebox.showerror("Action Not Allowed", "Admin cannot record treatments directly. Log in as staff.")
             return
        if not self.staff_id: # Staff ID check
             messagebox.showerror("Error", "Cannot identify logged-in staff member.")
             return

        # Get Patient ID
        patient_id = self.patients_dict.get(patient_display)
        if not patient_id:
            messagebox.showerror("Selection Error", "Invalid patient selection.")
            return

        # Database Insert
        query = """
            INSERT INTO Treatments (patient_id, recommending_staff_id, treatment_date, medications, details)
            VALUES (?, ?, ?, ?, ?)
        """
        params = (patient_id, self.staff_id, date_str, medications, details)

        new_treat_id = execute_query(query, params, commit=True)

        if new_treat_id is not None:
            logging.info(f"Treatment recorded successfully. ID: {new_treat_id} by Staff ID: {self.staff_id}")
            messagebox.showinfo("Success", "Treatment recorded successfully.")
            self.load_treatment_list() # Refresh list and clear form
        else:
            logging.error(f"Failed to record treatment. DB Error: {ExecuteQueryState.last_error}")
            messagebox.showerror("Database Error", f"Failed to record treatment.\n{ExecuteQueryState.last_error or ''}")

    def update_treatment(self):
        """Updates the selected treatment."""
        if not self.selected_treatment_id:
            messagebox.showwarning("No Selection", "Please select a treatment to update.")
            return

        logging.info(f"Attempting to update treatment ID: {self.selected_treatment_id} ({self.caller_context})")

        # Get data
        # Patient doesn't change on update
        date_str = self.date_entry_treatment.get().strip()
        medications = self.text_medications.get("1.0", tk.END).strip() or None
        details = self.text_details.get("1.0", tk.END).strip() or None

        # Validation
        if not date_str:
             messagebox.showwarning("Missing Information", "Please enter the treatment date.")
             return
        try:
            datetime.strptime(date_str, '%Y-%m-%d')
        except ValueError:
            messagebox.showwarning("Invalid Format", "Date must be in YYYY-MM-DD format.")
            return

        # TODO: Add check - can staff only update *their own* recommended treatments?
        # Fetch original record first if needed for permission check
        # original_treatment = get_treatment_details_by_id(self.selected_treatment_id)
        # if not self.is_admin and original_treatment and original_treatment['recommending_staff_id'] != self.staff_id:
        #     messagebox.showerror("Permission Denied", "You can only update treatments you recommended.")
        #     return

        # Database Update
        query = """
            UPDATE Treatments SET
                treatment_date = ?, medications = ?, details = ?
            WHERE treatment_id = ?
        """
        # Note: Not changing patient_id or recommending_staff_id here
        params = (date_str, medications, details, self.selected_treatment_id)

        update_success = execute_query(query, params, commit=True)

        if update_success:
            if ExecuteQueryState.last_error:
                logging.error(
                    f"Update query potentially succeeded, but error state set: {ExecuteQueryState.last_error}")
                messagebox.showerror("Database Error", f"Failed to update treatment.\n{ExecuteQueryState.last_error}")
            else:
                logging.info(f"Treatment ID {self.selected_treatment_id} updated successfully.")
                messagebox.showinfo("Success", "Treatment updated successfully.")
                self.load_treatment_list()  # Refresh and clear
        else:
            logging.error(f"Failed to update treatment ID {self.selected_treatment_id}. DB Error: {ExecuteQueryState.last_error}")
            messagebox.showerror("Database Error", f"Failed to update treatment.\n{ExecuteQueryState.last_error or ''}")

# --- Patient Booking View (Opens as New Window) ---
class PatientBookingView(tk.Toplevel):
    """Toplevel window for patients to book appointments."""
    def __init__(self, master, app_controller, patient_data): # patient_data is an sqlite3.Row
        super().__init__(master)
        self.app_controller = app_controller
        self.patient_data = patient_data

        # --- Corrected Data Access ---
        try:
            # Access patient_id and name using dictionary style []
            self.patient_id = patient_data['patient_id']
            self.patient_name = patient_data['name']
            # Access contact_number, handle if it's None in the database
            self.patient_phone = patient_data['contact_number'] if 'contact_number' in patient_data and patient_data['contact_number'] else None
            if not self.patient_phone:
                logging.warning(f"Patient {self.patient_name} (ID: {self.patient_id}) has no contact number in booking view.")

        except KeyError as e:
            logging.error(f"Missing expected key in patient_data for booking view: {e}. Cannot proceed.")
            messagebox.showerror("Data Error", f"Could not load necessary patient data ({e}) for booking.")
            self.destroy() # Close the broken window
            return # Stop initialization
        except Exception as e:
             logging.exception(f"Error accessing patient_data in PatientBookingView init: {e}")
             messagebox.showerror("Initialization Error", f"An error occurred loading patient booking data: {e}")
             self.destroy()
             return
        # --- End Corrected Data Access ---

        logging.debug(f"Initializing PatientBookingView for Patient ID: {self.patient_id}")

        self.title("Book New Appointment")
        self.grab_set() # Make modal
        self.geometry("650x550")
        self.resizable(False, False)

        # Data dictionaries
        self.staff_dict = {}
        self.available_slots_list = []

        # Selection variables
        self.selected_staff_var = tk.StringVar()
        self.selected_date_var = tk.StringVar() # Although DateEntry used, can still use for get/set if needed elsewhere
        self.selected_time_var = tk.StringVar()

        self.create_widgets()
        self.load_staff_dropdown()

    def create_widgets(self):
        logging.debug(f"Creating widgets for PatientBookingView (Patient ID: {self.patient_id})")
        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"Book Appointment for {self.patient_name}", font=("Helvetica", 14, "bold")).pack(
            pady=(0, 15))

        # --- Selection Frame ---
        select_frame = ttk.Frame(main_frame)
        select_frame.pack(fill=tk.X, pady=5)

        # Staff Selection
        ttk.Label(select_frame, text="Select Staff:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.combo_staff = ttk.Combobox(select_frame, textvariable=self.selected_staff_var,
                                        state='readonly', width=30)
        self.combo_staff.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        # *** Ensure binding is correct ***
        self.combo_staff.bind('<<ComboboxSelected>>', self.selection_changed, add='+')  # Use add='+' just in case

        # Date Selection
        ttk.Label(select_frame, text="Select Date:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.date_entry = DateEntry(select_frame, width=15, date_pattern='y-mm-dd',
                                    state='readonly',
                                    # *** Ensure command is correct ***
                                    command=self.selection_changed)
        self.date_entry.config(mindate=datetime.now().date())
        self.date_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.date_entry.bind('<<DateEntrySelected>>', self.selection_changed, add='+')

        # --- Available Slots Frame ---
        slots_frame = ttk.LabelFrame(main_frame, text="Available Time Slots", padding=10)
        slots_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        slots_frame.rowconfigure(0, weight=1)
        slots_frame.columnconfigure(0, weight=1)

        self.slots_listbox = tk.Listbox(slots_frame, height=10, font=('Helvetica', 12), selectmode=tk.SINGLE)
        self.slots_listbox.grid(row=0, column=0, sticky="nsew")
        slots_vsb = ttk.Scrollbar(slots_frame, orient="vertical", command=self.slots_listbox.yview)
        slots_vsb.grid(row=0, column=1, sticky="ns")
        self.slots_listbox.configure(yscrollcommand=slots_vsb.set)
        self.slots_listbox.bind('<<ListboxSelect>>', self.on_slot_select)

        self.no_slots_label = ttk.Label(slots_frame, text="Select Staff and Date to view available slots.",
                                        foreground="grey")
        self.no_slots_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        # --- Action Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        self.btn_book = ttk.Button(button_frame, text="Book Selected Slot", command=self.book_selected_appointment,
                                   state=tk.DISABLED)
        self.btn_book.pack(side=tk.RIGHT, padx=5)

        btn_cancel = ttk.Button(button_frame, text="Cancel", command=self.destroy)
        btn_cancel.pack(side=tk.RIGHT, padx=5)

    def load_staff_dropdown(self):
        """Populates the staff combobox."""
        staff_list = get_all_staff_for_selection()
        self.staff_dict = {}
        display_list = []
        if staff_list:
            for staff in staff_list:
                display_name = f"{staff['name']} (ID: {staff['staff_id']})"
                self.staff_dict[display_name] = staff['staff_id']
                display_list.append(display_name)
        self.combo_staff['values'] = display_list
        if display_list:
            self.selected_staff_var.set('')

    def selection_changed(self, event=None):
        """Called when staff or date selection changes."""
        logging.debug("--- selection_changed method triggered ---")  # Log entry
        try:
            staff_display = self.selected_staff_var.get()
            date_str = self.date_entry.get()
            logging.debug(f"  Selected Staff Display: '{staff_display}'")
            logging.debug(f"  Selected Date String: '{date_str}'")

            if staff_display and date_str:
                staff_id = self.staff_dict.get(staff_display)
                logging.debug(f"  Retrieved Staff ID: {staff_id}")  # Log retrieved ID
                if staff_id:
                    # Call show_available_slots only if we have valid selections
                    logging.debug(f"  Calling show_available_slots for Staff ID {staff_id}, Date {date_str}")
                    self.show_available_slots(staff_id, date_str)
                else:
                    logging.warning("  Could not find staff ID for selected display name. Clearing slots.")
                    self.clear_slots()
            else:
                # Staff or Date not selected yet
                logging.debug("  Staff or Date not yet selected. Clearing slots.")
                self.clear_slots()

        except Exception as e:
            # Catch any unexpected error within selection_changed
            logging.exception(f"ERROR inside selection_changed: {e}")
            messagebox.showerror("Error", f"An error occurred handling the selection change:\n{e}")
            self.clear_slots()  # Clear slots on error

        # Disable booking button until a time slot is selected (This should remain)
        self.btn_book.config(state=tk.DISABLED)
        self.selected_time_var.set("")  # Clear selected time
        logging.debug("--- selection_changed method finished ---")


    def clear_slots(self):
        """Clears the slots listbox and shows the helper message."""
        self.slots_listbox.delete(0, tk.END)
        self.available_slots_list = []
        self.no_slots_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER) # Show label


    def show_available_slots(self, staff_id, date_str):
        """Fetches booked times and displays available slots for staff/date."""
        logging.info(f"--- Running show_available_slots for Staff ID: {staff_id}, Date: {date_str} ---")
        self.clear_slots()

        try:
            selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()

            # --- Slot Logic Parameters ---
            start_hour = 9
            end_hour = 17 # Slots up to (but not including) 17:00
            slot_minutes_interval = 30 # Use a distinct variable name
            now = datetime.now()
            logging.debug(f"Current time ('now'): {now}")

            # --- Get Booked Times (Same as before) ---
            query = """
                SELECT time(appointment_datetime) as booked_start_time
                FROM Appointments
                WHERE staff_id = ? AND date(appointment_datetime) = date(?) AND status = 'Scheduled'
            """
            params = (staff_id, date_str)
            existing_appts_raw = execute_query(query, params, fetch_all=True)
            booked_start_times_hm = set()
            if existing_appts_raw:
                for appt in existing_appts_raw:
                    try:
                        time_obj = datetime.strptime(appt['booked_start_time'], '%H:%M:%S').time()
                        booked_start_times_hm.add(time_obj.strftime('%H:%M'))
                    except (ValueError, TypeError) as e: continue
            logging.debug(f"Booked 'Scheduled' times (HH:MM) for {date_str}: {booked_start_times_hm}")

            # --- Generate and Filter Slots (REVISED LOOP) ---
            available_slots = []
            logging.debug(f"Generating slots from {start_hour}:00 to {end_hour}:00 at {slot_minutes_interval} min intervals.")

            # Iterate through hours
            for hr in range(start_hour, end_hour):
                # Iterate through minutes based on the interval
                for mn in range(0, 60, slot_minutes_interval):
                    # Create the potential slot's time object
                    potential_slot_time = time(hour=hr, minute=mn)
                    # Combine with selected date to get the full datetime for comparison
                    potential_slot_dt = datetime.combine(selected_date, potential_slot_time)

                    slot_start_str_hm = potential_slot_dt.strftime('%H:%M')
                    logging.debug(f"  Checking Slot: {slot_start_str_hm} ({potential_slot_dt})")

                    # Condition 1: Is the slot already booked?
                    is_booked = slot_start_str_hm in booked_start_times_hm

                    # Condition 2: Is the slot start time in the past relative to now?
                    is_past = potential_slot_dt < now

                    # Log the checks
                    logging.debug(f"    Is Booked? {is_booked} (Checked against {booked_start_times_hm})")
                    logging.debug(f"    Is Past?   {is_past} (Slot Time {potential_slot_dt} < Now {now})")

                    # Add slot ONLY if it's NOT booked AND its start time is NOT in the past
                    if not is_booked and not is_past:
                        available_slots.append(slot_start_str_hm)
                        logging.debug(f"    -> Slot Added: {slot_start_str_hm}")
                    # else:
                    #     logging.debug(f"    -> Slot Skipped.")

            logging.debug(f"--- Slot Generation Finished ---")
            # --- End Slot Generation ---


            # --- Display Available Slots (Same as before) ---
            self.available_slots_list = available_slots
            if available_slots:
                 self.no_slots_label.place_forget()
                 self.slots_listbox.delete(0, tk.END)
                 for slot in available_slots:
                      self.slots_listbox.insert(tk.END, slot)
                 logging.info(f"Displaying {len(available_slots)} available slots: {available_slots}")
            else:
                 self.slots_listbox.delete(0, tk.END)
                 self.slots_listbox.insert(tk.END, " No available slots found for this selection.")
                 self.no_slots_label.place_forget()
                 logging.info("No available slots found for this selection after filtering.")
            # --- End Display ---

        except ValueError as ve:
            logging.error(f"Invalid date format provided: {date_str} - {ve}")
            messagebox.showerror("Error", f"Invalid date format: {date_str}. Please use YYYY-MM-DD.")
            self.clear_slots()
        except Exception as e:
            logging.exception(f"Error generating/showing available slots: {e}")
            messagebox.showerror("Error", "An unexpected error occurred while retrieving available slots.")
            self.clear_slots()


    def on_slot_select(self, event):
        """Enables the book button when a slot is selected."""
        selection_indices = self.slots_listbox.curselection()
        if selection_indices:
            selected_index = selection_indices[0]
            selected_slot = self.slots_listbox.get(selected_index)
            # Check if it's a real slot and not the "No slots" message
            if selected_slot in self.available_slots_list:
                self.selected_time_var.set(selected_slot)
                self.btn_book.config(state=tk.NORMAL)
                logging.debug(f"Time slot selected: {selected_slot}")
            else:
                 self.selected_time_var.set("")
                 self.btn_book.config(state=tk.DISABLED)
        else:
            self.selected_time_var.set("")
            self.btn_book.config(state=tk.DISABLED)


    def book_selected_appointment(self):
        """Books the appointment for the selected details."""
        staff_display = self.selected_staff_var.get()
        date_str = self.date_entry.get()
        time_str = self.selected_time_var.get()

        # Get IDs and final validation
        if not all([staff_display, date_str, time_str]):
            messagebox.showwarning("Incomplete Selection", "Please select Staff, Date, and Time Slot.")
            return

        staff_id = self.staff_dict.get(staff_display)
        if not staff_id:
            messagebox.showerror("Error", "Invalid staff selected.")
            return

        # Construct full datetime string for DB (add :00 for seconds)
        datetime_db_str = f"{date_str} {time_str}:00"
        logging.info(f"Attempting booking for Patient {self.patient_id}, Staff {staff_id}, DateTime {datetime_db_str}")

        # *** Basic Concurrency Check ***
        # Re-check if the slot was booked by someone else just now
        query_check = """
            SELECT 1 FROM Appointments
            WHERE staff_id = ? AND appointment_datetime = ?
        """
        params_check = (staff_id, datetime_db_str)
        existing = execute_query(query_check, params_check, fetch_one=True)
        if existing:
             logging.warning(f"Booking conflict detected for {datetime_db_str} with staff {staff_id}")
             messagebox.showwarning("Slot Taken", "Sorry, this time slot was just booked. Please select another.")
             # Refresh slots
             self.selection_changed()
             return

        # Proceed with booking
        query_insert = """
            INSERT INTO Appointments (patient_id, staff_id, appointment_datetime, status, reason)
            VALUES (?, ?, ?, ?, ?)
        """
        # Default reason to 'Patient Booking' or similar?
        params_insert = (self.patient_id, staff_id, datetime_db_str, 'Scheduled', 'Patient Booking')

        new_appt_id = execute_query(query_insert, params_insert, commit=True)

        if new_appt_id is not None:
            logging.info(f"Appointment booked successfully. ID: {new_appt_id}")

            # Send SMS Reminder (Triggered immediately after booking in this example)
            if self.patient_phone:
                 send_success = send_sms_reminder(
                     patient_phone_number=self.patient_phone,
                     patient_name=self.patient_name,
                     appointment_datetime_str=datetime_db_str,
                     staff_name=staff_display.split(" (ID:")[0] # Extract staff name
                 )
                 if send_success:
                     messagebox.showinfo("Booking Success", f"Appointment booked successfully for {time_str} on {date_str}.\nA reminder SMS has been sent.")
                 else:
                      # Show success but indicate SMS failure
                      messagebox.showwarning("Booking Success", f"Appointment booked successfully for {time_str} on {date_str}.\nHowever, the SMS reminder could not be sent.")
            else:
                 messagebox.showinfo("Booking Success", f"Appointment booked successfully for {time_str} on {date_str}.\n(No SMS sent as patient phone number is missing).")

            self.destroy() # Close the booking window

        else:
            logging.error(f"Failed to book appointment. DB Error: {ExecuteQueryState.last_error}")
            messagebox.showerror("Booking Failed", f"Failed to book appointment.\n{ExecuteQueryState.last_error or 'Database error'}")

# --- Admin Frame ---
# (No significant changes needed from previous version)
class AdminFrame(ttk.Frame):
    # ... (__init__, create_widgets, clear_content_frame, show_* methods remain the same) ...
    def __init__(self, master):
        super().__init__(master, padding="10")
        self.master = master
        logging.info("Initializing AdminFrame.")

        self.create_widgets()
        self.show_user_management_view() # Default view for Admin

    def create_widgets(self):
        """Creates the main layout and navigation for the admin view."""
        logging.debug("Creating widgets for AdminFrame.")
        top_frame = ttk.Frame(self)
        top_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 15))

        lbl_admin_info = ttk.Label(top_frame, text="Administrator Panel", font=("Helvetica", 16, "bold")) # Larger font
        lbl_admin_info.pack(side=tk.LEFT, padx=10, pady=5)

        btn_logout = ttk.Button(top_frame, text="Logout", command=self.master.logout)
        btn_logout.pack(side=tk.RIGHT, padx=10, pady=5)

        nav_frame = ttk.Frame(self, padding=(0, 10))
        nav_frame.pack(side=tk.TOP, fill=tk.X)

        btn_manage_users = ttk.Button(nav_frame, text="Manage User Logins", command=self.show_user_management_view)
        btn_manage_users.pack(side=tk.LEFT, padx=5)

        btn_manage_staff = ttk.Button(nav_frame, text="Manage Staff Details", command=self.show_staff_management_view)
        btn_manage_staff.pack(side=tk.LEFT, padx=5)

        btn_manage_patients = ttk.Button(nav_frame, text="Manage Patient Details", command=self.show_patient_management_view)
        btn_manage_patients.pack(side=tk.LEFT, padx=5)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(side=tk.TOP, fill=tk.X, pady=(5,10))

        self.content_frame = ttk.Frame(self)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

    def clear_content_frame(self):
        """Removes all widgets from the content frame."""
        logging.debug("Clearing content frame in AdminFrame.")
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    # --- View Switching Functions ---
    def show_user_management_view(self):
        logging.info("Admin switching to User Management view.")
        self.clear_content_frame()
        UserManagementViewAdmin(self.content_frame, self.master).pack(fill=tk.BOTH, expand=True)

    def show_staff_management_view(self):
        logging.info("Admin switching to Staff Details Management view.")
        self.clear_content_frame()
        StaffManagementViewAdmin(self.content_frame, self.master).pack(fill=tk.BOTH, expand=True)

    def show_patient_management_view(self):
        logging.info("Admin switching to Patient Details Management view.")
        self.clear_content_frame()
        # Pass None for staff_data to indicate Admin access
        admin_patient_view = PatientManagementView(self.content_frame, self.master, None)
        admin_patient_view.pack(fill=tk.BOTH, expand=True)

    # --- Placeholder calls ---
    def show_appointment_management_view(self):
         logging.info("Admin switching to Appointment Management view.")
         self.clear_content_frame()
         AppointmentManagementView(self.content_frame, self.master, None).pack(fill=tk.BOTH, expand=True)

    def show_treatment_management_view(self):
         logging.info("Admin switching to Treatment Management view.")
         self.clear_content_frame()
         TreatmentManagementView(self.content_frame, self.master, None).pack(fill=tk.BOTH, expand=True)

# --- Admin Sub-Views ---

# --- Staff Management View (Admin Only) ---
# (Incorporates previous changes + horizontal scrollbar)
class StaffManagementViewAdmin(ttk.Frame):
    """(Admin Only) Frame to view, add, edit staff *details* and create/link logins."""
    # ... (rest of StaffManagementViewAdmin class from previous version) ...
    # INCLUDING: __init__, create_widgets (with horizontal scrollbar),
    # load_staff_list, on_staff_select, clear_staff_form, add_staff,
    # update_staff, delete_staff
    def __init__(self, master, app_controller):
        super().__init__(master, padding="10")
        self.app_controller = app_controller
        self.selected_staff_id = None
        self.caller_context = "Admin" # Explicitly Admin context
        logging.debug(f"Initializing StaffManagementViewAdmin ({self.caller_context}).")

        # Variables for details/add form
        self.staff_entry_vars = {} # For staff details: Use StringVar for Entry, direct widget for Text
        self.add_staff_username = tk.StringVar()
        self.add_staff_password = tk.StringVar()

        self.create_widgets()
        self.load_staff_list()

    def create_widgets(self):
        logging.debug(f"Creating widgets for StaffManagementViewAdmin ({self.caller_context}).")
        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane: Staff List (No changes needed here) ---
        # ... (Staff List setup remains exactly the same, including Treeview + H/V scrollbars) ...
        list_frame = ttk.Frame(main_pane, padding="5")
        main_pane.add(list_frame, weight=1)
        list_frame.rowconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        lbl_list = ttk.Label(list_frame, text="Staff Members", font=("Helvetica", 14, "bold"))
        lbl_list.grid(row=0, column=0, columnspan=2, pady=(0, 10), sticky="w")
        staff_tree_frame = ttk.Frame(list_frame)
        staff_tree_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        staff_tree_frame.rowconfigure(0, weight=1)
        staff_tree_frame.columnconfigure(0, weight=1)
        cols = ('id', 'name', 'speciality', 'contact', 'username')
        self.tv_staff = ttk.Treeview(staff_tree_frame, columns=cols, show='headings', height=20)
        # ... headings/columns ...
        self.tv_staff.heading('id', text='ID'); self.tv_staff.column('id', width=50, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_staff.heading('name', text='Name'); self.tv_staff.column('name', width=170)
        self.tv_staff.heading('speciality', text='Speciality'); self.tv_staff.column('speciality', width=150)
        self.tv_staff.heading('contact', text='Contact'); self.tv_staff.column('contact', width=200)
        self.tv_staff.heading('username', text='Username'); self.tv_staff.column('username', width=130)
        self.tv_staff.grid(row=0, column=0, sticky="nsew")
        st_vsb = ttk.Scrollbar(staff_tree_frame, orient="vertical", command=self.tv_staff.yview)
        st_vsb.grid(row=0, column=1, sticky="ns")
        st_hsb = ttk.Scrollbar(staff_tree_frame, orient="horizontal", command=self.tv_staff.xview)
        st_hsb.grid(row=1, column=0, sticky="ew")
        self.tv_staff.configure(yscrollcommand=st_vsb.set, xscrollcommand=st_hsb.set)
        self.tv_staff.bind('<<TreeviewSelect>>', self.on_staff_select)
        list_btn_frame_staff = ttk.Frame(list_frame)
        list_btn_frame_staff.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        btn_refresh_staff = ttk.Button(list_btn_frame_staff, text="Refresh List", command=self.load_staff_list)
        btn_refresh_staff.pack(side=tk.LEFT, padx=5)


        # --- Right Pane: Scrollable Details / Add Form ---
        self.details_outer_frame = ttk.LabelFrame(main_pane, text="Staff Details / Add New", padding=(10,5)) # *** ADD self. ***
        main_pane.add(self.details_outer_frame, weight=2)
        self.details_outer_frame.rowconfigure(0, weight=1)
        self.details_outer_frame.columnconfigure(0, weight=1)

        # Canvas for scrolling
        canvas = tk.Canvas(self.details_outer_frame, borderwidth=0, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.details_outer_frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # *** Inner Frame ***
        self.staff_inner_details_frame = ttk.Frame(canvas, padding="15")
        self.canvas_frame_id = canvas.create_window((0, 0), window=self.staff_inner_details_frame, anchor="nw")
        self.staff_inner_details_frame.columnconfigure(1, weight=1)

        # --- Binding function to update scroll region ---
        def configure_scroll_region(event=None):
            bbox = canvas.bbox("all")
            logging.debug(f"Updating staff scrollregion: {bbox}")
            canvas.configure(scrollregion=bbox)
            canvas.itemconfig(self.canvas_frame_id, width=canvas.winfo_width())

        # --- Binding function for mouse wheel ---
        def on_mousewheel(event):
            scroll_amount = 0
            if event.num == 5 or event.delta < 0: scroll_amount = 1
            if event.num == 4 or event.delta > 0: scroll_amount = -1
            canvas.yview_scroll(scroll_amount, "units")

        # --- Bind events ---
        self.staff_inner_details_frame.bind("<Configure>", configure_scroll_region)
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
        # self.staff_inner_details_frame.bind("<MouseWheel>", on_mousewheel) # Optional fallback


        # --- Populate the staff_inner_details_frame with widgets ---
        row_idx = 0
        # Login Frame (Parent: staff_inner_details_frame)
        self.staff_login_details_frame = ttk.Frame(self.staff_inner_details_frame)
        self.staff_login_details_frame.grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=(0,15))
        self.staff_login_details_frame.columnconfigure(1, weight=1)
        # ... login widgets ...
        lbl_s_login_sec = ttk.Label(self.staff_login_details_frame, text="Login Credentials (for New Staff):", font=('Helvetica', 11, 'italic'))
        lbl_s_login_sec.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0,5))
        lbl_s_user = ttk.Label(self.staff_login_details_frame, text="Username:")
        lbl_s_user.grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.entry_add_staff_username = ttk.Entry(self.staff_login_details_frame, textvariable=self.add_staff_username, width=35)
        self.entry_add_staff_username.grid(row=1, column=1, padx=5, pady=2, sticky="ew")
        lbl_s_pass = ttk.Label(self.staff_login_details_frame, text="Password:")
        lbl_s_pass.grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.entry_add_staff_password = ttk.Entry(self.staff_login_details_frame, textvariable=self.add_staff_password, width=35, show="*")
        self.entry_add_staff_password.grid(row=2, column=1, padx=5, pady=2, sticky="ew")
        lbl_s_pass_req = ttk.Label(self.staff_login_details_frame, text="(Min 8 chars)", font=('Helvetica', 9))
        lbl_s_pass_req.grid(row=2, column=2, padx=(5,0), pady=2, sticky="w")
        row_idx += 1

        # Separator (Parent: staff_inner_details_frame)
        ttk.Separator(self.staff_inner_details_frame, orient=tk.HORIZONTAL).grid(row=row_idx, column=0, columnspan=3, sticky="ew", pady=(0, 15))
        row_idx += 1

        # Staff Detail Fields (Parent: staff_inner_details_frame)
        self.staff_entry_vars = {}

        name_var = tk.StringVar()
        self.staff_entry_vars["Staff Name:"] = name_var
        ttk.Label(self.staff_inner_details_frame, text="Staff Name:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        ttk.Entry(self.staff_inner_details_frame, textvariable=name_var, width=45).grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        row_idx += 1

        spec_var = tk.StringVar()
        self.staff_entry_vars["Speciality:"] = spec_var
        ttk.Label(self.staff_inner_details_frame, text="Speciality:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="w")
        ttk.Entry(self.staff_inner_details_frame, textvariable=spec_var, width=45).grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        row_idx += 1

        ttk.Label(self.staff_inner_details_frame, text="Contact Info:").grid(row=row_idx, column=0, padx=5, pady=6, sticky="nw")
        contact_frame = ttk.Frame(self.staff_inner_details_frame)
        contact_frame.grid(row=row_idx, column=1, columnspan=2, padx=5, pady=6, sticky="ew")
        contact_frame.columnconfigure(0, weight=1)
        contact_text = tk.Text(contact_frame, height=5, width=45, font=('Helvetica', 11), wrap="word", borderwidth=1, relief="sunken")
        contact_scroll = ttk.Scrollbar(contact_frame, orient="vertical", command=contact_text.yview)
        contact_text.configure(yscrollcommand=contact_scroll.set)
        contact_text.grid(row=0, column=0, sticky="ew")
        contact_scroll.grid(row=0, column=1, sticky="ns")
        self.staff_entry_vars["Contact Info:"] = contact_text
        # Bind mousewheel here if needed
        # contact_text.bind("<MouseWheel>", on_mousewheel, add='+')
        row_idx += 1

        # --- Buttons Frame --- (Parent: staff_inner_details_frame)
        s_btn_frame = ttk.Frame(self.staff_inner_details_frame)
        s_btn_frame.grid(row=row_idx, column=0, columnspan=3, pady=(25, 15))  # Add bottom padding
        # ... (pack buttons inside s_btn_frame as before) ...
        self.btn_add_staff = ttk.Button(s_btn_frame, text="Add Staff & Create Login", command=self.add_staff)
        self.btn_add_staff.pack(side=tk.LEFT, padx=5)
        self.btn_update_staff = ttk.Button(s_btn_frame, text="Update Details", command=self.update_staff,
                                           state=tk.DISABLED)
        self.btn_update_staff.pack(side=tk.LEFT, padx=5)
        self.btn_clear_staff = ttk.Button(s_btn_frame, text="Clear Form", command=self.clear_staff_form)
        self.btn_clear_staff.pack(side=tk.LEFT, padx=5)
        self.btn_delete_staff = ttk.Button(s_btn_frame, text="Delete Staff Record", command=self.delete_staff,
                                           state=tk.DISABLED)
        self.btn_delete_staff.pack(side=tk.LEFT, padx=10)

        self.after(10, lambda c=canvas, cf_id=self.canvas_frame_id: self._finish_scroll_setup(c, cf_id))

        # ** Force initial update and configure scroll region **
        self.staff_inner_details_frame.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.itemconfig(self.canvas_frame_id, width=canvas.winfo_width())

        def _finish_scroll_setup(self, canvas, canvas_frame_id):
            """Final setup for scroll region after widgets are drawn."""
            logging.debug(f"Running _finish_scroll_setup for {self.__class__.__name__}")
            try:
                self.staff_inner_details_frame.update_idletasks()
                bbox = canvas.bbox(tk.ALL)  # Or "all"
                if bbox:
                    logging.debug(f"  Final staff scrollregion bbox: {bbox}")
                    canvas.configure(scrollregion=bbox)
                    canvas.itemconfig(canvas_frame_id, width=canvas.winfo_width())
                    logging.debug(f"  Set staff scrollregion to {bbox}, canvas window width to {canvas.winfo_width()}")
                else:
                    logging.warning(
                        "  _finish_scroll_setup (Staff): Bbox calculation returned None. Scrollregion not set.")

                canvas.yview_moveto(0)  # Start scrolled to top

            except tk.TclError as e:
                logging.warning(
                    f"TclError during _finish_scroll_setup (Staff - likely window not ready yet): {e}. Retrying...")
                self.after(50, lambda c=canvas, cf_id=canvas_frame_id: self._finish_scroll_setup(c, cf_id))
            except Exception as e:
                logging.exception(f"Unexpected error during _finish_scroll_setup (Staff): {e}")


    def load_staff_list(self):
        """Fetches staff from DB and populates the Treeview."""
        logging.info(f"Loading staff list in StaffManagementViewAdmin ({self.caller_context}).")
        for item in self.tv_staff.get_children():
            self.tv_staff.delete(item)

        staff_list = get_all_staff() # Query now includes username
        if staff_list:
            logging.debug(f"Populating staff list with {len(staff_list)} records.")
            for staff in staff_list:
                self.tv_staff.insert('', tk.END, values=(
                    staff['staff_id'], staff['name'],
                    staff['speciality'] or 'N/A',
                    staff['contact_info'] or 'N/A',
                    staff['username'] or '(No Login)' # Display username or indicate if unlinked
                ))
        else:
            logging.info("No staff found in database.")
        self.clear_staff_form() # Resets form and buttons

    def on_staff_select(self, event):
        """Handles selection change in the staff list Treeview."""
        selected_items = self.tv_staff.selection()
        if not selected_items:
            logging.debug(f"Staff list selection cleared ({self.caller_context}).")
            self.clear_staff_form()
            return

        selected_item = selected_items[0]
        try:
             staff_id = int(self.tv_staff.item(selected_item)['values'][0])
        except (ValueError, IndexError):
            logging.error(f"Could not get valid staff ID from selected treeview item: {self.tv_staff.item(selected_item)['values']}")
            self.clear_staff_form()
            return

        logging.info(f"Staff selected: ID {staff_id} ({self.caller_context})")
        self.selected_staff_id = staff_id

        # --- Disable and clear login fields when editing ---
        self.entry_add_staff_username.config(state=tk.DISABLED)
        self.entry_add_staff_password.config(state=tk.DISABLED)
        self.add_staff_username.set("")
        self.add_staff_password.set("")
        # --- ---

        staff_details = execute_query("SELECT * FROM Staff WHERE staff_id = ?", (staff_id,), fetch_one=True)

        if staff_details:
            logging.debug(f"Loading details for staff ID: {staff_id}")
            self.staff_entry_vars["Staff Name:"].set(staff_details['name'] or '')
            self.staff_entry_vars["Speciality:"].set(staff_details['speciality'] or '')
            contact_widget = self.staff_entry_vars["Contact Info:"]
            contact_widget.delete('1.0', tk.END)
            contact_widget.insert('1.0', staff_details['contact_info'] or '')

            # --- Update form state for editing ---
            self.details_outer_frame.config(text=f"Details for Staff ID: {staff_id}") # Use outer_frame
            self.btn_update_staff.config(state=tk.NORMAL)
            self.btn_delete_staff.config(state=tk.NORMAL)
            self.btn_add_staff.config(state=tk.DISABLED) # Disable add when selected
            # --- ---
        else:
            logging.error(f"Could not fetch details for staff ID {staff_id} ({self.caller_context}).")
            messagebox.showerror("Error", f"Could not fetch details for selected staff ID {staff_id}")
            self.clear_staff_form()

    def clear_staff_form(self):
        """Clears all entry fields and resets buttons for the staff form."""
        logging.debug(f"Clearing staff details form ({self.caller_context}).")
        # Clear staff details
        for key, var_or_widget in self.staff_entry_vars.items():
             if isinstance(var_or_widget, tk.StringVar):
                 var_or_widget.set("")
             elif isinstance(var_or_widget, tk.Text):
                 var_or_widget.delete('1.0', tk.END)

        # Clear and ENABLE login fields
        self.add_staff_username.set("")
        self.add_staff_password.set("")
        self.entry_add_staff_username.config(state=tk.NORMAL)
        self.entry_add_staff_password.config(state=tk.NORMAL)

        # Reset selection and buttons
        if self.tv_staff.selection():
            self.tv_staff.selection_remove(self.tv_staff.selection())
        self.selected_staff_id = None
        self.details_outer_frame.config(text="Staff Details / Add New") # Use outer_frame
        self.btn_update_staff.config(state=tk.DISABLED)
        self.btn_delete_staff.config(state=tk.DISABLED)
        self.btn_add_staff.config(state=tk.NORMAL)

    def add_staff(self):
        """(Admin Only) Adds a new staff record AND creates a corresponding user login."""
        logging.info(f"Attempting to add new staff record and create login ({self.caller_context}).")

        # 1. Get Login Credentials
        username = self.add_staff_username.get().strip()
        password = self.add_staff_password.get()
        role = "Staff" # Fixed role

        # 2. Get Staff Details
        name = self.staff_entry_vars["Staff Name:"].get().strip()
        speciality = self.staff_entry_vars["Speciality:"].get().strip() or None
        contact_info = self.staff_entry_vars["Contact Info:"].get("1.0", tk.END).strip() or None

        # 3. Validation (same as before)
        if not username or not password:
            messagebox.showwarning("Missing Information", "Username and Password are required to create staff login.")
            return
        if len(password) < 8:
             messagebox.showwarning("Input Error", "Password should be at least 8 characters long.")
             return
        if check_username_exists(username):
            messagebox.showwarning("Input Error", f"Username '{username}' already exists. Choose another.")
            return
        if not name:
            messagebox.showwarning("Missing Information", "Staff Name is required.")
            return

        # 4. Database Operations (same logic as before)
        new_user_id = None
        new_staff_id = None
        try:
            hashed_password = hash_password(password)
            user_query = "INSERT INTO Users (username, password, role) VALUES (?, ?, ?)"
            new_user_id = execute_query(user_query, (username, hashed_password, role), commit=True)

            if new_user_id is None or ExecuteQueryState.last_error:
                err_msg = f"Failed to insert new user '{username}'"
                db_err = ExecuteQueryState.last_error if ExecuteQueryState.last_error else "Unknown DB error"
                messagebox.showerror("Database Error", f"{err_msg}\n{db_err}")
                return

            logging.info(f"User login created for '{username}'. User ID: {new_user_id}")

            staff_query = "INSERT INTO Staff (user_id, name, speciality, contact_info) VALUES (?, ?, ?, ?)"
            staff_params = (new_user_id, name, speciality, contact_info)
            new_staff_id = execute_query(staff_query, staff_params, commit=True)

            if new_staff_id is None or ExecuteQueryState.last_error:
                err_msg = f"CRITICAL: User {new_user_id} ('{username}') created, but failed to insert staff record!"
                logging.critical(err_msg)
                cleanup_success = execute_query("DELETE FROM Users WHERE user_id = ?", (new_user_id,), commit=True)
                logging.warning(f"Attempted cleanup of orphaned user {new_user_id}. Success: {cleanup_success is not None}")
                db_err = ExecuteQueryState.last_error if ExecuteQueryState.last_error else "Unknown DB error"
                messagebox.showerror("Critical Database Error", f"{err_msg}\nPlease contact administrator.\n{db_err}")
                return  # Stop execution

            logging.info(f"Staff record created for '{name}'. Staff ID: {new_staff_id}, Linked to User ID: {new_user_id}")
            messagebox.showinfo("Success", f"Staff member '{name}' registered with login '{username}' successfully (Staff ID: {new_staff_id}).")
            self.load_staff_list() # Refresh list and clear form

        except Exception as e:
            logging.exception(f"Unexpected error during staff registration for '{username}': {e}")
            messagebox.showerror("Application Error", f"An unexpected error occurred during registration: {e}")

    def update_staff(self):
        """(Admin Only) Updates the selected staff member's *details* record."""
        if not self.selected_staff_id: # Guard clause
            messagebox.showwarning("No Selection", "Please select a staff member to update.")
            return

        logging.info(f"Attempting to update staff details ID: {self.selected_staff_id} ({self.caller_context})")
        # Get details from form (same as before)
        name = self.staff_entry_vars["Staff Name:"].get().strip()
        speciality = self.staff_entry_vars["Speciality:"].get().strip() or None
        contact_info = self.staff_entry_vars["Contact Info:"].get("1.0", tk.END).strip() or None


        if not name: # Validation
            messagebox.showwarning("Missing Information", "Staff Name cannot be empty.")
            return

        try:
            staff_query = "UPDATE Staff SET name = ?, speciality = ?, contact_info = ? WHERE staff_id = ?"
            staff_params = (name, speciality, contact_info, self.selected_staff_id)
            update_success = execute_query(staff_query, staff_params, commit=True)

            if not update_success and ExecuteQueryState.last_error:
                 raise ExecuteQueryState.last_error

            logging.info(f"Staff details ID {self.selected_staff_id} updated.")
            messagebox.showinfo("Success", f"Staff details updated.")
            self.load_staff_list()

            # Re-select the updated staff member (same logic as patient view)
            for item in self.tv_staff.get_children():
                 try:
                     current_id = int(self.tv_staff.item(item)['values'][0])
                     if current_id == self.selected_staff_id:
                         self.tv_staff.selection_set(item)
                         self.tv_staff.focus(item)
                         self.entry_add_staff_username.config(state=tk.DISABLED) # Keep disabled
                         self.entry_add_staff_password.config(state=tk.DISABLED)
                         break
                 except (ValueError, IndexError):
                     continue

        except sqlite3.Error as e:
            logging.error(f"Database error during staff detail update ID {self.selected_staff_id}: {e}")
            messagebox.showerror("Database Error", f"Failed to update staff details: {e}")
        except Exception as e:
             logging.exception(f"Unexpected error during staff detail update ID {self.selected_staff_id}: {e}")
             messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")


    def delete_staff(self):
        """(Admin Only) Deletes the selected staff *record* (handling FKs). DOES NOT delete the user login."""
        if not self.selected_staff_id: # Guard clause
            messagebox.showwarning("No Selection", "Please select a staff record to delete.")
            return

        # Get name for confirmation... (same as before)
        try:
             selected_item = self.tv_staff.selection()[0]
             staff_name = self.tv_staff.item(selected_item)['values'][1]
        except IndexError:
             staff_name = f"ID {self.selected_staff_id}" # Fallback

        logging.warning(f"Admin attempting to delete staff RECORD ID: {self.selected_staff_id}, Name: {staff_name}")

        # Fetch linked user info for warning... (same as before)
        linked_user_info = execute_query("SELECT user_id, username FROM Users WHERE user_id = (SELECT user_id FROM Staff WHERE staff_id = ?)", (self.selected_staff_id,), fetch_one=True)

        confirm_msg = (f"Are you sure you want to permanently delete the staff record for '{staff_name}' (ID: {self.selected_staff_id})?\n\n"
                       "--- WARNING ---\n"
                       "This action may affect historical records:\n"
                       "  - Recommending staff on Treatments will be set to NULL.\n"
                       "  - Appointments with this staff member will be DELETED (CASCADE).\n\n")

        if linked_user_info:
             confirm_msg += f"The user login ('{linked_user_info['username']}', ID: {linked_user_info['user_id']}) will become UNLINKED but **will NOT be deleted**.\n"
             confirm_msg += "Delete the login separately via 'Manage User Logins' if required."
        else:
             confirm_msg += "This staff record does not appear to have a linked user login."

        if messagebox.askyesno("Confirm Staff Record Deletion", confirm_msg):
            try:
                query = "DELETE FROM Staff WHERE staff_id = ?"
                delete_success = execute_query(query, (self.selected_staff_id,), commit=True)

                if not delete_success and ExecuteQueryState.last_error:
                     raise ExecuteQueryState.last_error

                logging.info(f"Staff record ID {self.selected_staff_id} deleted successfully by Admin.")
                messagebox.showinfo("Record Deleted", f"Staff record ID {self.selected_staff_id} ('{staff_name}') deleted.")
                self.load_staff_list() # Refreshes list and clears form

            except sqlite3.Error as e:
                logging.error(f"Database error during staff record deletion for ID {self.selected_staff_id}: {e}")
                messagebox.showerror("Database Error", f"Failed to delete staff record: {e}")
            except Exception as e:
                logging.exception(f"Unexpected error during staff record deletion for ID {self.selected_staff_id}: {e}")
                messagebox.showerror("Application Error", f"An unexpected error occurred: {e}")
        else:
            logging.info(f"Deletion cancelled for staff record ID: {self.selected_staff_id}")

# --- User Management View (Admin Only) ---
# (Incorporates previous changes + horizontal scrollbar + Reset Password button)
class UserManagementViewAdmin(ttk.Frame):
    """(Admin Only) Frame to manage *EXISTING* user login accounts."""
    def __init__(self, master, app_controller):
        super().__init__(master, padding="10")
        self.app_controller = app_controller
        self.selected_user_id = None
        self.caller_context = "Admin"
        logging.debug(f"Initializing UserManagementViewAdmin ({self.caller_context} - View/Delete Logins Only).")

        # NO registration variables needed here

        self.create_widgets()
        self.load_user_list()

    def create_widgets(self):
        logging.debug(f"Creating widgets for UserManagementViewAdmin ({self.caller_context}).")
        self.pack(fill=tk.BOTH, expand=True) # Frame fills content area

        # --- User List Frame ---
        list_frame = ttk.LabelFrame(self, text="Manage Existing User Logins", padding="15")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        list_frame.rowconfigure(1, weight=1) # Treeview frame row expands
        list_frame.columnconfigure(0, weight=1) # Treeview frame col expands

        # --- Treeview Frame for Users ---
        user_tree_frame = ttk.Frame(list_frame)
        user_tree_frame.grid(row=1, column=0, columnspan=3, sticky="nsew") # Span 3 for buttons later
        user_tree_frame.rowconfigure(0, weight=1)
        user_tree_frame.columnconfigure(0, weight=1)

        # Note: No password column here due to security. Admin should reset, not view.
        cols = ('user_id', 'username', 'role', 'linked_name', 'linked_id')
        self.tv_users = ttk.Treeview(user_tree_frame, columns=cols, show='headings', height=25)
        self.tv_users.heading('user_id', text='User ID')
        self.tv_users.heading('username', text='Username')
        self.tv_users.heading('role', text='Role')
        self.tv_users.heading('linked_name', text='Linked Profile Name') # Name from Patient/Staff table
        self.tv_users.heading('linked_id', text='Linked Profile ID') # Patient ID or Staff ID
        self.tv_users.column('user_id', width=70, anchor=tk.CENTER, stretch=tk.NO)
        self.tv_users.column('username', width=180)
        self.tv_users.column('role', width=100)
        self.tv_users.column('linked_name', width=250)
        self.tv_users.column('linked_id', width=120, anchor=tk.CENTER)
        self.tv_users.grid(row=0, column=0, sticky="nsew")

        # Vertical Scrollbar
        user_vsb = ttk.Scrollbar(user_tree_frame, orient="vertical", command=self.tv_users.yview)
        user_vsb.grid(row=0, column=1, sticky="ns")
        self.tv_users.configure(yscrollcommand=user_vsb.set)

        # *** Horizontal Scrollbar ***
        user_hsb = ttk.Scrollbar(user_tree_frame, orient="horizontal", command=self.tv_users.xview)
        user_hsb.grid(row=1, column=0, sticky="ew")
        self.tv_users.configure(xscrollcommand=user_hsb.set)

        self.tv_users.bind('<<TreeviewSelect>>', self.on_user_select)

        # Buttons below scrollbars
        list_btn_frame = ttk.Frame(list_frame)
        list_btn_frame.grid(row=2, column=0, columnspan=3, pady=(15,0)) # Span 3, more space above

        btn_refresh = ttk.Button(list_btn_frame, text="Refresh List", command=self.load_user_list)
        btn_refresh.pack(side=tk.LEFT, padx=10)

        # Placeholder Button for future "Edit Login" (e.g., change role carefully)
        # self.btn_edit_user = ttk.Button(list_btn_frame, text="Edit Login", command=self.edit_user, state=tk.DISABLED)
        # self.btn_edit_user.pack(side=tk.LEFT, padx=10)

        # *** Reset Password Button (Placeholder) ***
        self.btn_reset_password = ttk.Button(list_btn_frame, text="Reset Password", command=self.reset_password, state=tk.DISABLED)
        self.btn_reset_password.pack(side=tk.LEFT, padx=10)

        self.btn_delete_user = ttk.Button(list_btn_frame, text="Delete Login", command=self.delete_user, state=tk.DISABLED)
        self.btn_delete_user.pack(side=tk.LEFT, padx=10)

    def load_user_list(self):
        """Fetches users from DB and populates the Treeview."""
        logging.info(f"Loading user list in UserManagementViewAdmin ({self.caller_context}).")
        for item in self.tv_users.get_children():
            self.tv_users.delete(item)

        users = get_all_users() # Query gets linked profile info
        if users:
            logging.debug(f"Populating user list with {len(users)} records.")
            for user in users:
                # Ensure N/A is shown correctly for None values or empty strings
                linked_name = user['linked_name'] if user['linked_name'] else 'N/A'
                linked_id = user['linked_profile_id'] if user['linked_profile_id'] is not None else 'N/A' # Check None specifically for ID
                self.tv_users.insert('', tk.END, values=(
                    user['user_id'], user['username'], user['role'],
                    linked_name, linked_id
                ))
        else:
            logging.info("No users found in database.")
        self.clear_selection()

    def on_user_select(self, event):
        """Handles selection change in the user list Treeview."""
        selected_items = self.tv_users.selection()
        if not selected_items:
            logging.debug(f"User list selection cleared ({self.caller_context}).")
            self.clear_selection()
            return

        selected_item = selected_items[0]
        try:
            user_id = int(self.tv_users.item(selected_item)['values'][0])
            username = self.tv_users.item(selected_item)['values'][1]
        except (ValueError, IndexError, TypeError):
             logging.error(f"Could not get valid user ID/username from selected item: {self.tv_users.item(selected_item)}")
             self.clear_selection()
             return

        logging.info(f"User selected: ID {user_id}, Username: {username} ({self.caller_context})")
        self.selected_user_id = user_id
        # self.btn_edit_user.config(state=tk.NORMAL) # Enable when edit is implemented

        # Enable Delete and Reset Password buttons, EXCEPT for the admin user itself
        if username == 'admin':
             self.btn_delete_user.config(state=tk.DISABLED)
             self.btn_reset_password.config(state=tk.DISABLED)
             logging.debug("Delete/Reset Password buttons disabled for admin user.")
        else:
             self.btn_delete_user.config(state=tk.NORMAL)
             self.btn_reset_password.config(state=tk.NORMAL)

    def clear_selection(self):
        """Clears selection and disables context-sensitive buttons."""
        logging.debug(f"Clearing user selection ({self.caller_context}).")
        if self.tv_users.selection():
            self.tv_users.selection_remove(self.tv_users.selection())
        self.selected_user_id = None
        # self.btn_edit_user.config(state=tk.DISABLED) # Disable when edit implemented
        self.btn_delete_user.config(state=tk.DISABLED)
        self.btn_reset_password.config(state=tk.DISABLED)

    def edit_user(self):
        """Placeholder for editing selected user login (e.g., change role)."""
        # Kept as placeholder, no functionality added here.
        if not self.selected_user_id:
             messagebox.showwarning("Action Required", "Select user login to edit.")
             return
        logging.warning(f"Edit user login function (ID: {self.selected_user_id}) not implemented.")
        messagebox.showinfo("Not Implemented", f"Editing login ID {self.selected_user_id} not implemented.")

    def reset_password(self):
        """Placeholder for Admin resetting a user's password."""
        if not self.selected_user_id:
            logging.warning(f"Reset Password attempt failed: No user selected ({self.caller_context}).")
            messagebox.showwarning("Action Required", "Please select a user login to reset their password.")
            return

        # Get username for confirmation
        try:
            selected_item = self.tv_users.selection()[0]
            username = self.tv_users.item(selected_item)['values'][1]
        except (IndexError, TypeError):
            messagebox.showerror("Error", "Cannot identify selected user.")
            return

        if username == 'admin':
            messagebox.showerror("Action Denied", "Cannot reset password for the 'admin' user via this interface.")
            return

        # *** SECURITY NOTE ***
        # This is where a secure password reset flow would be triggered.
        # This could involve:
        # 1. Generating a strong temporary password.
        # 2. Hashing the temporary password.
        # 3. Updating the user's password hash in the database.
        # 4. Displaying the temporary password to the Admin ONLY ONCE, or preferably,
        #    implementing a way for the user to set a new password themselves (e.g., email link - complex).
        # For now, it's just a placeholder.
        logging.warning(f"Admin triggered password reset placeholder for user ID: {self.selected_user_id}, Username: {username}")
        messagebox.showinfo("Not Implemented", f"Password reset functionality for user '{username}' (ID: {self.selected_user_id}) is not yet implemented.\n\nA real implementation would securely set a new temporary password.")


    def delete_user(self):
        """(Admin Only) Deletes the selected user *login*. DOES NOT delete linked profiles."""
        # This method remains largely the same, focusing on deleting from the Users table.
        if not self.selected_user_id: # Guard
            messagebox.showwarning("Action Required", "Select user login to delete.")
            return

        # Get details for confirmation
        try:
            selected_item = self.tv_users.selection()[0]
            username = self.tv_users.item(selected_item)['values'][1]
            role = self.tv_users.item(selected_item)['values'][2]
            linked_name = self.tv_users.item(selected_item)['values'][3]
        except (IndexError, TypeError):
            messagebox.showerror("Error", "Cannot retrieve details for selected user.")
            return

        if username == 'admin': # Prevent deleting admin
            messagebox.showerror("Action Denied", "Cannot delete the default 'admin' user login.")
            return

        logging.warning(f"Admin attempting delete user LOGIN ID: {self.selected_user_id}, Username: {username}, Role: {role}")

        confirm_msg = f"Are you sure you want to permanently delete the user login for '{username}' (ID: {self.selected_user_id})?"
        # Add clarification about unlinking
        if linked_name != 'N/A':
             confirm_msg += f"\n\nNote: This removes the login ONLY. The associated {role} profile ('{linked_name}') will be unlinked but NOT deleted."
             confirm_msg += f"\nDelete the profile separately from 'Manage {role} Details' if required."
        else:
             confirm_msg += "\n\nNote: This login does not appear linked to an active profile record."

        if messagebox.askyesno("Confirm Login Deletion", confirm_msg):
            try:
                # ON DELETE SET NULL in Patients/Staff handles unlinking. Delete user record.
                query = "DELETE FROM Users WHERE user_id = ?"
                delete_success = execute_query(query, (self.selected_user_id,), commit=True)

                if not delete_success and ExecuteQueryState.last_error:
                     raise ExecuteQueryState.last_error

                logging.info(f"User login ID {self.selected_user_id} ('{username}') deleted.")
                messagebox.showinfo("Deletion Success", f"User login for '{username}' deleted.")
                self.load_user_list() # Refresh

            except sqlite3.Error as e:
                logging.error(f"Database error during user login deletion ID {self.selected_user_id}: {e}")
                messagebox.showerror("Database Error", f"Failed to delete user login: {e}")
            except Exception as e:
                logging.exception(f"Unexpected error during user login deletion ID {self.selected_user_id}: {e}")
                messagebox.showerror("Application Error", f"Unexpected error: {e}")
        else:
            logging.info(f"Deletion cancelled for user login ID: {self.selected_user_id}")


# --- Main Execution ---
# (No changes needed from previous version)
if __name__ == "__main__":
    try:
        initialize_database()
        app = HealthcareApp()
        app.mainloop()
    except Exception as e:
        logging.critical(f"Unhandled exception during application startup or main loop: {e}", exc_info=True)
        try:
            # Attempt to show fatal error message
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", f"A critical error occurred: {e}\n\nPlease check the log file ({LOG_FILE}) for details.")
            root.destroy()
        except Exception as msg_e:
             print(f"CRITICAL ERROR: {e}. Also failed showing messagebox: {msg_e}. Check logs: {LOG_FILE}")
    finally:
        logging.info("Application has finished.")

# --- END OF FILE App v1.py ---