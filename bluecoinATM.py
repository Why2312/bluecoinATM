vers = '1.7.8'
import time
import PySimpleGUI as sg
import threading
from threading import Thread, Event, Lock
import urllib3
import json
import os
import subprocess
import ctypes
import signal
import importlib
import base64
import sys
import platform
import encryptlib
import requests
from collections import deque
from types import SimpleNamespace
# Create appdata locallow folder
if not os.path.exists(os.path.join(os.getenv('APPDATA'), "BluecoinATM")):
    os.mkdir(os.path.join(os.getenv('APPDATA'), "BluecoinATM"))
# Create logs folder
if not os.path.exists(os.path.join(os.getenv('APPDATA'), "BluecoinATM", "logs")):
    os.mkdir(os.path.join(os.getenv('APPDATA'), "BluecoinATM", "logs"))

# Does mods folder exist? (current folder mods)
if not os.path.exists("./mods"):
    # If it does not, then create it
    os.mkdir("./mods")

def is_older_or_equal(version_str, target_str):
    version = parse_version(version_str)
    target_version = parse_version(target_str)
    return version <= target_version 

request_lock = threading.Lock()
oldprint = print

def parse_version(version_str):
    try:
        major, minor, patch = version_str.split('.')
        return int(major), int(minor), int(patch)
    except ValueError:
        raise ValueError("Invalid version format. Expected format: major.minor.patch")

default_ui_settings = {
    "Normal": {
        "Font": ("Helvetica", 17),
    },
    "Title": {
        "Font": ("Helvetica", 30),
    }
}


def print(*args, **kwargs):
    # Debugger print, which prints to a file, with somewhat full support of print() arguments
    # Get the date and time
    date = time.strftime("%d-%m-%Y")
    time_ = time.strftime("%H:%M:%S")
    # Open the log file
    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", "logs", f"{date}.log"), "a") as file:
        # Write the date and time
        file.write(f"[{date} {time_}] ")
        # Write the arguments
        file.write(str(args))
        # Write the keyword arguments
        file.write(str(kwargs))
        # Write a newline
        file.write("\n")
def debounce(wait):
    """ Decorator that ensures only the most recent function call in order
        is executed after a `wait` period, with any calls made in the meantime dropped. """
    def decorator(fn):
        last_call_time = 0
        call_queue = deque()
        call_event = Event()
        lock = Lock()

        def call_latest():
            nonlocal last_call_time
            while True:
                call_event.wait()  # Wait until a new call is queued
                with lock:
                    # Retrieve the most recent call
                    _, args, kwargs = call_queue[-1]  
                    call_queue.clear()  # Clear the queue since we only need the latest call
                    call_event.clear()

                # Ensure the wait time has elapsed since the last call
                wait_time = last_call_time + wait - time.time()
                if wait_time > 0:
                    time.sleep(wait_time)

                last_call_time = time.time()
                fn(*args, **kwargs)  # Call the function with the latest arguments

        # Start the thread that will execute the function calls
        Thread(target=call_latest, daemon=True).start()

        def debounced(*args, **kwargs):
            with lock:
                # Add the new call to the queue
                call_queue.append((time.time(), args, kwargs))
                call_event.set()  # Signal that a new call is queued

        return debounced

    return decorator
# Create an sg animated popup till we load everything
if os.name == "nt":
    whnd = ctypes.windll.kernel32.GetConsoleWindow()
    # Check if the script is running in a console window or not
    if whnd != 0:
        # If it is, hide the console
        ctypes.windll.user32.ShowWindow(whnd, 0)
else:
    # if it is not windows, then it is probably linux, so we dont do anything
    pass
enc = encryptlib.HWIDBasedEncryption()
settings = None
# Open settings.json
print(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'settings.json'))
if os.path.exists(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'settings.json')):
    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'settings.json'), 'r') as file:
        # Decode the JSON
        settings = json.load(file)
        # Try to do mitigation for old settings.json files
        version = settings.get("Version")
        if version != vers:
            # Older or is 1.7.5?
            if is_older_or_equal(version, "1.7.5"):
                # Then we need to update it
                settings["Theme"] = "DarkBlack"
                settings["ShareData"] = True
                settings["Version"] = vers
                
        
else:
    settings = {}


# Initialize urllib3 pool manager
http = urllib3.PoolManager()

# Does users.json exist?
if not os.path.exists(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json')):
    # Create it
    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json'), 'w') as file:
        json.dump({}, file)



def init_settings(settings):
    # Set default values for missing keys
    defaults = {
        'Theme': 'DarkBlack',  # Default theme
        'ShareData': True,  # Default for sharing data
        'Version': vers
    }

    settings_changed = False

    for key, default_value in defaults.items():
        if settings.get(key) is None:
            settings[key] = default_value
            settings_changed = True

    # Save the settings if they were changed
    if settings_changed:
        settings_file_path = os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'settings.json')
        with open(settings_file_path, 'w') as file:
            json.dump(settings, file)

init_settings(settings)
# Is the version different?
if settings["Version"] != vers:
    # If it is, then update it
    settings["Version"] = vers
    # Save the settings
    settings_file_path = os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'settings.json')
    with open(settings_file_path, 'w') as file:
        json.dump(settings, file)
            
theme = settings['Theme']
share_data = settings['ShareData']
sg.theme(theme)
sg.set_options(font=default_ui_settings["Normal"]["Font"])


# Function to save user credentials
def save_user(username, password):

    if os.path.exists('users.json'):
        with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json'), 'r') as file:
            users = json.load(file)
    else:
        users = {}

    encrypted_password = enc.encrypt(password)
    # Convert bytes to a string using Base64
    encrypted_password_str = base64.b64encode(encrypted_password).decode('utf-8')

    users[username] = encrypted_password_str

    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json'), 'w') as file:
        json.dump(users, file)

def update_user(username, password):
    # Load the users
    users = load_users()
    # Update the password
    encrypted_password = enc.encrypt(password)
    # Convert bytes to a string using Base64
    encrypted_password_str = base64.b64encode(encrypted_password).decode('utf-8')
    users[username] = encrypted_password_str
    # Save the users
    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json'), 'w') as file:
        json.dump(users, file)
        

def save_user_list(users):
    newusers = {}
    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json'), 'w') as file:
        for user,password in users.items():
            encrypted_password = enc.encrypt(password)
            # Convert bytes to a string using Base64
            encrypted_password_str = base64.b64encode(encrypted_password).decode('utf-8')
            newusers[user] = encrypted_password_str
        json.dump(newusers, file)

def load_users():

    if not os.path.exists(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json')):
        return {}

    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM",'users.json'), 'r') as file:
        encrypted_users = json.load(file)

    decrypted_users = {}
    for user, password_str in encrypted_users.items():
        # Convert string back to bytes
        encrypted_password = base64.b64decode(password_str)
        decrypted_password = enc.decrypt(encrypted_password)
        decrypted_users[user] = decrypted_password

    return decrypted_users

# Function to send a request
def send_request(url, method, username, password, receiver=None, amount=None, new_password=None):
    data = {"Method": method, "Username": username, "Password": password}
    if receiver:
        data["ReceivingUser"] = receiver
    if amount:
        data["Amount"] = amount
    if new_password:
        data["NewPassword"] = new_password

    encoded_data = json.dumps(data).encode('utf-8')
    # Set content type and our useragent
    if settings["ShareData"]:  
        headers = {'Content-Type': 'application/json', 'User-Agent': f"BluecoinATM | {settings['Version']}, {platform.system()} {platform.release()} {platform.machine()}, USER {username}"}
    else:
        headers = {'Content-Type': 'application/json', 'User-Agent': f"BluecoinATM | {settings['Version']}, ANONYMOUS USER"}
    print("[INFO] REQUEST: ",headers, method)
    response = http.request('POST', url, body=encoded_data, headers=headers)
    return response.data.decode('utf-8')

global additional_layout

additional_layout = {}
theme_list = ['Black', 'BlueMono', 'BluePurple', 'BrightColors', 'BrownBlue', 'Dark', 'Dark2', 'DarkAmber', 'DarkBlack', 'DarkBlack1', 'DarkBlue', 'DarkBlue1', 'DarkBlue10', 'DarkBlue11', 'DarkBlue12', 'DarkBlue13', 'DarkBlue14', 'DarkBlue15', 'DarkBlue16', 'DarkBlue17', 'DarkBlue2', 'DarkBlue3', 'DarkBlue4', 'DarkBlue5', 'DarkBlue6', 'DarkBlue7', 'DarkBlue8', 'DarkBlue9', 'DarkBrown', 'DarkBrown1', 'DarkBrown2', 'DarkBrown3', 'DarkBrown4', 'DarkBrown5', 'DarkBrown6', 'DarkGreen', 'DarkGreen1', 'DarkGreen2', 'DarkGreen3', 'DarkGreen4', 'DarkGreen5', 'DarkGreen6', 'DarkGrey', 'DarkGrey1', 'DarkGrey2', 'DarkGrey3', 'DarkGrey4', 'DarkGrey5', 'DarkGrey6', 'DarkGrey7', 'DarkPurple', 'DarkPurple1', 'DarkPurple2', 'DarkPurple3', 'DarkPurple4', 'DarkPurple5', 'DarkPurple6', 'DarkRed', 'DarkRed1', 'DarkRed2', 'DarkTanBlue', 'DarkTeal', 'DarkTeal1', 'DarkTeal10', 'DarkTeal11', 'DarkTeal12', 'DarkTeal2', 'DarkTeal3', 'DarkTeal4', 'DarkTeal5', 'DarkTeal6', 'DarkTeal7', 'DarkTeal8', 'DarkTeal9', 'Default', 'Default1', 'DefaultNoMoreNagging', 'Green', 'GreenMono', 'GreenTan', 'HotDogStand', 'Kayak', 'LightBlue', 'LightBlue1', 'LightBlue2', 'LightBlue3', 'LightBlue4', 'LightBlue5', 'LightBlue6', 'LightBlue7', 'LightBrown', 'LightBrown1', 'LightBrown10', 'LightBrown11', 'LightBrown12', 'LightBrown13', 'LightBrown2', 'LightBrown3', 'LightBrown4', 'LightBrown5', 'LightBrown6', 'LightBrown7', 'LightBrown8', 'LightBrown9', 'LightGray1', 'LightGreen', 'LightGreen1', 'LightGreen10', 'LightGreen2', 'LightGreen3', 'LightGreen4', 'LightGreen5', 'LightGreen6', 'LightGreen7', 'LightGreen8', 'LightGreen9', 'LightGrey', 'LightGrey1', 'LightGrey2', 'LightGrey3', 'LightGrey4', 'LightGrey5', 'LightGrey6', 'LightPurple', 'LightTeal', 'LightYellow', 'Material1', 'Material2', 'NeutralBlue', 'Purple', 'Reddit', 'Reds', 'SandyBeach', 'SystemDefault', 'SystemDefault1', 'SystemDefaultForReal', 'Tan', 'TanBlue', 'TealMono', 'Topanga']
global runonuicreation
runonuicreation = []

def save_settings():
    global settings
    with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'settings.json'), 'w') as file:
        json.dump(settings, file)

def add_layout(name, layout):
    global additional_layout
    additional_layout[name] = layout
    
def remove_layout(name):
    global additional_layout
    additional_layout.pop(name)

def modify_layout(name, idx, layout):
    global additional_layout
    additional_layout[name][idx] = layout

def modify_layout_element(name, idx, element, value):
    global additional_layout
    additional_layout[name][idx][element] = value

# Function to create the main window
def create_main_window():
    login_layout = [
        [sg.Text('', expand_x=True),sg.Text("Login", font=default_ui_settings["Title"]["Font"], justification="center"), sg.Text('', expand_x=True)],
        [sg.Text("Username"), sg.InputText(key='Username')],
        [sg.Text("Password"), sg.InputText(key='Password', password_char='●')],
        [sg.Button("Select new user")]
    ]

    # Layout for Signup Tab
    signup_layout = [
        [sg.Text('', expand_x=True),sg.Text("Signup", font=default_ui_settings["Title"]["Font"], justification="center"), sg.Text('', expand_x=True)],
        [sg.Text("Username"), sg.InputText(key='Signup_Username')],
        [sg.Text("Password"), sg.InputText(key='Signup_Password', password_char='●')],
        [sg.Button("Signup")]
    ]

    # Layout for Transaction Tab
    transaction_layout = [
        [sg.Text('', expand_x=True),sg.Text("Transactions", font=default_ui_settings["Title"]["Font"], justification="center"), sg.Text('', expand_x=True)],
        [sg.Text("Enter recipient"), sg.InputText(key='Transaction_Recipient')],
        [sg.Text("Enter amount"), sg.InputText(key='Transaction_Amount'), sg.Text("Balance: "), sg.Text("0", key='TBalance', text_color='green')],
        [sg.Button("Make Transaction")]
    ]

    # Layout for Check Balance Tab
    management_layout = [
        [sg.Text('', expand_x=True),sg.Text("Account Management", font=default_ui_settings["Title"]["Font"], justification="center"), sg.Text('', expand_x=True)],
        [sg.Text("Current Balance:"), sg.Text("0", key='Balance')],
        [sg.Button("Change Password", key='ChangePassword'), sg.Button("Delete Account", key='DeleteAccount', button_color=('white', 'red'))]
    ]
    mining_layout = [
        [sg.Text('', expand_x=True),sg.Text("Mining", font=default_ui_settings["Title"]["Font"], justification="center"), sg.Text('', expand_x=True)],
        [sg.Button("Start Mining", key='StartMining'), sg.Button("Stop Mining", key='StopMining')],
        [sg.Text(size=(40, 10), key='MiningOutput')]
    ]
    
    donation_layout = [
        [sg.Text('', expand_x=True),sg.Text("Donation", font=default_ui_settings["Title"]["Font"], justification="center"), sg.Text('', expand_x=True)],
        [sg.Text("Enter donation amount"), sg.InputText(key='Donation_Amount')],
        [sg.Button("Donate!")]
    ]
    
    default_theme = settings['Theme']
    
    settings_layout = [
        # Big centered text, saying settings
        [sg.Text('', expand_x=True),sg.Text("Settings", font=default_ui_settings['Title']['Font'], justification="center"), sg.Text('', expand_x=True)],
        [sg.Text("Running version: " + settings['Version'] + " with operating system: " + platform.system() + " " + platform.release()), sg.Button("Check for updates", key="CheckForUpdates")],
        [sg.Text("Share data with blueloops9 (creator of bluecoin)?"), sg.Checkbox("", default=share_data, key="ShareData", enable_events=True, tooltip="This will send your username and system operating system (like Windows 10) to blueloops9, so he can see who is using this program. This is completely optional, and you can disable it at any time.")],
        # Mod list, and total mod count
        [sg.Text("Mods:")],
        [sg.Listbox(list({}), size=(31, 10), key='ModList', select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, enable_events=True, bind_return_key=True)], # Empty listbox
        [sg.Text("Theme"), sg.Combo(theme_list, default_value=default_theme, key='Theme', readonly=True)],
        [sg.Button("Apply Theme")]
    ]
    
    layout_group = [
        login_layout,
        signup_layout,
        transaction_layout,
        management_layout,
        mining_layout,
        donation_layout,
        settings_layout
    ]
    for func in runonuicreation:
        func(library, layout_group) # We give it layout group so they can modify it
    # Layout for Login Tab
    # Define the window's tabs
    tab_group_layout = [
        sg.Tab('Login', login_layout),
        sg.Tab('Signup', signup_layout),
        sg.Tab('Transaction', transaction_layout),
        sg.Tab('Manage account', management_layout),
        sg.Tab('Mining', mining_layout),
        sg.Tab('Donate', donation_layout),
        sg.Tab('Settings', settings_layout)
    ]
    print("[INFO] additional_layout",additional_layout)
    for layoutname, layout in additional_layout.items():
        tab_group_layout.insert(layout[0], sg.Tab(layoutname, layout[1])) # layout[0] is for the order, layout[1] is for the layout itself

    # Create the window
    return sg.Window(f"Bluecoin ATM {settings['Version']}", [[sg.TabGroup([tab_group_layout])]])

# Function to show user selection layout
def user_selection_layout(users):
    return [[sg.Listbox(list(users.keys()), size=(31, 10), key='UserList')],
            [sg.Button("Select User"), sg.Button("New User"), sg.Button("Delete User")]]

def get_user():
    # Is the miner running? STOP IT!!
    stop_mining()
    
    users = load_users()
    user_window = sg.Window("User Selection", user_selection_layout(users))
    sg.theme(settings['Theme'])
    selected_user = None

    while True:
        event, values = user_window.read()
        

        if event == sg.WIN_CLOSED:
            user_window.close()
            return "No User Selected"

        if event == "Select User":
            if len(values['UserList']) == 0:
                sg.popup("Please select a user or create a new one", title="No User Selected", non_blocking=True)
                continue
            selected_user = values['UserList'][0]
            break

        if event == "New User":
            selected_user = None
            break
        if event == "Delete User":
            # Delete the user
            if len(values['UserList']) == 0:
                sg.popup("Please select a user to delete", title="No User Selected", non_blocking=True)
                continue
            
            selected_user = values['UserList'][0]
            users.pop(selected_user)
            with open(os.path.join(os.getenv('APPDATA'), "BluecoinATM", 'users.json'), 'w') as file:
                json.dump(users, file)
            # Reload the user list
            users = load_users()
            user_window['UserList'].update(list(users.keys()))
        

    user_window.close()
    return selected_user

global handlers
def testHandler(event, values, atm):
    #print(event, values)
    #sg.popup("Test handler called", title="Test Handler")
    return False # Dont stop execution
handlers = {
    "TestHandler":testHandler
}

def addHandler(name, handler):
    global handlers
    handlers[name] = handler

def removeHandler(name):
    global handlers
    handlers.pop(name)


global mining_process
global process
mining_process = None
stop_mining_flag = threading.Event()
stop_mining_flag.clear()
def start_mining(username, window):
    # Does ./bluecoinMINER.exe exist?
    if not os.path.exists("./bluecoinMINER.exe"): # Check for both windows and linux
        sg.popup("bluecoinMINER.exe not found, (gitlab version does not have integrated miner).", title="Error", non_blocking=True)
        return
    stop_mining() #Incase user clicks start mining twice
    global mining_process, stop_mining_flag
    # Check if process exists
    if mining_process:
        if mining_process.is_alive():
            # If it is, then we dont need to do anything
            return
    def run():
        global process
        stop_mining_flag.clear()
        if os.name == "nt":
            process = subprocess.Popen(["bluecoinMINER.exe", username], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
        else:
            process = subprocess.Popen(["wine ./bluecoinMINER.exe", username], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
        while not stop_mining_flag.is_set():
            line = process.stdout.readline()
            if not line:
                break
            window.write_event_value('-MINING_OUTPUT-', line)
        print("[INFO] Stopping mining process")
        process.wait()  # Wait for the process to finish
        process.stdout.close()

    mining_process = threading.Thread(target=run, daemon=True)
    mining_process.start()

global window

def get_window():
    return window

def stop_mining():
    global stop_mining_flag, mining_process
    stop_mining_flag.set()
    if mining_process:
        os.kill(process.pid, signal.SIGTERM)  # Send a signal to the process
        # we dont need to wait for thread, probably gonna finish soonish
        mining_process = None

global username
global password
username = ""
password = ""

def get_user_mod():
    return [username, password]

class ValueEvent:
    def __init__(self):
        self._event = threading.Event()
        self._value = None
        self._lock = threading.Lock()

    def set(self, value):
        with self._lock:
            self._value = value
            self._event.set()

    def wait(self, timeout=None):
        self._event.wait(timeout)
        return self._value

    def clear(self):
        with self._lock:
            self._value = None
            self._event.clear()
global runonwindowcreation
runonwindowcreation = []

def check_for_updates(window, settings, first):
    """
    Function to check for updates in a separate thread.
    """
    raw_url = "https://raw.githubusercontent.com/Why2312/bluecoinATM/main/bluecoinATM.py"
    http = urllib3.PoolManager()
    response = http.request('GET', raw_url, headers={'Cache-Control': 'no-cache, no-store, must-revalidate', 'Pragma': 'no-cache', 'Expires': '0'}).data.decode('utf-8')

    # Extract version from response
    lines = response.split("\n")
    version = None
    if lines:
        first_line = lines[0]
        if "vers = '" in first_line:
            version_parts = first_line.split("vers = '")
            if len(version_parts) > 1:
                version = version_parts[1].split("'")[0]

    # Use window.write_event_value to send a message to the GUI thread
    window.write_event_value('UpdateCheckComplete', (version, response, first))

def main():
    global window
    users = load_users()  # Load users at the beginning of the main function
    sg.theme(settings['Theme'])
    selected_user = get_user()
    if selected_user == "No User Selected":
        return "STOP"

    window = create_main_window()

    user_valid = threading.Event()
    user_exists_valid = threading.Event()
    user_exists_transaction = threading.Event()
    
    balance_value = ValueEvent()
    @debounce(.5)
    def check_user(username, password):
        if username == "" or password == "":
            user_valid.clear()
            return
        response = send_request("https://darkbluestealth.pythonanywhere.com", "VerifyUser", username, password)
        if response == "True":
            user_valid.set()
        else:
            user_valid.clear()
    
    def check_user_exists(username, password):
        if username == "":
            user_exists_valid.clear()
            return
        response = send_request("https://darkbluestealth.pythonanywhere.com", "AccountValid", username, "")
        if response == "True":
            user_exists_valid.set()
        else:
            user_exists_valid.clear()
    
    def check_user_transaction(username, password):
        if username == "":
            user_exists_transaction.clear()
            return
        response = send_request("https://darkbluestealth.pythonanywhere.com", "AccountValid", username, "")
        if response == "True":
            user_exists_transaction.set()
        else:
            user_exists_transaction.clear()
    
    def get_balance_thread(username, password):
        time.sleep(0.5)
        if username == "" or password == "":
            # Set balance to 0, avoid lag
            balance_value.set("0")
            return
        
        response = send_request("https://darkbluestealth.pythonanywhere.com", "CheckBalance", username, password)
        if response == "E407":
            # Set the balance to 0
            balance_value.set("0")
        elif response == "E406":
            # Set the balance to 0
            balance_value.set("0")
        else:
            balance_value.set(response)
    @debounce(.5)
    def check_user_2(username, password):
        if username == "" or password == "":
            return False
        response = send_request("https://darkbluestealth.pythonanywhere.com", "VerifyUser", username, password)
        if response == "True":
            # Send event to window
            window.write_event_value('UserValid', True)
    global check_user_thread
    check_user_thread = None
    
    global balance_thread
    balance_thread = None
    # Firstly we check if user is valid
    selected_username, selected_password = selected_user, users.get(selected_user)
    valid = check_user(selected_username, selected_password)
    window.Finalize()
    olduser = ""
    oldpassword = ""
    oldnewuser = ""
    oldnewpassword = ""
    oldtransactionuser = ""
    if selected_user and not window['Username'].get() and not window['Password'].get():
        window['Username'].update(selected_username)
        window['Password'].update(selected_password)
    if valid:
        window['Username'].update(background_color='green')
        window['Password'].update(background_color='green')
    else:
        window['Username'].update(background_color='red')
        window['Password'].update(background_color='red')
        
    # Set the mod list
    window['ModList'].update(list(mods))
    window['ModList'].bind('<Double-Button-1>', 'DoubleClicked')
    window['ShareData'].bind('<Button-1>', '')
    
    olderpassword = ""
    olderusername = ""
    
    for func in runonwindowcreation:
        func(library)
    # Trigger the checkforupdates event
    window.write_event_value('CheckForUpdates', "First")
    def check_version(oldver, newver):
        # Is newver newer than oldver using major.minor.patch?
        oldver = oldver.split(".")
        newver = newver.split(".")
        if int(newver[0]) > int(oldver[0]):
            return True
        elif int(newver[1]) > int(oldver[1]):
            return True
        elif int(newver[2]) > int(oldver[2]):
            return True
        else:
            return False
    time.sleep(0.3) # let for everything to load
    while True:
        
        try:
            
            event, values = window.read(timeout=0.05)
            values:dict = values



            if event == "ModList":
                continue # Ignore this event
            if event == "ModListDoubleClicked":
                # Get the selected mod
                if len(values['ModList']) == 0:
                    continue
                selected_mod = values['ModList'][0]
                # Get the mod data
                mod_data = mods[selected_mod]
                # Display the mod data
                sg.popup(f"Name: {mod_data['name']}\nAuthor: {mod_data['author']}\nVersion: {mod_data['version']}\nDescription: {mod_data['description']}", title="Mod Info", non_blocking=True)
                continue
            if event == "ShareData":
                # Update the setting
                settings["ShareData"] = values["ShareData"]
                # Save the settings
                save_settings()
                print("[INFO] Updated share data setting to " + str(values["ShareData"]))
                continue
            if event == "CheckForUpdates":
                # Start the update check in a separate thread
                threading.Thread(target=check_for_updates, args=(window, settings, values.get("CheckForUpdates", "NotFirst")), daemon=True).start()
                continue

            if event == "UpdateCheckComplete":
                version, response, first = values[event]
                if version and version != settings["Version"] and check_version(settings["Version"], version):
                    update = sg.popup_yes_no(f"Update available! Current version: {settings['Version']}, new version: {version}. Would you like to update?", title="Update Available")
                    if update == "Yes":
                        with open(__file__, 'w', encoding='utf-8') as file:
                            file.write(response)  # Write the response directly
                        sg.popup("Update complete! Please restart the program.", title="Update Complete", non_blocking=True)
                else:
                    if first != "First":
                        sg.popup("No updates available.", title="No Updates Available", non_blocking=True)
                continue

            if event == "Select new user":
                window.close()
                break  # Exit the loop and close the window

            if event in (sg.WIN_CLOSED, "Cancel"):
                break
            global username
            global password
            username = values['Username']
            transaction_username = values['Transaction_Recipient']
            password = values['Password']
            # Lets start getting the balance
            if balance_thread:
                if balance_thread.is_alive():
                    pass
                else:
                    balance_thread = threading.Thread(target=get_balance_thread, args=(username, password))
                    balance_thread.start()
            else:
                balance_thread = threading.Thread(target=get_balance_thread, args=(username, password))
                balance_thread.start()

            balance = balance_value.wait(1)
            # If balance starts with <!doctype html> then it is an error
            if balance:
                if balance.startswith("<html>"):
                    balance = None
            if balance:
                balance = str(format(float(balance), '.5f'))
                window['Balance'].update(f"{balance} Bluecoin, {int(float(balance) * 100000)} Morsels")
                window['TBalance'].update(balance) # For transaction tab
            # check if signup username and password are the same as the old ones
            newusername = values['Signup_Username']
            newpassword = values['Signup_Password']
            if username != olduser or password != oldpassword:
                olduser = username
                oldpassword = password
                user_valid.clear()
                threading.Thread(target=check_user, args=(username, password)).start()

            if newusername != oldnewuser or newpassword != oldnewpassword:
                oldnewuser = newusername
                oldnewpassword = newpassword
                if not newusername == "" or not newpassword == "":
                    oldnewuser = newusername
                    oldnewpassword = newpassword
                    user_exists_valid.clear()
                    threading.Thread(target=check_user_exists, args=(newusername,"cuh")).start()

            if transaction_username != oldtransactionuser:
                if not transaction_username == "":
                    oldtransactionuser = transaction_username
                    user_exists_transaction.clear()
                    threading.Thread(target=check_user_transaction, args=(transaction_username,"cuh")).start()






            olduser = username
            oldpassword = password
            oldnewuser = newusername
            oldnewpassword = newpassword
            oldtransactionuser = transaction_username

            if users.get(username) != password:
                check_user_thread = threading.Thread(target=check_user_2, args=(username, password))
                check_user_thread.start()
                olderpassword = password
                olderusername = username
                
            
            
            if event == "UserValid":
                # Get value
                value = values['UserValid']
                if value:
                    # Save the user
                    users[olderusername] = olderpassword
                    # Save the user list
                    save_user_list(users)
                    

            if user_valid.is_set():
                window['Username'].update(background_color='green')
                window['Password'].update(background_color='green')
                # Does user already exist in user list?
                if username not in users:
                    # If not, add them, and save the user list
                    save_user(username, password)
                    # Reload the user list
                    users = load_users()
                # Does the password match? If not, update it
            else:
                window['Username'].update(background_color='red')
                window['Password'].update(background_color='red')

            if user_exists_valid.is_set():
                window['Signup_Username'].update(background_color='red')
            else:
                window['Signup_Username'].update(background_color='green')

            if user_exists_transaction.is_set():
                window['Transaction_Recipient'].update(background_color='green')
            else:
                window['Transaction_Recipient'].update(background_color='red')


            # Lets check if the value in the transaction amount field is a number
            transaction_amount = values['Transaction_Amount']
            if transaction_amount:
                amount = None
                try:
                    amount = float(transaction_amount)
                except ValueError:
                    window['Transaction_Amount'].update(background_color='red')
                if amount == 0:
                    window['Transaction_Amount'].update(background_color=sg.theme_input_background_color())

                if amount:
                    # Compare it to the balance
                    if amount > float(balance):
                        window['Transaction_Amount'].update(background_color='red')
                    else:
                        window['Transaction_Amount'].update(background_color='green')
            else:
                # Set to theme color
                window['Transaction_Amount'].update(background_color=sg.theme_input_background_color())


            # Lets do the same for donation amount
            donation_amount = values['Donation_Amount']
            if donation_amount:
                amount = None
                try:
                    amount = float(donation_amount)
                except ValueError:
                    window['Donation_Amount'].update(background_color='red')

                if amount == 0:
                    window['Donation_Amount'].update(background_color=sg.theme_input_background_color())

                if amount:
                    # Compare it to the balance
                    if amount > float(balance):
                        window['Donation_Amount'].update(background_color='red')
                    else:
                        window['Donation_Amount'].update(background_color='green')
            else:
                # Set to theme color
                window['Donation_Amount'].update(background_color=sg.theme_input_background_color())


            if event == "DeleteAccount":
                # Pop up a confirmation window, with a password field
                password = sg.popup_get_text("Confirm by entering your password", password_char='●')
                # Does the password match?
                if password == values['Password']:
                    # Ask the user if they are sure
                    sure = sg.popup_yes_no("Are you sure you want to delete your account? This cannot be undone.")
                    if sure == "Yes":
                        send_request("https://darkbluestealth.pythonanywhere.com", "DeleteAccount", username, password)
                        # Delete the user from the user list
                        users.pop(username)
                        # Save the user list
                        save_user_list(users)
                        # Exit the main loop
                        window.close()
                        return None

            # Theme selection
            if event == "Apply Theme":
                # Get the theme
                theme = values['Theme']
                # Set the theme
                sg.theme(theme)
                # Update the settings
                settings['Theme'] = theme
                # Save the theme in the settings file
                save_settings()
                # Regenerate the window
                window.close()
                return None
            if event == sg.TIMEOUT_KEY:
                continue
            exit = False
            for handlername, handler in handlers.items():
                value = handler(event, values, library)
                print("[INFO] value, handlername",value, handlername)
                if value:
                    print("[INFO] Handler " + handlername + " stopped execution")
                    exit = True
                    break
            if exit:
                continue
            
            


            if event == "Signup":
                print("[INFO] user_exists_valid: ",user_exists_valid.is_set())
                if user_exists_valid.is_set():
                    sg.popup("Username invalid or already exists.", title="Error", non_blocking=True)
                    continue
                signup_username = values['Signup_Username']
                signup_password = values['Signup_Password']
                response = send_request("https://darkbluestealth.pythonanywhere.com", "Signup", signup_username, signup_password)
                if response == "400":
                    sg.popup("User already exists", title="Error", non_blocking=True)
                elif response == "200":
                    sg.popup("Account created successfully", title="Success", non_blocking=True)
                    save_user(signup_username, signup_password)
                    users = load_users()  # Reload users
                    # Set the username and password fields to the new user
                    window['Username'].update(signup_username)
                    window['Password'].update(signup_password)
                else:
                    sg.popup("Error: " + response, title="Error", non_blocking=True)
                continue
            
            if not user_valid.is_set() and event != sg.TIMEOUT_KEY:
                print(event, "REAL")
                if username == "" or password == "":
                    continue # Dont show error if username or password is empty
                sg.popup("Username or password invalid.", title="Error", non_blocking=True)
                continue
            if event == 'StopMining':
                # Clear the output
                window['MiningOutput'].update("")
                stop_mining()  # Call the function to stop mining
            if event == 'StartMining':
                username = values.get('Username')
                if username:
                    start_mining(username, window)
                else:
                    sg.popup("Please enter a username to start mining.", title="No username entered", non_blocking=True)

            if event == '-MINING_OUTPUT-':
                # Just set the output to the text element
                window['MiningOutput'].update(values['-MINING_OUTPUT-'])

            if event == "Donate!":
                # Get amount
                amount = values['Donation_Amount']
                # Send request
                response = send_request("https://darkbluestealth.pythonanywhere.com", "Transaction", username, password, "GenericRblxStudioDev", amount)
                if response == "404":
                    sg.popup("Your password is invalid", title="Error", non_blocking=True)
                elif response == "400":
                    sg.popup("Invalid username.", title="Error", non_blocking=True)
                elif response == "407":
                    sg.popup("Invalid recipient username.", title="Error", non_blocking=True)
                elif response == "402":
                    sg.popup("You cannot take bluecoin, silly.", title="Error", non_blocking=True)
                elif response == "401":
                    sg.popup("You don't have enough bluecoin.", title="Error", non_blocking=True)
                elif response == "200":
                    sg.popup(f"Thanks for donating {amount} bluecoin to me! Your new balance is {send_request('https://darkbluestealth.pythonanywhere.com', 'CheckBalance', username, password)}", title="Thanks for donating", non_blocking=True) # Check balance should work


            if event == "Make Transaction":
                if not user_exists_transaction.is_set():
                    sg.popup("Recipient username invalid or does not exist.", title="Error", non_blocking=True)
                    continue
                receiver = values['Transaction_Recipient']
                amount = values['Transaction_Amount']
                response = send_request("https://darkbluestealth.pythonanywhere.com", "Transaction", username, password, receiver, amount)
                if response == "404":
                    sg.popup("Your password is invalid", title="Error", non_blocking=True)
                elif response == "400":
                    sg.popup("Invalid username.", title="Error", non_blocking=True)
                elif response == "407":
                    sg.popup("Invalid recipient username.", title="Error", non_blocking=True)
                elif response == "402":
                    sg.popup("You cannot take bluecoin, silly.", title="Error", non_blocking=True)
                elif response == "401":
                    sg.popup("You don't have enough bluecoin.", title="Error", non_blocking=True)
                elif response == "200":
                    sg.popup("Transaction successful, new balance: " + send_request("https://darkbluestealth.pythonanywhere.com", "CheckBalance", username, password), title="Success", non_blocking=True) # Check balance should work
                else:
                    sg.popup("Error: " + response, non_blocking=True)

            elif event == "ChangePassword":
                # Ask the user for new password
                new_password = sg.popup_get_text("Enter new password", password_char='●', )
                if new_password:
                    # Send the request
                    response = send_request("https://darkbluestealth.pythonanywhere.com", "ChangePassword", username, password, new_password=new_password)
                    if response == "407":
                        sg.popup("Invalid username.", title="Error", non_blocking=True)
                    elif response == "408":
                        sg.popup("Invalid password.", title="Error", non_blocking=True)
                    elif response == "100":
                        sg.popup("Password changed successfully.", title="Success", non_blocking=True)
                        # Update the password in the user list
                        users[username] = new_password
                        # Save the user list
                        update_user(username, new_password)

                        # Update the password field
                        window['Password'].update(new_password)
                    else:
                        sg.popup("Error: " + response, title="Error", non_blocking=True)


            #Regenerate the window if needed
            if selected_user and not window['Username'].get() and not window['Password'].get():
                window['Username'].update(selected_username)
                window['Password'].update(selected_password)
        except Exception as e:
            import traceback
            error_message = traceback.format_exc()
            print("[INFO] Error in main loop: ", error_message)
            sg.popup(f"An unexpected error occurred: {str(e)}\n\nDetailed error info:\n{error_message}", title="Error", non_blocking=False)
            time.sleep(0.5)
mods = {}

def get_ui_settings():
    return default_ui_settings

class DotDict(dict):

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, attr, value):
        self[attr] = value

    def __delattr__(self, attr):
        del self[attr]
library = DotDict({
    "add_layout": add_layout,
    "remove_layout": remove_layout,
    "modify_layout": modify_layout,
    "modify_layout_element": modify_layout_element,
    "addHandler": addHandler,
    "removeHandler": removeHandler,
    "send_request": send_request,
    "settings": settings,
    "save_settings": save_settings,
    "load_users": load_users,
    "get_current_user": get_user_mod,
    "save_user": save_user,
    "update_user": update_user,
    "get_window": get_window,
    "print": print,
    "get_gist_raw_url": get_gist_raw_url,
    "get_user": get_user,
    "get_ui_settings": get_ui_settings,
    
})

loaded = []
temp_buffer = []
mixins = []

global runonshutdown
runonshutdown = []

global runonuishutdown
runonuishutdown = []

def load_mod_to_buffer(scriptname):
    # Import the module without executing its main logic
    mod = importlib.import_module("mods." + scriptname)
    # Add the mod to the temporary buffer
    temp_buffer.append(mod)

def process_mixins():
    # Process mixins for each mod in the buffer
    for mod in temp_buffer:
        for mixin in mixins:
            mixin(mod)

def finalize_mod_loading():
    # Finalize loading of each mod from the buffer
    for mod in temp_buffer:
        mainfunc = getattr(mod, "main")
        mainfunc(library)
        loaded.append(mod)
        runonuicreation.append(getattr(mod, mod.mod_data["uicreated"]))
        runonwindowcreation.append(getattr(mod, mod.mod_data["aftercreation"]))
        runonshutdown.append(getattr(mod, mod.mod_data["shutdown"]))
        runonuishutdown.append(getattr(mod, mod.mod_data["uishutdown"]))
        mods[mod.mod_data["name"]] = mod.mod_data

if __name__ == "__main__":
    print("START OF BLUECOINATM!!!")
    # Load every mod into the buffer
    for file in os.listdir("mods"):
        if file.endswith(".py"):
            load_mod_to_buffer(file[:-3])

    # Process mixins
    process_mixins()

    # Finalize loading of mods
    finalize_mod_loading()

    while True:
        data = main()
        if data == "STOP":
            break
        for func in runonuishutdown:
            print("[INFO] Running uishutdown function " + func.__name__)
            func(library)
    
    for func in runonshutdown:
        print("[INFO] Running shutdown function " + func.__name__)
        func(library)