import subprocess
import hashlib
import base64
from cryptography.fernet import Fernet
import platform

def get_hwid_windows():
    # Getting various hardware identifiers
    cmds = [
        "wmic csproduct get uuid",
        "wmic diskdrive get serialnumber",
        "wmic baseboard get serialnumber",
        "wmic bios get serialnumber"
    ]
    hwid = ""
    for cmd in cmds:
        hwid += subprocess.check_output(cmd, shell=True).decode()
    return hwid

def get_hwid_linux():
    # Commands to get hardware identifiers in Linux
    cmds = [
        "sudo dmidecode -s system-uuid",
        "sudo hdparm -I /dev/sda | grep Serial",
        "sudo dmidecode -s baseboard-serial-number",
        "sudo dmidecode -s bios-serial-number"
    ]
    hwid = ""
    for cmd in cmds:
        try:
            hwid += subprocess.check_output(cmd, shell=True).decode().strip()
        except subprocess.CalledProcessError:
            pass  # Handle the exception if the command fails
    return hwid

def get_hwid():
    if platform.system() == "Linux":
        return get_hwid_linux()
    # Add other platform-specific functions here if needed
    elif platform.system() == "Windows":
        return get_hwid_windows()
    else:
        raise NotImplementedError("Unsupported Operating System")

def generate_key_from_hwid():
    hwid = get_hwid()
    hasher = hashlib.sha256()
    hasher.update(hwid.encode())
    key = base64.urlsafe_b64encode(hasher.digest())
    return key

class HWIDBasedEncryption:
    def __init__(self):
        self.key = generate_key_from_hwid()
        self.fernet = Fernet(self.key) # Prepare the encryption object

    def encrypt(self, message):
        encrypted_message = self.fernet.encrypt(message.encode())
        return encrypted_message

    def decrypt(self, encrypted_message):
        decrypted_message = self.fernet.decrypt(encrypted_message).decode()
        return decrypted_message