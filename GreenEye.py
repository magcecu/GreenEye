import win32security
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import pygetwindow as gw
import os
import json
from pystyle import Colorate, Colors, Center

with open('config.json', 'r') as config_file:
    config = json.load(config_file)

turnoff = config['turn_off_pc']
delete = config['delete_new_files']
path = config['path_to_monitor']
webcam = config['check_for_cam_spy']

class Antivirus(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"New file created: {file_path}")
            if turnoff == "T":
                print("TURNING OFF!!!!")
                time.sleep(0.1)
                os.system("shutdown /s /t 0")

            owner_info = self.get_file_owner(file_path)
            if owner_info:
                owner_name, owner_domain = owner_info
                print(f"The file is owned by {owner_domain}\\{owner_name}")
            else:
                print("Error: Unable to retrieve owner information")

            audit_info = self.check_file_audit(file_path)
            print(f"Audit Information: {audit_info}")
            if delete == "T":
                os.remove(file_path)
                print(f"{file_path} was deleted.")

    def get_file_owner(self, file_path):
        try:
            owner_sid, owner_domain, owner_type = win32security.LookupAccountName("", file_path)
            if owner_sid and owner_domain:
                owner_name = win32security.GetAccountName(None, owner_sid)
                return owner_name, owner_domain
        except Exception as e:
            return None

    def check_file_audit(self, file_path):
        try:
            security_descriptor = win32security.GetFileSecurity(
                file_path,
                win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
            )
            
            sacl = security_descriptor.GetSecurityDescriptorSacl()
            if sacl:
                return "Auditing is enabled."
                
            else:
                return "Auditing is not enabled."
            
        except Exception as e:
            return str(e)
            
observer = Observer()
antivirus = Antivirus()

observer.schedule(antivirus, path=path)
observer.start()

def is_camera_in_use():
        windows = gw.getAllTitles()
        return any("camera" in window.lower() for window in windows)

eye = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡇⠀⠀⢰⡆⢘⣆⠀⠀⡆⠀⢸⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⣆⣧⡤⠾⢷⡚⠛⢻⣏⢹⡏⠉⣹⠟⡟⣾⠳⣼⢦⣀⣰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠰⣄⡬⢷⣝⢯⣷⢤⣘⣿⣦⣼⣿⣾⣷⣼⣽⣽⣿⣯⡾⢃⣠⣞⠟⠓⢦⣀⠆⠀⠀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠲⣄⣤⣞⡉⠛⢶⣾⡷⠟⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⡿⢿⡛⠻⠿⣥⣤⣶⠞⠉⢓⣤⡴⢁⠄⠀⠀⠀⠀⠀
⠀⠀⠀⣄⣠⠞⠉⢛⣻⡿⠛⠁⠀⣸⠯⠈⠀⠁⣴⣿⣿⣿⡶⠤⠽⣇⠈⣿⠀⠀⠈⠙⠻⢶⣾⣻⣭⠿⢫⣀⣴⡶⠃⠀⠀
⠀⢤⣀⣜⣉⣩⣽⠿⠋⠀⠀⠀⠀⣿⠈⠀⠀⢸⣿⣿⣿⣿⣀⠀⠀⠸⠇⢸⡇⠀⠀⠀⠀⠀⠘⠛⢶⣶⣾⣻⡯⠄⠀⣠⠄
⠀⠤⠬⢭⣿⣿⠋⠀⠀⠀⠀⠀⠀⢻⡀⠀⠀⠀⢿⣿⣿⣿⡿⠋⠁⠀⠀⣼⠁⠀⠀⠀⠀⠀⢀⣴⣫⣏⣙⠛⠒⠚⠋⠁⠀
⡔⢀⡵⠋⢧⢹⡀⠀⠀⠀⠀⠀⠀⠈⢷⡀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⣰⠏⠀⠀⠀⠀⠀⣠⣾⣿⡛⠛⠛⠓⠦⠀⠀⠀⠀
⣇⠘⠳⠦⠼⠧⠷⣄⣀⠀⠀⠀⠀⠀⠀⠳⢤⣀⠀⠀⠀⠀⠀⢀⣠⠾⠃⠀⠀⠀⣀⣴⣻⣟⡋⠉⠉⢻⠶⠀⠀⠀⠀⠀⠀
⠈⠑⠒⠒⠀⠀⢄⣀⡴⣯⣵⣖⣦⠤⣀⣀⣀⠉⠙⠒⠒⠒⠚⠉⢁⣀⣠⢤⣖⣿⣷⢯⡉⠉⠙⣲⠞⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠣⢤⡞⠉⢉⡿⠒⢻⢿⡿⠭⣭⡭⠿⣿⡿⠒⠻⣯⡷⡄⠉⠳⣬⠷⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠺⠤⣄⣠⡏⠀⠀⡿⠀⠀⠘⡾⠀⢀⣈⡧⠴⠒⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠒⠓⠒⠒⠚⠛⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

logo = """
   ____ ____  _____ _____ _   _   _______   _______ 
  / ___|  _ \| ____| ____| \ | | | ____\ \ / / ____|
 | |  _| |_) |  _| |  _| |  \| | |  _|  \ V /|  _|  
 | |_| |  _ <| |___| |___| |\  | | |___  | | | |___ 
  \____|_| \_\_____|_____|_| \_| |_____| |_| |_____|
                  Made By MagCecu
"""
print(Center.XCenter(Center.YCenter(Colorate.Vertical(Colors.green_to_white, eye, 2))))
time.sleep(4)
os.system('cls' if os.name == 'nt' else 'clear')
print(Center.XCenter(Colorate.Vertical(Colors.green_to_white, logo, 2)))
print("")
print(f"Listening on Path:{path}")

try:
    while True:
        pass
        if webcam == "T":
            if is_camera_in_use():
                print("Camera is in use!!!")
                time.sleep(5)
except KeyboardInterrupt:
    observer.stop()
observer.join()