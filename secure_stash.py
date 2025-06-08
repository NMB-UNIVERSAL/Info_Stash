import os
import json
import hashlib
import base64
import re
import getpass
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pytube
import requests
from bs4 import BeautifulSoup

class SecureStash:
    def __init__(self):
        self.data_file = "secure_stash.dat"
        self.salt_file = "salt.dat"
        self.master_password = None
        self.cipher = None
        self.stash = []
        
        # Initialize or load salt
        if not os.path.exists(self.salt_file):
            self.salt = os.urandom(16)
            with open(self.salt_file, "wb") as f:
                f.write(self.salt)
        else:
            with open(self.salt_file, "rb") as f:
                self.salt = f.read()

    def derive_key(self, password):
        """Derive encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def authenticate(self, password=None):
        """Authenticate with master password"""
        if not password:
            password = getpass.getpass("Enter master password: ")
        
        # Generate key from password
        key = self.derive_key(password)
        self.cipher = Fernet(key)
        
        # Try to decrypt the file to verify password
        if os.path.exists(self.data_file) and os.path.getsize(self.data_file) > 0:
            try:
                with open(self.data_file, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = self.cipher.decrypt(encrypted_data).decode()
                self.stash = json.loads(decrypted_data)
                self.master_password = password
                return True
            except Exception:
                print("Invalid password or corrupted data.")
                return False
        else:
            # First time setup
            self.master_password = password
            self.stash = []
            self.save_stash()
            return True

    def save_stash(self):
        """Save encrypted stash to file"""
        if not self.cipher:
            raise ValueError("Not authenticated")
        
        encrypted_data = self.cipher.encrypt(json.dumps(self.stash).encode())
        with open(self.data_file, "wb") as f:
            f.write(encrypted_data)
    
    def add_entry(self, value):
        """Add an entry to the stash"""
        if not self.cipher:
            raise ValueError("Not authenticated")
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {"timestamp": timestamp}
        
        # Check if it's a URL
        if self._is_url(value):
            title = self._get_url_title(value)
            entry["type"] = "url"
            entry["url"] = value
            entry["title"] = title
        else:
            entry["type"] = "text"
            entry["content"] = value
        
        self.stash.append(entry)
        self.save_stash()
    
    def get_all_entries(self):
        """Retrieve all entries from the stash"""
        if not self.cipher:
            raise ValueError("Not authenticated")
        
        return self.stash
    
    def delete_entry(self, index):
        """Delete an entry from the stash by index"""
        if not self.cipher:
            raise ValueError("Not authenticated")
        
        try:
            index = int(index) - 1  # Convert from 1-based to 0-based indexing
            if 0 <= index < len(self.stash):
                self.stash.pop(index)
                self.save_stash()
                return True
            return False
        except (ValueError, IndexError):
            return False
    
    def _is_url(self, text):
        """Check if text is a URL"""
        url_pattern = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ipv4
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        return bool(url_pattern.match(text))
    
    def _get_url_title(self, url):
        """Extract title from URL"""
        try:
            # Try to use pytube for YouTube videos
            if "youtube.com" in url or "youtu.be" in url:
                yt = pytube.YouTube(url)
                return yt.title
            else:
                # For other websites
                response = requests.get(url, timeout=5)
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.find('title')
                if title:
                    return title.get_text()
                return "No title found"
        except Exception as e:
            return f"Error retrieving title: {str(e)}"

def main_menu():
    """Display main menu and handle user input"""
    stash = SecureStash()
    
    # First, authenticate
    authenticated = False
    while not authenticated:
        password = getpass.getpass("Enter your master password: ")
        authenticated = stash.authenticate(password)
    
    print("\nSecure Stash - Your encrypted information storage")
    
    while True:
        print("\nMENU:")
        print("1. Add new information")
        print("2. View all information")
        print("3. Delete entry")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == "1":
            value = input("Enter the information to store: ")
            stash.add_entry(value)
            print("Information added successfully.")
            
        elif choice == "2":
            entries = stash.get_all_entries()
            if entries:
                print("\n=== All Stored Information ===")
                for i, entry in enumerate(entries, 1):
                    print(f"\n[{i}] - {entry['timestamp']}")
                    
                    if entry["type"] == "url":
                        print(f"URL: {entry['url']}")
                        print(f"Title: {entry['title']}")
                    else:
                        print(f"Content: {entry['content']}")
                    
                    print("-" * 40)
            else:
                print("\nNo information stored yet.")
                
        elif choice == "3":
            entries = stash.get_all_entries()
            if not entries:
                print("\nNo entries to delete.")
                continue
                
            print("\nAll entries:")
            for i, entry in enumerate(entries, 1):
                if entry["type"] == "url":
                    print(f"{i}. {entry['title']} ({entry['url']})")
                else:
                    content_preview = entry['content'][:30] + "..." if len(entry['content']) > 30 else entry['content']
                    print(f"{i}. {content_preview}")
                    
            index = input("\nEnter number of entry to delete: ")
            if stash.delete_entry(index):
                print("Entry deleted successfully.")
            else:
                print("Invalid entry number.")
                
        elif choice == "4":
            print("Exiting Secure Stash. Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu() 