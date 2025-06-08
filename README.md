# Secure Stash

A secure, password-protected application for storing sensitive information, including URLs with their titles.

## Features

- Password-protected access
- Secure encryption of all stored data
- Special handling for URLs (extracts and stores titles)
- Direct information storage without naming entries
- Available in both command-line and GUI interfaces

## Installation

1. Install the latest release
2. Run the GUI or CLI build

## Usage

### Command-Line Interface

1. **First Run**: When you first run the app, you'll be asked to set a master password. This will be used to encrypt all your data.

2. **Main Menu**:
   - Add new information: Store new text or URL directly
   - View all information: See everything you've stored with timestamps
   - Delete entry: Remove an entry by its number
   - Exit: Close the application

### GUI Interface

The GUI version provides the same functionality with a more user-friendly interface:

1. **Login Screen**: Enter your master password to access the application
2. **Main Screen**: 
   - View all your stored information
   - Add new information via a popup dialog
   - Delete entries from a selection list
   - Refresh view to see latest changes

3. **URL Handling**: When you add a URL, the application will automatically:
   - Detect that it's a URL
   - Extract the page title (works with YouTube and other websites)
   - Store both the URL and its title

## Security Details

- Your master password is never stored directly
- Data is encrypted using Fernet symmetric encryption
- A unique salt is generated for your installation
- Password-based key derivation (PBKDF2) with 100,000 iterations

## Requirements

See requirements.txt for all dependencies if runnign via python.
