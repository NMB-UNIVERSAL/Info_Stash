import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from secure_stash import SecureStash

class SecureStashGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Stash")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        # Set style
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", background="#4287f5", font=("Arial", 10))
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 11))
        self.style.configure("Header.TLabel", font=("Arial", 16, "bold"))
        
        self.stash = SecureStash()
        self.create_login_screen()

    def create_login_screen(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        login_frame = ttk.Frame(self.root, padding=20)
        login_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_label = ttk.Label(
            login_frame, 
            text="Secure Stash", 
            font=("Arial", 24, "bold"), 
            foreground="#4287f5"
        )
        header_label.pack(pady=(0, 20))
        
        # Description
        desc_label = ttk.Label(
            login_frame, 
            text="Encrypted information storage",
            font=("Arial", 12)
        )
        desc_label.pack(pady=(0, 40))
        
        # Password field
        password_frame = ttk.Frame(login_frame)
        password_frame.pack(fill=tk.X, pady=10)
        
        password_label = ttk.Label(password_frame, text="Master Password:")
        password_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(fill=tk.X, ipady=5)
        self.password_entry.bind("<Return>", lambda e: self.authenticate())
        
        # Login button
        button_frame = ttk.Frame(login_frame)
        button_frame.pack(fill=tk.X, pady=(20, 10))
        
        login_button = ttk.Button(
            button_frame, 
            text="Login", 
            command=self.authenticate,
            style="TButton",
            cursor="hand2"
        )
        login_button.pack(pady=10, ipady=5, fill=tk.X)
        
        # Status message
        self.status_var = tk.StringVar()
        status_label = ttk.Label(login_frame, textvariable=self.status_var, foreground="red")
        status_label.pack(pady=10)
        
        # Focus on password field
        self.password_entry.focus()

    def authenticate(self):
        password = self.password_var.get()
        if not password:
            self.status_var.set("Password cannot be empty")
            return
        
        # Show loading message
        self.status_var.set("Authenticating...")
        self.root.update_idletasks()
        
        # Use a thread to prevent UI freeze
        def auth_thread():
            authenticated = self.stash.authenticate(password)
            if authenticated:
                self.root.after(0, self.create_main_screen)
            else:
                self.root.after(0, lambda: self.status_var.set("Invalid password or corrupted data"))
        
        threading.Thread(target=auth_thread).start()

    def create_main_screen(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
            
        # Create main frame
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_label = ttk.Label(
            main_frame, 
            text="Secure Stash", 
            style="Header.TLabel"
        )
        header_label.pack(pady=(0, 20))
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        # Add info button
        add_button = ttk.Button(
            buttons_frame,
            text="Add Information",
            command=self.show_add_info,
            padding=10,
            cursor="hand2"
        )
        add_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Delete button
        delete_button = ttk.Button(
            buttons_frame,
            text="Delete Entry",
            command=self.show_delete_entry,
            padding=10,
            cursor="hand2"
        )
        delete_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Content area (view all info)
        content_frame = ttk.Frame(main_frame, relief=tk.GROOVE, borderwidth=1)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Title for content area
        view_label = ttk.Label(content_frame, text="All Information", font=("Arial", 12, "bold"))
        view_label.pack(anchor=tk.W, padx=10, pady=10)
        
        # Scrolled text widget for content
        self.content_text = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD, height=15)
        self.content_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.content_text.config(state=tk.DISABLED)
        
        # Refresh button
        refresh_button = ttk.Button(
            content_frame,
            text="Refresh",
            command=self.refresh_content,
            cursor="hand2"
        )
        refresh_button.pack(padx=10, pady=(0, 10), anchor=tk.E)
        
        # Display initial content
        self.refresh_content()

    def refresh_content(self):
        # Clear content
        self.content_text.config(state=tk.NORMAL)
        self.content_text.delete(1.0, tk.END)
        
        entries = self.stash.get_all_entries()
        if entries:
            for i, entry in enumerate(entries, 1):
                # Entry header with number and timestamp
                self.content_text.insert(tk.END, f"[{i}] - {entry['timestamp']}\n", "header")
                
                # Content based on type
                if entry["type"] == "url":
                    self.content_text.insert(tk.END, f"URL: {entry['url']}\n", "field")
                    self.content_text.insert(tk.END, f"Title: {entry['title']}\n", "value")
                else:
                    self.content_text.insert(tk.END, f"Content: {entry['content']}\n", "value")
                
                self.content_text.insert(tk.END, "-" * 50 + "\n\n")
                
            # Apply tags for styling
            self.content_text.tag_configure("header", font=("Arial", 11, "bold"))
            self.content_text.tag_configure("field", font=("Arial", 10), lmargin1=20, lmargin2=20)
            self.content_text.tag_configure("value", font=("Arial", 10), foreground="blue", lmargin1=20, lmargin2=20)
        else:
            self.content_text.insert(tk.END, "No information stored yet.")
        
        self.content_text.config(state=tk.DISABLED)

    def show_add_info(self):
        # Create add info dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Information")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        title_label = ttk.Label(frame, text="Add New Information", font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Text input
        info_label = ttk.Label(frame, text="Enter information or URL:")
        info_label.pack(anchor=tk.W, pady=(0, 5))
        
        info_entry = scrolledtext.ScrolledText(frame, height=6, wrap=tk.WORD)
        info_entry.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        info_entry.focus_set()
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        
        cancel_btn = ttk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            cursor="hand2"
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        save_btn = ttk.Button(
            btn_frame,
            text="Save",
            command=lambda: self.add_info(info_entry.get(1.0, tk.END).strip(), dialog),
            cursor="hand2"
        )
        save_btn.pack(side=tk.RIGHT, padx=5)

    def add_info(self, info, dialog):
        if not info:
            messagebox.showwarning("Empty Input", "Please enter some information to store.")
            return
            
        try:
            self.stash.add_entry(info)
            dialog.destroy()
            self.refresh_content()
            messagebox.showinfo("Success", "Information added successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add information: {str(e)}")

    def show_delete_entry(self):
        entries = self.stash.get_all_entries()
        if not entries:
            messagebox.showinfo("No Entries", "There are no entries to delete.")
            return
        
        # Create delete dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Delete Entry")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        title_label = ttk.Label(frame, text="Select Entry to Delete", font=("Arial", 14, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Listbox for entries
        listbox_frame = ttk.Frame(frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(listbox_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        listbox = tk.Listbox(
            listbox_frame,
            yscrollcommand=scrollbar.set,
            font=("Arial", 10),
            selectmode=tk.SINGLE
        )
        
        for i, entry in enumerate(entries, 1):
            if entry["type"] == "url":
                display_text = f"{i}. {entry['title']} ({entry['url'][:30]}...)" if len(entry['url']) > 30 else f"{i}. {entry['title']} ({entry['url']})"
            else:
                content_preview = entry['content'][:40] + "..." if len(entry['content']) > 40 else entry['content']
                display_text = f"{i}. {content_preview}"
            listbox.insert(tk.END, display_text)
        
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=listbox.yview)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))
        
        cancel_btn = ttk.Button(
            btn_frame,
            text="Cancel",
            command=dialog.destroy,
            cursor="hand2"
        )
        cancel_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = ttk.Button(
            btn_frame,
            text="Delete",
            command=lambda: self.delete_entry(listbox.curselection(), dialog),
            cursor="hand2"
        )
        delete_btn.pack(side=tk.RIGHT, padx=5)

    def delete_entry(self, selection, dialog):
        if not selection:
            messagebox.showwarning("No Selection", "Please select an entry to delete.")
            return
            
        index = selection[0] + 1  # Convert to 1-based index for the stash
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            if self.stash.delete_entry(index):
                dialog.destroy()
                self.refresh_content()
                messagebox.showinfo("Success", "Entry deleted successfully.")
            else:
                messagebox.showerror("Error", "Failed to delete entry.")

def main():
    root = tk.Tk()
    app = SecureStashGUI(root)
    
    # Set window icon if available
    try:
        root.iconbitmap("lock_icon.ico") 
    except:
        pass

    root.mainloop()

if __name__ == "__main__":
    main() 