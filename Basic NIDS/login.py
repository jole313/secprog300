import tkinter as tk
from tkinter import ttk, messagebox
from users import verify_user, add_user, ensure_admin_exists
import sys
import os
import threading
from capture import start_capture
import gui

class LoginScreen:
    def __init__(self, root):
        self.root = root
        root.title("NIDS Login")
        root.geometry("400x400")
        
        # Configure style
        style = ttk.Style()
        style.configure('TLabel', font=('Helvetica', 11))
        style.configure('TButton', font=('Helvetica', 11))
        style.configure('Header.TLabel', font=('Helvetica', 16, 'bold'))
        
        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.pack(expand=True, fill="both")
        
        # Title
        title = ttk.Label(self.main_frame, text="Network Intrusion Detection System", 
                         style='Header.TLabel', wraplength=300, justify='center')
        title.pack(pady=(0, 20))
        
        # Login frame
        self.login_frame = ttk.LabelFrame(self.main_frame, text="Login", padding="10")
        self.login_frame.pack(fill="x", padx=20, pady=10)
        
        # Username
        ttk.Label(self.login_frame, text="Username:").pack(fill="x", pady=(0, 5))
        self.username = ttk.Entry(self.login_frame)
        self.username.pack(fill="x", pady=(0, 10))
        
        # Password
        ttk.Label(self.login_frame, text="Password:").pack(fill="x", pady=(0, 5))
        self.password = ttk.Entry(self.login_frame, show="●")
        self.password.pack(fill="x", pady=(0, 10))
        
        # Login button
        self.login_btn = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_btn.pack(fill="x", pady=(10, 0))
        
        # Status label
        self.status = ttk.Label(self.main_frame, text="", wraplength=300, justify='center')
        self.status.pack(pady=10)
        
        # Bind Enter key
        self.username.bind('<Return>', lambda e: self.password.focus())
        self.password.bind('<Return>', lambda e: self.login())
        
        # Set initial focus
        self.username.focus()
        
        # Create default admin if needed
        ensure_admin_exists()
        
        # Show default credentials message if just created
        if not os.path.exists("users.json") or os.path.getsize("users.json") == 2:  # Empty JSON file
            messagebox.showinfo("Default Credentials", 
                              "Default admin credentials:\nUsername: admin\nPassword: admin123\n\n")
    
    def login(self):
        username = self.username.get()
        password = self.password.get()
        
        if not username or not password:
            self.status.config(text="Please enter both username and password", foreground="red")
            return
        
        success, message = verify_user(username, password)
        
        if success:
            self.status.config(text="Login successful! Starting NIDS...", foreground="green")
            self.root.after(1000, self.start_nids)
        else:
            self.status.config(text=message, foreground="red")
    
    def start_nids(self):
        """Start the NIDS main program"""
        try:
            # Create a new window for NIDS
            nids_window = tk.Toplevel(self.root)
            nids_window.geometry("1000x700")  # Set default size
            nids_window.title("Network Intrusion Detection System")
            
            # Start capture thread
            capture_thread = threading.Thread(target=start_capture, daemon=True)
            capture_thread.start()
            
            # Start GUI with the user's password for log decryption
            nids_gui = gui.NIDSGUI(nids_window, self.password.get())
            
            # Hide the login window
            self.root.withdraw()
            
            # Handle NIDS window closing
            def on_nids_closing():
                if messagebox.askokcancel("Quit", "Do you want to close the NIDS Dashboard?"):
                    nids_window.destroy()
                    self.root.destroy()
            
            nids_window.protocol("WM_DELETE_WINDOW", on_nids_closing)
            
        except Exception as e:
            self.root.deiconify()  # Show the login window again
            self.status.config(text=f"Error starting NIDS: {str(e)}", foreground="red")

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginScreen(root)
    root.mainloop() 