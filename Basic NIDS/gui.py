import tkinter as tk
from tkinter import ttk, messagebox
from packet_logging import read_encrypted_log, PACKET_LOG_FILE, MALICIOUS_LOG_FILE
import os
import signal
import sys
import threading
import time

class NIDSGUI:
    def __init__(self, root, password):
        self.root = root
        self.password = password  # Store password for log decryption
        root.title("Basic NIDS Dashboard")
        root.geometry("1000x700")  # Larger default size
        
        # Set up proper window close handling
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Create main frame
        main_frame = ttk.Frame(root)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Add title and status frame
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill="x", pady=(0, 10))

        # Add title label
        title_label = ttk.Label(title_frame, text="Network Intrusion Detection System", font=("Helvetica", 14, "bold"))
        title_label.pack(side="left", pady=(0, 10))

        # Add auto-scroll toggle
        self.auto_scroll = tk.BooleanVar(value=True)
        self.auto_scroll_check = ttk.Checkbutton(
            title_frame, 
            text="Auto-scroll", 
            variable=self.auto_scroll,
            style='Switch.TCheckbutton'
        )
        self.auto_scroll_check.pack(side="right", padx=10)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill="both")

        # Create Malicious Alerts tab
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="Malicious Alerts")

        # Create All Logs tab
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="All Traffic")

        # Set up alert box
        self.setup_text_widget(self.alerts_frame, "alert_box")
        
        # Set up log box
        self.setup_text_widget(self.logs_frame, "log_box")

        # Add status bar
        self.status_frame = ttk.Frame(main_frame)
        self.status_frame.pack(fill="x", pady=(5, 0))
        
        self.status_bar = ttk.Label(self.status_frame, text="Status: Starting...", anchor=tk.W)
        self.status_bar.pack(side="left")
        
        self.packet_counter = ttk.Label(self.status_frame, text="Packets: 0", anchor=tk.E)
        self.packet_counter.pack(side="right")

        # Initialize file monitoring
        self.file_positions = {
            MALICIOUS_LOG_FILE: 0,
            PACKET_LOG_FILE: 0
        }
        self.packet_count = 0
        
        # Configure style for switch
        style = ttk.Style()
        style.configure('Switch.TCheckbutton', font=("Helvetica", 10))

        # Start update loop
        self.running = True
        self.update_thread = threading.Thread(target=self.background_update, daemon=True)
        self.update_thread.start()

    def setup_text_widget(self, parent, name):
        # Create frame for text widget and scrollbars
        frame = ttk.Frame(parent)
        frame.pack(expand=True, fill="both")

        # Add vertical scrollbar
        y_scrollbar = ttk.Scrollbar(frame)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Add horizontal scrollbar
        x_scrollbar = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        # Create text widget with scrollbars
        text_widget = tk.Text(
            frame,
            wrap=tk.NONE,
            yscrollcommand=y_scrollbar.set,
            xscrollcommand=x_scrollbar.set,
            font=("Consolas", 10),
            background="#f0f0f0"
        )
        text_widget.pack(expand=True, fill="both")

        # Configure scrollbars
        y_scrollbar.config(command=text_widget.yview)
        x_scrollbar.config(command=text_widget.xview)

        # Store text widget reference
        setattr(self, name, text_widget)

    def update_text_widget(self, widget, file_path):
        try:
            if not os.path.exists(file_path):
                return 0

            # Get current file size
            current_size = os.path.getsize(file_path)
            
            # Read only new content
            with open(file_path, 'r', encoding='utf-8') as f:
                f.seek(self.file_positions.get(file_path, 0))
                new_content = f.read()
                
                if new_content:
                    # Append new content to widget
                    widget.insert(tk.END, new_content)
                    if self.auto_scroll.get():
                        widget.see(tk.END)
                    
                    # Update packet count for packet log
                    if file_path == PACKET_LOG_FILE:
                        self.packet_count += new_content.count('\n')
                        self.packet_counter.config(text=f"Packets: {self.packet_count}")
                
                # Update file position
                self.file_positions[file_path] = current_size

            return current_size

        except Exception as e:
            self.status_bar.config(text=f"Error reading {file_path}: {str(e)}")
            return 0

    def background_update(self):
        while self.running:
            try:
                # Update malicious alerts
                self.update_text_widget(self.alert_box, MALICIOUS_LOG_FILE)
                
                # Update all logs
                self.update_text_widget(self.log_box, PACKET_LOG_FILE)

                # Update status
                if os.path.exists(MALICIOUS_LOG_FILE) and os.path.exists(PACKET_LOG_FILE):
                    self.status_bar.config(text="Status: Connected - Monitoring")
                else:
                    self.status_bar.config(text="Status: Waiting for log files...")

                # Small delay to prevent high CPU usage
                time.sleep(0.1)

            except Exception as e:
                self.status_bar.config(text=f"Error: {str(e)}")
                time.sleep(1)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to close the NIDS Dashboard?"):
            self.running = False
            self.update_thread.join(timeout=1.0)
            # Kill the main NIDS process if it was started by this GUI
            parent_pid = os.getppid()
            try:
                os.kill(parent_pid, signal.SIGTERM)
            except:
                pass
            self.root.destroy()
            sys.exit(0)

if __name__ == "__main__":
    root = tk.Tk()
    # Apply a modern theme if available
    try:
        style = ttk.Style()
        style.theme_use('clam')  # or 'vista' on Windows
    except:
        pass
    gui = NIDSGUI(root, "password")
    root.mainloop()
