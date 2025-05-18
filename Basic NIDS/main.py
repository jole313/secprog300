import threading
from capture import start_capture
import gui
from login import LoginScreen
import tkinter as tk

if __name__ == "__main__":
    # Start with login screen

    root = tk.Tk()
    root.title("NIDS Login")
    login = LoginScreen(root)
    root.mainloop()
