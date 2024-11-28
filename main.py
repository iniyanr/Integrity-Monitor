import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from monitor import create_baseline, monitor_directory, QUARANTINE_DIR

class IntegrityMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Integrity Monitor")
        self.root.geometry("800x600")
        
        self.monitor_path = tk.StringVar()
        self.alert_threshold = tk.IntVar(value=5)
        self.status_message = tk.StringVar(value="Monitor Status: Idle")
        self.log_messages = []
        self.monitoring = False
        self.rollback_enabled = tk.BooleanVar(value=False)
        self.quarantine_enabled = tk.BooleanVar(value=False)

        self.setup_ui()

    def setup_ui(self):
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)
        
        ttk.Label(top_frame, text="Monitor Path: ").pack(side=tk.LEFT)
        ttk.Entry(top_frame, textvariable=self.monitor_path, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Browse", command=self.browse_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Start Monitoring", command=self.start_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Create Baseline", command=self.create_baseline).pack(side=tk.LEFT, padx=5)

        settings_frame = ttk.LabelFrame(self.root, text="Settings", padding=10)
        settings_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(settings_frame, text="Alert Threshold: ").pack(side=tk.LEFT)
        ttk.Spinbox(settings_frame, from_=1, to=100, textvariable=self.alert_threshold, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(settings_frame, text="Enable Rollback", variable=self.rollback_enabled).pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(settings_frame, text="Enable Quarantine", variable=self.quarantine_enabled).pack(side=tk.LEFT, padx=10)

        status_frame = ttk.Frame(self.root, padding=10)
        status_frame.pack(fill=tk.X)
        
        ttk.Label(status_frame, textvariable=self.status_message, foreground="blue").pack(anchor=tk.W)

        log_frame = ttk.LabelFrame(self.root, text="Activity Log", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.log_box = tk.Text(log_frame, state="disabled", wrap="word")
        self.log_box.pack(fill=tk.BOTH, expand=True)

        controls_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        controls_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(controls_frame, text="View Quarantine", command=self.view_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(controls_frame, text="Exit", command=self.root.quit).pack(side=tk.RIGHT, padx=5)

    def browse_path(self):
        selected_path = filedialog.askdirectory()
        if selected_path:
            self.monitor_path.set(selected_path)

    def log_message(self, message):
        self.log_messages.append(message)
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"{message}\n")
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def create_baseline(self):
        monitor_path = self.monitor_path.get()
        if not monitor_path or not os.path.exists(monitor_path):
            messagebox.showerror("Error", "Invalid path.")
            return
        create_baseline(monitor_path)
        self.log_message(f"Baseline created for: {monitor_path}")

    def start_monitoring(self):
        monitor_path = self.monitor_path.get()
        if not monitor_path or not os.path.exists(monitor_path):
            messagebox.showerror("Error", "Invalid monitor path.")
            return
        
        self.monitoring = True
        self.status_message.set("Monitor Status: Running")
        self.log_message(f"Started monitoring path: {monitor_path}")
        
        self.monitor_thread = threading.Thread(
            target=self.monitor_logic,
            args=(monitor_path,),
            daemon=True
        )
        self.monitor_thread.start()

    def monitor_logic(self, monitor_path):
        try:
            monitor_directory(
                monitor_path,
                log_callback=self.log_message,
                alert_threshold=self.alert_threshold.get()
            )
        except Exception as e:
            self.log_message(f"Error: {e}")
        finally:
            self.monitoring = False
            self.status_message.set("Monitor Status: Idle")

    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            self.status_message.set("Monitor Status: Stopping...")
            self.log_message("Monitoring stopped.")

    def clear_logs(self):
        self.log_messages.clear()
        self.log_box.config(state="normal")
        self.log_box.delete(1.0, "end")
        self.log_box.config(state="disabled")

    def view_quarantine(self):
        if not os.path.exists(QUARANTINE_DIR):
            messagebox.showinfo("Quarantine", "No files are quarantined.")
            return
        files = os.listdir(QUARANTINE_DIR)
        if files:
            quarantined_files = "\n".join(files)
            messagebox.showinfo("Quarantined Files", f"Files in quarantine:\n{quarantined_files}")
        else:
            messagebox.showinfo("Quarantine", "No files are quarantined.")

if __name__ == "__main__":
    root = tk.Tk()
    app = IntegrityMonitorGUI(root)
    root.mainloop()

