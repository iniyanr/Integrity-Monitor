import os
import shutil
import hashlib
import json
import time

BASELINE_FILE = "baseline.json"
BACKUP_DIR = "backups"
QUARANTINE_DIR = "quarantine"

def calculate_hash(file_path, algorithm="sha256"):
    hash_func = getattr(hashlib, algorithm)()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def create_baseline(directory):
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
    
    baseline = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            backup_path = os.path.join(BACKUP_DIR, os.path.relpath(file_path, directory))
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            shutil.copy2(file_path, backup_path)  # Create a backup
            
            baseline[file_path] = {
                "hash": calculate_hash(file_path),
                "permissions": oct(os.stat(file_path).st_mode),
                "size": os.path.getsize(file_path),
                "timestamp": os.path.getmtime(file_path),
            }
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

def restore_file(file_path):
    try:
        backup_path = os.path.join(BACKUP_DIR, os.path.relpath(file_path, os.path.dirname(BASELINE_FILE)))
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, file_path)
            return True
        else:
            return False
    except Exception as e:
        print(f"Error restoring file {file_path}: {e}")
        return False

def quarantine_file(file_path):
    """Move a file to the quarantine directory."""
    try:
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
        shutil.move(file_path, quarantine_path)
        return True
    except Exception as e:
        print(f"Error quarantining file {file_path}: {e}")
        return False

def monitor_directory(directory, log_callback, alert_threshold=5):
    """Monitor a directory for integrity changes and handle incidents."""
    if not os.path.exists(BASELINE_FILE):
        create_baseline(directory)
    
    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)
    
    alerts = 0
    while True:
        current_files = {}
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                current_files[file_path] = {
                    "hash": calculate_hash(file_path),
                    "permissions": oct(os.stat(file_path).st_mode),
                    "size": os.path.getsize(file_path),
                    "timestamp": os.path.getmtime(file_path),
                }
                
                if file_path in baseline:
                    baseline_entry = baseline[file_path]
                    if (baseline_entry["hash"] != current_files[file_path]["hash"] or
                        baseline_entry["permissions"] != current_files[file_path]["permissions"] or
                        baseline_entry["size"] != current_files[file_path]["size"] or
                        baseline_entry["timestamp"] != current_files[file_path]["timestamp"]):
                        
                        log_callback(f"Unauthorized change detected in {file_path}")
                        
                        if restore_file(file_path):
                            log_callback(f"File restored to original state: {file_path}")
                        else:
                            if quarantine_file(file_path):
                                log_callback(f"File quarantined: {file_path}")
                            else:
                                log_callback(f"Failed to quarantine file: {file_path}")
                        
                        alerts += 1
                        if alerts >= alert_threshold:
                            log_callback("Alert threshold reached. Taking further action.")
                            return
        
        for file_path in list(baseline.keys()):
            if file_path not in current_files:
                log_callback(f"File deleted: {file_path}")
                alerts += 1
                if alerts >= alert_threshold:
                    log_callback("Alert threshold reached. Taking further action.")
                    return
        
        time.sleep(5)

