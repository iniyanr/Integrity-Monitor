---
# Integrity Monitor

Integrity Monitor is a security tool designed to track and monitor the integrity of critical files and directories on your system. It detects unauthorized changes, suspicious file additions, and enables automatic rollback or quarantine actions for compromised files. Additionally, it provides an easy-to-use graphical interface for configuration and management.

## Features

- **Real-time Monitoring**: Continuously monitors files and directories for any changes such as modifications, deletions, or additions.
- **Suspicious File Detection**: Identifies and quarantines unknown files that are not part of the baseline.
- **Baseline Comparison**: Generates a baseline of monitored files, comparing the current state with the original to detect changes.
- **Hashing**: Uses SHA-256 hashing to verify file integrity.
- **Rollback Mechanism**: Allows automatic restoration of files to their previous state upon unauthorized changes.
- **Quarantine Mode**: Isolates suspicious files in a dedicated quarantine folder to prevent further compromise.
- **Configurable Alerts**: Set alert thresholds for monitoring frequency and choose whether rollback and quarantine features are enabled.
- **Log Viewer**: View detailed logs of all detected events, including file changes and quarantined files.
- **User-Friendly GUI**: An interactive graphical user interface built with Tkinter for easy monitoring and configuration.

## Requirements

- **Python 3.x** (Recommended: Python 3.6 or higher)
- **Tkinter**: Python library for building the graphical user interface.
- **hashlib**: Python library for calculating file hashes.
- **os** and **shutil**: For filesystem operations (moving files, checking paths, etc.).

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/iniyanr/Integrity-Monitor
   cd integrity-monitor
   ```


3. Ensure you have Python 3.x and Tkinter installed (Tkinter is included by default in most Python distributions).

## Usage

### Running the Application

1. **Start the GUI**:
   To launch the Integrity Monitor GUI, run the following command:
   ```bash
   python main.py
   ```

2. **Select Directory to Monitor**:
   - Click on **Browse** to select the directory you want to monitor.
   - Once selected, click **Start Monitoring** to begin monitoring the directory for changes.

3. **Create a Baseline**:
   - Before monitoring, create a baseline of file hashes by clicking **Create Baseline**. This baseline will be used to compare with the current state to detect any changes.

4. **View and Manage Quarantine**:
   - If any suspicious files are detected or if a file's integrity is compromised, the file will be moved to the quarantine folder.
   - Click **View Quarantine** to see a list of all quarantined files.

5. **Enable/Disable Rollback and Quarantine**:
   - In the settings, you can enable or disable the automatic rollback and quarantine features depending on your security requirements.

6. **Monitor Logs**:
   - All events, such as file modifications, suspicious file detection, and quarantined files, are logged in the **Activity Log** section for later review.

7. **Stop Monitoring**:
   - When you're finished monitoring, click **Stop Monitoring** to end the process.

### Example of Suspicious File Detection

When a new, unknown file is added to the monitored directory (i.e., not part of the baseline), it will be flagged as suspicious. The system will automatically quarantine this file to prevent any potential security risks.

## Configuration

The following configuration options can be adjusted in the GUI:
- **Alert Threshold**: The threshold for generating alerts based on changes or modifications.
- **Enable Rollback**: Toggle the option to automatically restore files to their previous state upon detection of unauthorized changes.
- **Enable Quarantine**: Enable or disable the automatic quarantining of suspicious or modified files.

## Directory Structure

- `main.py`: The main graphical user interface for the Integrity Monitor.
- `monitor.py`: The backend script responsible for monitoring file integrity, creating baselines, detecting changes, and handling quarantine.
- `baseline/`: Directory where file hashes and baseline data are stored.
- `quarantine/`: Directory where suspicious files are moved and isolated.

## Troubleshooting

- **Error: "No files are quarantined"**:
  - This message appears if no suspicious files have been flagged and quarantined yet. Ensure that files are being monitored correctly and that any new, unknown files are being detected.

- **Error: "Invalid path"**:
  - Ensure that the directory you have selected exists and is accessible.

