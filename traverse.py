import os

# Set the path to the Desktop folder (adjust as needed)
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

# Iterate over all files and directories on the Desktop
for root, dirs, files in os.walk(desktop_path):
    for file_name in files:
        # Full path of the file
        file_path = os.path.join(root, file_name)
        print(f"Found file: {file_path}")
