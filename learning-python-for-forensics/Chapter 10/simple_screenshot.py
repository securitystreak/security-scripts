import win32con
import win32gui
import win32ui
import time

desktop = win32gui.GetDesktopWindow()
left, top, right, bottom = win32gui.GetWindowRect(desktop)
height = bottom - top
width = right - left

win_dc = win32gui.GetWindowDC(desktop)
ui_dc = win32ui.CreateDCFromHandle(win_dc)

bitmap = win32ui.CreateBitmap()
bitmap.CreateCompatibleBitmap(ui_dc, width, height)

compat_dc = ui_dc.CreateCompatibleDC()
compat_dc.SelectObject(bitmap)

compat_dc.BitBlt((0,0), (width, height), ui_dc, (0,0), win32con.SRCCOPY)
bitmap.Paint(compat_dc)
timestr = time.strftime("_%Y%m%d_%H%M%S")
bitmap.SaveBitmapFile(compat_dc, 'screenshot{}.bmp'.format((timestr)))

ui_dc.DeleteDC()
compat_dc.DeleteDC()
win32gui.ReleaseDC(desktop, win_dc)
win32gui.DeleteObject(bitmap.GetHandle())
