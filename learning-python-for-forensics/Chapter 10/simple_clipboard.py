import win32clipboard as clip
import win32con

clip.OpenClipboard()
print clip.GetClipboardData(win32con.CF_TEXT)
clip.CloseClipboard()
