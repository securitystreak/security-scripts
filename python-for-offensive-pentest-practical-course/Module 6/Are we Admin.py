import ctypes


if ctypes.windll.shell32.IsUserAnAdmin() == 0:
    print '[-] We are NOT admin! '
else:
    print '[+] We are admin :) '
    
