import webbrowser
import time

def open_websites():
    websites = ['http://www.python.org','http://www.kali.org']
    # Open websites in browser
    for website in websites:
        webbrowser.open_new_tab(website)
        time.sleep(2)
        

def main():
    open_websites()
    
if __name__ == '__main__':
    main()