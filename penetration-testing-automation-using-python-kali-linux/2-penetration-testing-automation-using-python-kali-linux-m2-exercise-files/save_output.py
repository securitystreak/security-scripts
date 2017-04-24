import subprocess
import os
import webbrowser
import time

def open_websites():
    websites = ['http://www.python.org','http://www.kali.org']
    # Open websites in browser
    for website in websites:
        webbrowser.open_new_tab(website)
        time.sleep(2)
        
def save_results(results,folder_name,file_name):
    try:
        # Create a directory for the category e.g reconnissance or external scanning ...
        if not os.path.isdir(folder_name):
            os.mkdir(folder_name)
        # Save the results to a file
        file_name = folder_name + '/'+ file_name
        file_to_save = open(file_name,'w')
        file_to_save.write(results)
        file_to_save.close()
    except Exception,e:
        print '[!] Error: Cannot save the results to a file!'

def open_terminal(app_name,cmd):
    output = '[+] Executing ' + str(app_name) + '...\r\n'
    try:
        output += subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT)
        output += '\r\n'
    except Exception,e:
        output += str(e)
    output +=  '---------------------------\r\n'
    return output

def execute_commands():
    #Execute commands in terminal
    commands = {"list files":"ls","current directory":"pwd"}
    results = ''
    for key,val in commands.items():
        output = open_terminal(key,val)
        results += output
    return results

def main():
    results = execute_commands()
    print results
    
    # Save the terminal results
    save_results(results, 'results', 'reports.txt')
    
    #open web browser
    open_websites()    
    
if __name__ == '__main__':
    main()
