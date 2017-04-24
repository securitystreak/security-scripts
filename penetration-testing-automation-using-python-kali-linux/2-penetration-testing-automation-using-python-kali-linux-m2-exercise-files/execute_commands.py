import subprocess

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
    print execute_commands()
    
if __name__ == '__main__':
    main()

