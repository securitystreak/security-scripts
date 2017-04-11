#!/usr/bin/env python
'''
Author: Christopher Duffy
Date: June 2015
Name: multi_threaded.py
Purpose: To identify live web applications with a list of IP addresses, using concurrent threads

Copyright (c) 2015, Christopher Duffy All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met: * Redistributions 
of source code must retain the above copyright notice, this list of conditions and 
the following disclaimer. * Redistributions in binary form must reproduce the above 
copyright notice, this list of conditions and the following disclaimer in the 
documentation and/or other materials provided with the distribution. * Neither the 
name of the nor the names of its contributors may be used to endorse or promote 
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL CHRISTOPHER DUFFY BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import urllib2, argparse, sys, threading, logging, Queue, time
queue = Queue.Queue()
lock = threading.Lock()

class Agent(threading.Thread):
    def __init__(self, queue, logger, verbose):
        threading.Thread.__init__(self)
        self.queue = queue
        self.logger = logger
        self.verbose = verbose

    def run(self):
        while True:
            host = self.queue.get()
            print("[*] Testing %s") % (str(host))
            target = "http://" + host
            target_secure = "https://" + host
            try:
                request = urllib2.Request(target)
                request.get_method = lambda : 'HEAD'
                response = urllib2.urlopen(request)
            except:
                with lock:
                    self.logger.debug("[-] No web server at %s reported by thread %s" % (str(target), str(threading.current_thread().name)))
                    print("[-] No web server at %s reported by thread %s") % (str(target), str(threading.current_thread().name))
                response = None
            if response != None:
                with lock:
                    self.logger.debug("[+] Response from %s reported by thread %s" % (str(target), str(threading.current_thread().name)))
                    print("[*] Response from insecure service on %s reported by thread %s") % (str(target), str(threading.current_thread().name))
                self.logger.debug(response.info())
            try:
                target_secure = urllib2.urlopen(target_secure)
                request_secure.get_method = lambda : 'HEAD'
                response_secure = urllib2.urlopen(request_secure)
            except:
                with lock:
                    self.logger.debug("[-] No secure web server at %s reported by thread %s" % (str(target_secure), str(threading.current_thread().name)))
                    print("[-] No secure web server at %s reported by thread %s") % (str(target_secure), str(threading.current_thread().name))
                response_secure = None
            if response_secure != None:
                with lock:
                    self.logger.debug("[+] Secure web server at %s reported by thread %s" % (str(target_secure), str(threading.current_thread().name)))
                    print("[*] Response from secure service on %s reported by thread %s") % (str(target_secure), str(threading.current_thread().name))
                self.logger.debug(response_secure.info())
            # Execution is complete
            self.queue.task_done()

def main():
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-t hostfile] [-m threads] [-f filename] [-l logfile.log] [-m 2]  -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-t", action="store", dest="targets", default=None, help="Filename for hosts to test")
    parser.add_argument("-f", "--filename", type=str, action="store", dest="filename", default="xml_output", help="The filename that will be used to create an XLSX")
    parser.add_argument("-m", "--multi", action="store", dest="threads", default=1, type=int, help="Number of threads, defaults to 1")
    parser.add_argument("-l", "--logfile", action="store", dest="log", default="results.log", type=str, help="The log file to output the results")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()

    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    if (args.targets == None):
        parser.print_help()
        sys.exit(1)

    # Set Constructors
    targets = args.targets                                                                            # Targets to be parsed
    verbose = args.verbose                                                                            # Verbosity level
    threads = args.threads                                                                            # Threads to be used
    log = args.log                                                                                    # Configure the log output file
    if ".log" not in log:
        log = log + ".log"
    level = logging.DEBUG                                                                             # Logging level
    format = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s") # Log format
    logger_obj = logging.getLogger()                                                                  # Getter for logging agent
    file_handler = logging.FileHandler(args.log)                                                      # File Handler
    #stderr_handler = logging.StreamHandler()                                                          # STDERR Handler
    targets_list = []

    # Configure logger formats for STDERR and output file
    file_handler.setFormatter(format)
    #stderr_handler.setFormatter(format)

    # Configure logger object
    logger_obj.addHandler(file_handler)
    #logger_obj.addHandler(stderr_handler)
    logger_obj.setLevel(level)

    # Load the targets into a list and remove trailing "\n"
    with open(targets) as f:
        targets_list = [line.rstrip() for line in f.readlines()]

    # Spawn workers to access site
    for thread in range(0, threads):
        worker = Agent(queue, logger_obj, verbose)
        worker.setDaemon(True)
        worker.start()

    # Build queue of work
    for target in targets_list:
        queue.put(target)

    # Wait for the queue to finish processing
    queue.join()

if __name__ == '__main__':
    main()
