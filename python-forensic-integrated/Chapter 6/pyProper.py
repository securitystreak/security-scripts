#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# See http://sleuthkit.org/autopsy/docs/api-docs/3.1/index.html for documentation

# Simple report module for Autopsy.
# Used as part of Python tutorials from Basis Technology - September 2015


import os
import logging
import jarray
from array import *
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.autopsy.casemodule.services import FileManager

# List of English Language stop words.  These words may be
# capitalized in text documents, but provide little probative
# value, therefore they will be ignored if detected during the 
# search. Stop words exist in virtually every language and
# many versions of stop words exist.  I have put this list together
# over time and found it to be effective in eliminating
# words that are not of interest.

stopWords =["able","about","above","accordance","according",
            "accordingly","across","actually","added","affected",
            "affecting","affects","after","afterwards","again",
            "against","almost","alone","along","already","also",
            "although","always","among","amongst","announce",
            "another","anybody","anyhow","anymore","anyone",
            "anything","anyway","anyways","anywhere","apparently",
            "approximately","arent","arise","around","aside",
            "asking","auth","available","away","awfully","back",
            "became","because","become","becomes","becoming",
            "been","before","beforehand","begin","beginning",
            "beginnings","begins","behind","being",
            "believe","below","beside","besides","between",
            "beyond","both","brief","briefly","came","cannot",
            "cause","causes","certain","certainly","come",
            "comes","contain","containing","contains","could",
            "couldnt","date","different","does","doing","done",
            "down","downwards","during","each","effect","eight",
            "eighty","either","else","elsewhere","end",
            "ending","enough","especially","even","ever",
            "every","everybody","everyone","everything",
            "everywhere","except","fifth","first","five",
            "followed","following","follows","former","formerly",
            "forth","found","four","from","further",
            "furthermore","gave","gets","getting",
            "give","given","gives","giving","goes",
            "gone","gotten","happens","hardly","has","have",
            "having","hence","here","hereafter","hereby",
            "herein","heres","hereupon","hers","herself",
            "himself","hither","home","howbeit","however",
            "hundred","immediate","immediately","importance",
            "important","indeed","index","information",
            "instead","into","invention","inward","itself",
            "just","keep","keeps","kept","know","known",
            "knows","largely","last","lately","later","latter",
            "latterly","least","less","lest","lets","like",
            "liked","likely","line","little","look","looking",
            "looks","made","mainly","make","makes","many",
            "maybe","mean","means","meantime","meanwhile",
            "merely","might","million","miss","more","moreover",
            "most","mostly","much","must","myself","name",
            "namely","near","nearly","necessarily","necessary",
            "need","needs","neither","never","nevertheless",
            "next","nine","ninety","nobody","none","nonetheless",
            "noone","normally","noted","nothing","nowhere",
            "obtain","obtained","obviously","often","okay",
            "omitted","once","ones","only","onto","other",
            "others","otherwise","ought","ours","ourselves",
            "outside","over","overall","owing","page","pages",
            "part","particular","particularly","past","perhaps",
            "placed","please","plus","poorly","possible","possibly",
            "potentially","predominantly","present","previously",
            "primarily","probably","promptly","proud","provides",
            "quickly","quite","rather","readily","really","recent",
            "recently","refs","regarding","regardless",
            "regards","related","relatively","research",
            "respectively","resulted","resulting","results","right",
            "run","said","same","saying","says","section","see",
            "seeing","seem","seemed","seeming","seems","seen",
            "self","selves","sent","seven","several","shall",
            "shed","shes","should","show","showed","shown",
            "showns","shows","significant","significantly",
            "similar","similarly","since","slightly","some",
            "somebody","somehow","someone","somethan",
            "something","sometime","sometimes","somewhat",
            "somewhere","soon","sorry","specifically","specified",
            "specify","specifying","still","stop","strongly",
            "substantially","successfully","such","sufficiently",
            "suggest","sure","take","taken","taking","tell",
            "tends","than","thank","thanks","thanx","that",
            "thats","their","theirs","them","themselves","then",
            "thence","there","thereafter","thereby","thered",
            "therefore","therein","thereof","therere",
            "theres","thereto","thereupon","there've","these",
            "they","think","this","those","thou","though","thought",
            "thousand","through","throughout","thru","thus",
            "together","took","toward","towards","tried","tries",
            "truly","trying","twice","under","unfortunately",
            "unless","unlike","unlikely","until","unto","upon",
            "used","useful","usefully","usefulness","uses","using",
            "usually","value","various","very","want","wants",
            "was","wasnt","welcome","went","were","what","whatever",
            "when","whence","whenever","where","whereafter","whereas",
            "whereby","wherein","wheres","whereupon","wherever",
            "whether","which","while","whim","whither","whod",
            "whoever","whole","whom","whomever","whos","whose",
            "widely","willing","wish","with","within","without",
            "wont","words","world","would","wouldnt",
            "your","youre","yours","yourself","yourselves"] 

####################
# Function
# Name: ExtractProperNames
# Purpose: Extract possible proper names from the passed string
# Input: string
# Return: Dictionary of possible Proper Names along with the number of 
#         of occurrences as a key, value pair
# Usage: theDictionary = ExtractProperNames('John is from Alaska')
####################

def ExtractProperNames(theBuffer):

    # Prepare the string (strip formatting and special characters)
    # You can extend the set of allowed characters by adding to the string
    # Note 1: this example assumes ASCII characters not unicode
    # Note 2: You can expand the allowed ASCII characters that you
    #         choose to include for valid proper name searches
    #         by modifying this string.  For this example I have kept
    #         the list simple.
    
    allowedCharacters ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    finalString = ''
    
    # Notice that you can write Python like English if you choose your 
    #    words carefully
    
    # Process each character in the theString passed to the function

    for eachCharacter in theBuffer:

        # Check to see if the character is in the allowedCharacter string
        if eachCharacter in allowedCharacters:
            # Yes, then add the character to the finalString
            finalString = finalString + eachCharacter
        else:
            # otherwise replace the not allowed character 
            #    with a space
            finalString = finalString + ' '
    
    # Now that we only have allowed characters or spaces in finalString
    #     we can use the built in Python string.split() method
    # This one line will create a list of words contained in the finalString
        
    wordList = finalString.split()
    
    # Now, let's determine which words are possible proper names
    #     and create a list of them.
    
    # We start by declaring an empty list
    
    properNameList = []

    # For this example we will assume words are possible proper names
    #    if they are in title case and they meet certain length requirements
    # We will use a Min Length of 4 and a Max Length of 20  
     
    # To do this, we loop through each word in the word list
    #    and if the word is in title case and the word meets
    #    our minimum/maximum size limits we add the word to the properNameList
    # We utilize the Python built in string method string.istitle() 
    #
    # Note: I'm setting minimum and maximum word lengths that
    #       will be considered proper names.  You can adjust these
    #       psuedo constants for your situation.  Note if you make
    #       the MIN_SIZE smaller you should also update the StopWord
    #       list to include smaller stop words.
    
    MIN_SIZE = 4
    MAX_SIZE = 20
    
    for eachWord in wordList:
        
        if eachWord.istitle() and len(eachWord) >= MIN_SIZE and len(eachWord) <= MAX_SIZE:
            # if the word meets the specified conditions we add it
            # and it is not a common stop word 
            # we add it to the properNameList            

            if eachWord.lower() not in stopWords:
                properNameList.append(eachWord)
        else:
            # otherwise we loop to the next word
            continue

    # Note this list will likely contain duplicates to deal with this
    #    and to determine the number of times a proper name is used
    #    we will create a Python Dictionary
    
    # The Dictionary will contain a key, value pair.
    # The key will be the proper name and value is the number of occurrences
    #     found in the text

    # Create an empty dictionary
    properNamesDictionary = {}

    # Next we loop through the properNamesList
    for eachName in properNameList:
        
        # if the name is already in the dictionary
        # the name has been processed increment the number
        # of occurrences, otherwise add a new entry setting
        # the occurrences to 1

        if eachName in properNamesDictionary:
            cnt = properNamesDictionary[eachName]
            properNamesDictionary[eachName] = cnt+1
        else:
            properNamesDictionary[eachName] = 1
    
    # Once all the words have been processed
    # the function returns the created properNamesDictionary
    
    return properNamesDictionary

# End Extract Proper Names Function


# Class responsible for defining module metadata and logic
class CSVReportModule(GeneralReportModuleAdapter):

    # This defines the Report name
    moduleName = "Proper Names Report"

    _logger = None
    def log(self, level, msg):
        if _logger == None:
            _logger = Logger.getLogger(self.moduleName)

        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Extracts Possible Proper Names"

    def getRelativeFilePath(self):
        return "prop.txt"

    # The 'baseReportDir' object being passed in is a string 
    # with the directory that reports are being stored in.   
    # Report should go into baseReportDir + getRelativeFilePath().
    # The 'progressBar' object is of type ReportProgressPanel.
    #   See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    
    def generateReport(self, baseReportDir, progressBar):

        # Open the output file.
        fileName = os.path.join(baseReportDir, self.getRelativeFilePath())
        report = open(fileName, 'w')

        # Query the database for the files (ignore the directories)
        sleuthkitCase = Case.getCurrentCase().getSleuthkitCase()
        files = sleuthkitCase.findAllFilesWhere("NOT meta_type = " + str(TskData.TSK_FS_META_TYPE_ENUM.TSK_FS_META_TYPE_DIR.getValue()))

        # Setup progress Indicator
        progressBar.setIndeterminate(False)
        progressBar.start()
        progressBar.setMaximumProgress(len(files))        

        for file in files:
            # For this script I will limit the processing
            # to files with .txt extensions only
            
            if file.getName().lower().endswith(".txt"):
                
                # Setup to Read the contents of the file.
                                   
                # Create a Python string to hold the file contents
                # for processing
                fileStringBuffer = ''  
                
                # Setup an inputStream to read the file
                inputStream = ReadContentInputStream(file)    
                              
                # Setup a jarry buffer to read chunks of the file
                # we will read 1024 byte chunks
                
                buffer = jarray.zeros(1024, "b")
                
                # Attempt to read in the first Chunk
                bytesRead = inputStream.read(buffer)
                
                # Continue reading until finished reading
                # the file indicated by -1 return from
                # the inputStream.read() method
                
                while (bytesRead != -1):
                    
                    for eachItem in buffer:
                        # Now extract only potential ascii characters from the
                        # buffer and build the final Python string 
                        # that we will process. 
                        
                        if eachItem >= 0 and eachItem <= 255:
                            fileStringBuffer = fileStringBuffer + chr(eachItem)
                    
                    # Read the next file Chunk
                    bytesRead = inputStream.read(buffer)
                 
                # Once the complete file has been read and the
                # possible ASCII characters have been extracted
                
                # The ExtractProperNames Function 
                # will process the contents of the file
                # the result will be returned as a Python
                # dictionary object

                properNamesDictionary = ExtractProperNames(fileStringBuffer)
                               
                # For each file processed     
                # Write the information to the Report
                # File Name, along with each possible proper name
                # found, with highest occurring words order
                
                report.write("\n\nProcessing File: "+ file.getUniquePath() + "\n\n") 
                report.write("Possible Name        Occurrences \n")
                report.write("-------------------------------- \n")
                
                for eachName in sorted(properNamesDictionary, key=properNamesDictionary.get, reverse=True):   
                    theName = '{:20}'.format(eachName)
                    theCnt  = '{:5d}'.format(properNamesDictionary[eachName])
                    report.write(theName + theCnt + "\n")                      
            
            # Increment the progress bar for each
            # file processed
            progressBar.increment()
            
            # Process the Next File
                
        # Close the report and post ProgressBar Complete
        progressBar.complete(ReportStatus.COMPLETE)
        report.close()

        # Add the report to the Case
        Case.getCurrentCase().addReport(fileName, self.moduleName, "Prop Report")
