# Requirements: Python 3, PyQt, Qt4

from PyQt4 import QtGui, QtCore
#from mainwindow_dialog import Ui_Dialog as Dlg

import os   # To get filesizes and path
import time  # To get the actual time
import binascii  # To convert hex-strings to ascii
import sys # exits
import csv # To write csv-files
import re # Regex to search for magic bytes in unallocated clusters

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

# Init

programmversion = "0.8"
maxblocksize = 1024 # Delimit block after x bytes, if there cant be found another filename header. 

#Magic Bytes
headerfilename = b"\x02\x01\x00\x01" # In Hex because headerfilename is searched in a binary object, 
                                    # which is then hexlified to a binary without "/x.." an this new object is searched for
                                    # filesize, requests etc using the following binary objects 
headerfilesize = b"03010002"
headertotalupload = b"03010050"
headerrequests = b"03010051"
headeracceptedrequests = b"03010052"
headeruploadpriority = b"03010019"
headerpartname = b"02010012"

# GUI
class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName(_fromUtf8("Dialog"))
        Dialog.setEnabled(True)
        Dialog.resize(650, 500)
        Dialog.setMinimumSize(QtCore.QSize(650, 500))
        Dialog.setMaximumSize(QtCore.QSize(650, 500))
        Dialog.setModal(False)
        self.button_exit = QtGui.QPushButton(Dialog)
        self.button_exit.setGeometry(QtCore.QRect(410, 460, 114, 32))
        self.button_exit.setObjectName(_fromUtf8("button_exit"))
        self.button_help = QtGui.QPushButton(Dialog)
        self.button_help.setGeometry(QtCore.QRect(10, 460, 114, 32))
        self.button_help.setObjectName(_fromUtf8("button_help"))
        self.groupBox_3 = QtGui.QGroupBox(Dialog)
        self.groupBox_3.setGeometry(QtCore.QRect(10, 120, 631, 331))
        self.groupBox_3.setObjectName(_fromUtf8("groupBox_3"))
        self.progressbar = QtGui.QProgressBar(self.groupBox_3)
        self.progressbar.setGeometry(QtCore.QRect(80, 300, 541, 23))
        self.progressbar.setProperty("value", 0)
        self.progressbar.setTextVisible(True)
        self.progressbar.setInvertedAppearance(False)
        self.progressbar.setObjectName(_fromUtf8("progressbar"))
        self.label_4 = QtGui.QLabel(self.groupBox_3)
        self.label_4.setGeometry(QtCore.QRect(10, 300, 71, 16))
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.infotext = QtGui.QTextEdit(self.groupBox_3)
        self.infotext.setGeometry(QtCore.QRect(10, 30, 611, 261))
        self.infotext.setObjectName(_fromUtf8("infotext"))
        self.button_start = QtGui.QPushButton(Dialog)
        self.button_start.setGeometry(QtCore.QRect(530, 460, 114, 32))
        self.button_start.setDefault(True)
        self.button_start.setObjectName(_fromUtf8("button_start"))
        self.groupBox = QtGui.QGroupBox(Dialog)
        self.groupBox.setGeometry(QtCore.QRect(10, 0, 631, 121))
        self.groupBox.setObjectName(_fromUtf8("groupBox"))
        self.layoutWidget_2 = QtGui.QWidget(self.groupBox)
        self.layoutWidget_2.setGeometry(QtCore.QRect(13, 20, 611, 100))
        self.layoutWidget_2.setObjectName(_fromUtf8("layoutWidget_2"))
        self.gridLayout = QtGui.QGridLayout(self.layoutWidget_2)
        self.gridLayout.setMargin(0)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.radio_parse_active = QtGui.QCheckBox(self.layoutWidget_2)
        self.radio_parse_active.setObjectName(_fromUtf8("radio_parse_active"))
        self.gridLayout.addWidget(self.radio_parse_active, 0, 0, 1, 1)
        self.radio_parse_uc = QtGui.QCheckBox(self.layoutWidget_2)
        self.radio_parse_uc.setObjectName(_fromUtf8("radio_parse_uc"))
        self.gridLayout.addWidget(self.radio_parse_uc, 1, 0, 1, 1)
        self.radio_keywords = QtGui.QCheckBox(self.layoutWidget_2)
        self.radio_keywords.setObjectName(_fromUtf8("radio_keywords"))
        self.gridLayout.addWidget(self.radio_keywords, 2, 0, 1, 1)
               
        #slots
        self.connect(self.button_exit, QtCore.SIGNAL("clicked()"), self.exit) 
        self.connect(self.button_help, QtCore.SIGNAL("clicked()"), self.showhelp)
        self.connect(self.button_start, QtCore.SIGNAL("clicked()"),self.startpressed)
        #tooltips
        self.radio_keywords.setToolTip("Parsed filenames will be searches for keywords. Enter path to the textfile containing keywords after pressind the start button.")
        self.radio_parse_active.setToolTip("Recursively search and parse active known.met files. Enter root directory after pressing the start button.")
        self.radio_parse_uc.setToolTip("Carve unallocated space in ftk imager mounted ewf images. Enter volume of mounted image after pressing start.")

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QtGui.QApplication.translate("Dialog", "Forensic Emule Analyzer", None, QtGui.QApplication.UnicodeUTF8))
        self.button_exit.setText(QtGui.QApplication.translate("Dialog", "Exit", None, QtGui.QApplication.UnicodeUTF8))
        self.button_help.setText(QtGui.QApplication.translate("Dialog", "Help", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox_3.setTitle(QtGui.QApplication.translate("Dialog", "Information", None, QtGui.QApplication.UnicodeUTF8))
        self.label_4.setText(QtGui.QApplication.translate("Dialog", "Progress:", None, QtGui.QApplication.UnicodeUTF8))
        self.button_start.setText(QtGui.QApplication.translate("Dialog", "Start", None, QtGui.QApplication.UnicodeUTF8))
        self.groupBox.setTitle(QtGui.QApplication.translate("Dialog", "Jobs", None, QtGui.QApplication.UnicodeUTF8))
        self.radio_parse_active.setText(QtGui.QApplication.translate("Dialog", "Parse active Known.Met files", None, QtGui.QApplication.UnicodeUTF8))
        self.radio_parse_uc.setText(QtGui.QApplication.translate("Dialog", "Parse mounted unallocated space (FTK Imager 3+)", None, QtGui.QApplication.UnicodeUTF8))
        self.radio_keywords.setText(QtGui.QApplication.translate("Dialog", "Check results for keywords", None, QtGui.QApplication.UnicodeUTF8))


class MainDialog(QtGui.QDialog, Ui_Dialog):
    def __init__(self): 
        QtGui.QDialog.__init__(self) 
        self.setupUi(self)        
        self.show()
    
    def exit(self): 
        exitquestion = QtGui.QMessageBox.question(self, "Really Quit?", "Exit Forensic Emule Analyzer?", QtGui.QMessageBox.Yes, QtGui.QMessageBox.No)
        if exitquestion == QtGui.QMessageBox.Yes:
            sys.exit()
   
    def get_active_dir(self):
        global active_dir
        active_dir = QtGui.QFileDialog.getExistingDirectory(parent=None, caption='Select directory to start searching for Known.Met files', directory="")
        
    def get_uc_volume(self):
        global volume_uc_parse
        volume_uc_parse = QtGui.QFileDialog.getExistingDirectory(parent=None, caption='Select volume to parse for deleted Known.Met entries', directory='')
        
        #volume_uc_parse = "E:" #TODO: Can be deleted. For testing...
    
    def writetoinfo(self,infotext):
        self.infotext.append(infotext)
        QtCore.QCoreApplication.instance().processEvents()
        
    def showhelp(self):
        QtGui.QMessageBox.information(self,"Help","Forensic Emule Analyzer Version " + programmversion + ".\n\nWritten by Hex, Bugs and Rock`n Roll. \nHOSTING HIER\n\n\
Emule Analyzer parses unallocated clusters of EnCase Image Files (*.e01) mounted with Access Data`s FTK Imager for deleted known.met records.\n\n\
Mount evidence in FTK Imager as \n\n\
MountType: Physical & Logical\nMount Method: File System / Read Only (IMPORTANT or FEA will not work!).\n\
Drive Letter: This will be the volume for which EmuleAnalyzer will ask\n\n\
EmuleAnalyzer searches and parses active know.met files recursively too.\n\n\
Results can be searched for keywords (eg. child porn codewords). Check the included keywords file for instructions how to make keyword files.\n\n\
All results are written to TAB separated files. \n\nFTK Imager 3.0 or newer required. It is free (as in beer) an can be found at http://accessdata.com/.\n\n\
Regards to Access Data for making this great tool available for free!\n\n\
Double-check the results!") #TODO: Enter Hosting!
        
    def setprogressbarvalue(self, progressvalue):
        self.progressbar.setProperty("value", progressvalue)
        QtCore.QCoreApplication.instance().processEvents() 
              
    def startpressed(self):
        Worker()
    
                
class Worker(object):
    
    def __init__(self):
        self.do_keywordslist = appwindow.radio_keywords.isChecked()
        self.do_activeknownmet = appwindow.radio_parse_active.isChecked()
        self.do_unallocatedclusters = appwindow.radio_parse_uc.isChecked()
        self.process()
        
    def process(self):
        
        if self.do_unallocatedclusters == False and self.do_activeknownmet == False:
            appwindow.infotext.clear()
            appwindow.writetoinfo("Select to parse active known.met file or to carve for known.met entries in unallocated space in FTK Imager 3.0 mounted volume")
        elif self.do_keywordslist == True:
            self.keywordsfilename = QtGui.QFileDialog.getOpenFileName(parent=None, caption='Select textfile with keywords', directory='.',filter="*.txt")
            self.keywordlist = self.getkeywordslist(self.keywordsfilename)
                
        if self.do_unallocatedclusters == True:
            appwindow.get_uc_volume()
        
        if self.do_activeknownmet == True:
            appwindow.get_active_dir()
            
        if self.do_activeknownmet == True or self.do_unallocatedclusters == True:
            self.outputpath = QtGui.QFileDialog.getExistingDirectory(parent=None, caption='Select directory to save results', directory='')
            
        if self.do_unallocatedclusters == True:
            self.parse_uc()

        if self.do_activeknownmet == True:
            self.parseactiveknownmet()

                    
                    
    def getblockofdata (self,i,fobj, filesize): 
    # Seraching a block of data. A block starts with the filenameheader 0x02010001 and ends directly in front of the next
    # filenameheader or it will be delimited at a length of maxblocksizes bytes or at the end of file.  
    
        blockcounter = 0
        fobj.seek((i+6+blockcounter),0)
        headersucher = (fobj.read(4))
    
        while headersucher != headerfilename:
            blockcounter += 1
            
            if i + blockcounter >= filesize:      # Stop at EOF
                break
            elif blockcounter >= maxblocksize:    # Stop when maximal blocksize has been reached
                break
            fobj.seek((i+6+blockcounter),0)
            headersucher = (fobj.read(4))
    
    
        fobj.seek((i),0)
        block =  (fobj.read(blockcounter+6))
        block=binascii.hexlify(block)
        return(block)
    
    def carvefilename(self,block):# Takes offset 8-10 and 10-12 changes byteorder and make an decimal of it
        filenamelength = (block[10:12])
        filenamelength = filenamelength + (block[8:10])
        filenamelength = int(filenamelength,16)
        filename = block[12:((filenamelength*2)+12)]
        filename = binascii.unhexlify(filename)
    
        try: # Try to use filename as an utf-8 string. 
            filename = filename.decode("utf-8")
        except:
            filename = str(filename)
            filename = filename.lstrip("b'")
            filename = filename.rstrip("'")
        
        return str(filename)
    
    def carvefilesize(self,block):
        filesizeentry = "Not Found"
        try:
            indexinblock = block.index(headerfilesize)
            filesizeentry = block[indexinblock+8:indexinblock+16]      # Big endian
            entrylittleendian = filesizeentry[6:8] + filesizeentry[4:6] + filesizeentry[2:4] + filesizeentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
            filesizeentry = int(entrylittleendian,16)  # Litte endian in decimal
            return(filesizeentry)
        except:
            return(filesizeentry)
    
    def carvetotalupload(self,block): 
        totalupload = 0
        try:
            indexinblock = block.index(headertotalupload)
            uploadentry = block[indexinblock+8:indexinblock+16]      # Big endian
            entrylittleendian = uploadentry[6:8] + uploadentry[4:6] + uploadentry[2:4] + uploadentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
            totalupload = int(entrylittleendian,16)  # Litte endian in dezimal
            return(totalupload)
        except:
            return(totalupload)
    
    def carverequests(self,block):
        requests = 0
        try:
            indexinblock = block.index(headerrequests)
            requestsentry = block[indexinblock+8:indexinblock+16]      # Big endian
            entrylittleendian = requestsentry[6:8] + requestsentry[4:6] + requestsentry[2:4] + requestsentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
            requests = int(entrylittleendian,16)  # Litte endian in dezimal
            return(requests)
        except:
            return(requests)
    
    def carveacceptedrequests(self,block):
        acceptedrequests = 0
        try:
            indexinblock = block.index(headeracceptedrequests)
            acceptedrequestssentry = block[indexinblock+8:indexinblock+16]      # Big endian
            entrylittleendian = acceptedrequestssentry[6:8] + acceptedrequestssentry[4:6] + acceptedrequestssentry[2:4] + acceptedrequestssentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
            acceptedrequests = int(entrylittleendian,16)  # Litte endian in dezimal
            return(acceptedrequests)
        except:
            return(acceptedrequests)
    
    def carveuploadpriority(self,block):
        uploadpriority = "Not Found"
        try:
            indexinblock = block.index(headeruploadpriority)
            uploadpriorityentry = block[indexinblock+8:indexinblock+10] # Just one byte needet for upload priority
            if uploadpriorityentry == b"05":
                uploadpriority = "Auto"
            elif uploadpriorityentry == b"00":
                uploadpriority = "Low"
            elif uploadpriorityentry == b"01":
                uploadpriority = "Normal"
            elif uploadpriorityentry == b"02":
                uploadpriority = "High"
            elif uploadpriorityentry == b"03":
                uploadpriority = "Release"
            elif uploadpriorityentry == b"04":
                uploadpriority = "Very Low"
            return(uploadpriority)
        except:
            return(uploadpriority)
    
    def carvepartfile(self,block): 
        partfile = "Not Found"
        try:
            indexinblock = block.index(headerpartname)
            laengepartfile = int(block[indexinblock+10:indexinblock+12] + block[indexinblock+8:indexinblock+10],16)   #read value, change byte order and convert to decimal
            partfile = binascii.unhexlify(partfile)
            partfile = str(partfile)
            partfile = partfile.lstrip("b'")
            partfile = partfile.rstrip("'")
            return(partfile)
        except:
            return(partfile)
    
    def getkeywordstatus(self,filename):
        keywordstatus = "Not Searched"
        if self.do_keywordslist == True:
            keywordstatus = "Not Found"
            for keywordchecker in self.keywordlist:
                if keywordchecker.lower() in filename.lower():
                    keywordstatus = "FOUND !!!"
                    break
        return(keywordstatus)
    
    def getknownmetpaths (self,startdir): # Searches for known.met files. Rekursively, starting at startdir. Case insensitive.
        searchfilename = "known.met"
        foundpathslist = []
    
        for root, dir, name in os.walk(startdir):
            for nametemp in name:
                namelower=nametemp.lower()
                if namelower == searchfilename:
                    foundpath = (os.path.join(root, searchfilename))
                    foundpathslist.append(foundpath)
            
        return(foundpathslist)
    
    def getkeywordslist(self,keywordsfilename): # Builds and returns the list of keywords
        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Building keywordlist\n"))
        
        try: 
            keywordsfile = open(keywordsfilename, "r")
            self.keywordlist = []
            for zeile in keywordsfile:
                if zeile[0] != "#":
                    self.keywordlist.append(zeile[:-1])
            keywordsfile.close()
        except:
            appwindow.writetoinfo("\nERROR: Keywordsfile not loaded!\n")

        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Found " + str(len(self.keywordlist)) + " keywords\n"))
        return(self.keywordlist)
    
    def getlistof_uc_files(self,volumesign):
    
        filesliste=[] # a list with all complete paths and a status flag indicating that the unallocated clusters continue in the next file
        
        pathtouc = os.path.join(volumesign, "[unallocated space]")
        #pathtouc = "/Volumes/MacBook_HD/Downloads/[unallocated space]/" # TODO: For Testing on Mac OSX
        #pathtouc = "F:\\[unallocated space]" # Testing on another system, Win this time
        
        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Gathering information about unallocated clusters. This can take some time.\n"))
        for path, dirs, files in os.walk(pathtouc):   # walks the volume where the uc are mounted and makes a list of an files
            for name in files:
                pathfull = os.path.join(path, name)
                filesliste.append(pathfull)

                filestat = os.stat(pathfull)
                filesize = filestat.st_size
                if filesize == 104857600: #checks if the uc continue in next file using the filesize
                    filesliste.append(1) #Flag 1 for consecutive uc-files
                else:
                    filesliste.append(0) # Flag 0. uc section ending in this file
        return(filesliste)
    
    
    def parseactiveknownmet(self):
          
        filenamelist = []
        filesizelist = []
        totaluploadlist = []
        requestslist = []
        acceptedrequestslist = []
        uploadprioritylist = []
        partnamelist = []
        keywordstatuslist = []
        startdir = active_dir
        
        appwindow.button_start.setDisabled(True)
        appwindow.button_start.setText("Running...")
        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Searching for aktive known.met files starting in " + startdir + "\n"))
        
        foundpathslist = self.getknownmetpaths(startdir)
        
        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Found " + str(len(foundpathslist)) + " known.met file(s)\n"))
    
        knownmetcounter = 0 #Counts if there are more than one known.met files to parse
        for knownmetname in foundpathslist: # Start parsing all found known.met files
            counter = 0     #Counts found filenameheader while parsing
            filesize= os.path.getsize(knownmetname)
            percentdone = (knownmetcounter / len(foundpathslist)) * 100
            appwindow.setprogressbarvalue(percentdone)
            knownmetcounter = knownmetcounter + 1
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Parsing File: %s" % knownmetname + "\n"))
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Filesize: {0:.2f} KB ({1} Bytes)".format((filesize/1024),(str(filesize)))))
            appwindow.writetoinfo("")
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Parsing. Please wait...\n"))
       
            fobj = open(knownmetname, "rb")
            for i in range(filesize):  # i = index. Offset to actual serach position in fileobject
                fobj.seek(i,0)
                charakter = (fobj.read(4))

                if charakter == headerfilename:
                    counter = counter + 1
                    block=self.getblockofdata(i,fobj, filesize)
                    filename = self.carvefilename(block)
                    filesizeentry = self.carvefilesize(block)
                    totalupload = self.carvetotalupload(block)
                    requests = self.carverequests(block)
                    acceptedrequests = self.carveacceptedrequests(block)
                    uploadpriority = self.carveuploadpriority(block)
                    partfile = self.carvepartfile(block)
                    keywordstatus = self.getkeywordstatus(filename)
    
                    filenamelist.append(filename)
                    filesizelist.append(filesizeentry)
                    totaluploadlist.append(totalupload)
                    requestslist.append(requests)
                    acceptedrequestslist.append(acceptedrequests)
                    uploadprioritylist.append(uploadpriority)
                    partnamelist.append(partfile)
                    keywordstatuslist.append(keywordstatus)
    
            fobj.close()
    
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Parsing Ready. Found %d Entries" % counter))
            appwindow.writetoinfo("")
            appwindow.setprogressbarvalue(0)
            
            #writing output of actual known.met file
            outputfile = os.path.join(self.outputpath, ("knownmet_"+ str(knownmetcounter) + "_parsed.csv"))
            
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Writing CSV-File (utf-8) " + outputfile + "\n"))
    
            writer = csv.writer(open(outputfile, "w", encoding = "utf-8", newline=""),"excel-tab") # newline="" needed only in Windows
            writer.writerow(["Filname", "Filesize", "Partfile", "Requests", "Accepted", "Uploaded", "Upload Priority", "Keywords", "Known.met Path"])
    
            listcounter=0
            while listcounter < len(filenamelist): 
                writer.writerow([filenamelist[listcounter], str(filesizelist[listcounter]), str(partnamelist[listcounter]), str(requestslist[listcounter]), str(acceptedrequestslist[listcounter]), str(totaluploadlist[listcounter]), str(uploadprioritylist[listcounter]), str(keywordstatuslist[listcounter]), knownmetname])
                listcounter += 1
    
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Done parsing active known.met file\n"))
    
            #Clearing lists for next known.met file
            filenamelist = []
            filesizelist = []
            totaluploadlist = []
            requestslist = []
            acceptedrequestslist = []
            uploadprioritylist = []
            partnamelist = []
            keywordstatuslist = []
            
        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Done parsing all active known.met files"))
        appwindow.button_start.setDisabled(False)
        appwindow.button_start.setText("Start")
       
    def parse_uc(self):    
        # Lists to take the parsed information
        uc_filenamelist = []
        uc_filesizelist = []
        uc_totaluploadlist = []
        uc_requestslist = []
        uc_acceptedrequestslist = []
        uc_uploadprioritylist = []
        uc_partnamelist = []
        uc_keywordstatuslist = []
    
        uc_parsecounter = 1
        uc_foundblocks = 0

        appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Parsing started\n"))
        appwindow.button_start.setDisabled(True)
        appwindow.button_start.setText("Running...")
          
        filesliste = self.getlistof_uc_files(volume_uc_parse) # Makes a list of all files with the uc
    
        for ucfilenumerator in range(0,len(filesliste),2): # Parsing all files
        #for ucfilenumerator in range(0,20,2): #Parses only the first (0, x/2, 2) files. For testing purposes
            
            mb_list=[] # list to contain offsets of found headerfilename magic bytes
            fobj = open(filesliste[ucfilenumerator], "rb")
            filesize = os.path.getsize(filesliste[ucfilenumerator])
    
            percentdone = int(100 - (((len(filesliste)/2) - uc_parsecounter) * 100) / (len(filesliste)/2))
            appwindow.setprogressbarvalue(percentdone)                      
            appwindow.writetoinfo(("Parsing file " + str(uc_parsecounter) + " of " + str(int(len(filesliste)/2)) + \
                   " (" + str(percentdone) + "%)"))
            appwindow.writetoinfo(("Filename: " + filesliste[ucfilenumerator]))
            appwindow.writetoinfo(("Filesize: " + str(filesize/1024) + " KB"))
            appwindow.writetoinfo(("Possible known.met entries so far: " + str(uc_foundblocks)+"\n"))
                
#            if filesliste[ucfilenumerator + 1] == 1:
#                appwindow.writetoinfo("Contiguous unallocated space found!!!\n\n") #TODO: Parse contiguous uc in two different files
       
            parsefile=fobj.read() #reads one file from the unallocated clusters fileslist
 
            fileiterator = re.finditer(headerfilename, parsefile) #searches for all headerfilename magic bytes in parsefile and makes the iterable object fileiterator
            for index in fileiterator:
                mb_list.append(index.span()[0])
                
            for index in range (0,len(mb_list)): # get a block, check for different special situations
                blockstart = mb_list[index]

                if len(mb_list) == 1 or (index + 1) == len(mb_list):
                    blockend=blockstart + maxblocksize
                elif mb_list[index+1] - mb_list[index] > maxblocksize:
                    blockend=blockstart + maxblocksize
                else:
                    blockend = mb_list[index+1]           
                    
                if blockend - blockstart < 14: #Dont use block if it is too short #TODO: What exactly is "too short"?
                    #print("break")
                    break       
                
                if blockend > len(parsefile):
                    blockend = len(parsefile)
            
                block = parsefile[blockstart:blockend]
                block = binascii.hexlify(block)
                filename = self.carvefilename(block)
                if len(filename) > 255 or len(filename) == 0 or len(filename) > len(block): # Check for plausible filenamelength
                    break
                
                filesizeentry = self.carvefilesize(block)
                totalupload = self.carvetotalupload(block)
                requests = self.carverequests(block)
                acceptedrequests = self.carveacceptedrequests(block)
                uploadpriority = self.carveuploadpriority(block)
                partfile = self.carvepartfile(block)
                keywordstatus = self.getkeywordstatus(filename)
              
                uc_filenamelist.append(repr(filename)) #repr doesn`t print nonprintables
                #uc_filenamelist.append(filename)
                uc_filesizelist.append(filesizeentry)
                uc_totaluploadlist.append(totalupload)
                uc_requestslist.append(requests)
                uc_acceptedrequestslist.append(acceptedrequests)
                uc_uploadprioritylist.append(uploadpriority)
                uc_partnamelist.append(partfile)
                uc_keywordstatuslist.append(keywordstatus)
                uc_foundblocks = uc_foundblocks + 1
                
            fobj.close()
            uc_parsecounter = uc_parsecounter + 1
            
        if len(uc_filenamelist) == 0: #exit if no known.met entries have been found
            appwindow.writetoinfo(time.strftime("%H:%M:%S", time.localtime()) + " No known.met entries in unallocted space found!\n")
            appwindow.button_start.setDisabled(False)
            appwindow.button_start.setText("Start")          
                             
        #Writing TAB separated CSV-File
        if len(uc_filenamelist) > 0:
            appwindow.setprogressbarvalue(0)
            appwindow.writetoinfo((time.strftime("%H:%M:%S", time.localtime()) + " Writing CSV-File (Unallocated Clusters)\n"))
            outputfile = os.path.join(self.outputpath, ("Volume_" + volume_uc_parse[0:-2].upper() + "_Unallocated_Clusters.csv"))
            writer = csv.writer(open(outputfile, "w", encoding = "utf-8", newline=""),"excel-tab",quoting=csv.QUOTE_MINIMAL) # newline="" needed for Windows 
            listcounter=0
            writer.writerow(["Filname", "Filesize", "Partfile", "Requests", \
                             "Accepted", "Uploaded","Upload Priority", "Keywords"])
            uc_singles = set() # set do eliminate double entries
                  
            while listcounter < len(uc_filenamelist):
                        
                writer.writerow((uc_filenamelist[listcounter].strip("'"), str(uc_filesizelist[listcounter]), \
                            uc_partnamelist[listcounter], str(uc_requestslist[listcounter]), \
                            str(uc_acceptedrequestslist[listcounter]), str(uc_totaluploadlist[listcounter]), \
                            uc_uploadprioritylist[listcounter], uc_keywordstatuslist[listcounter]))
                
                uc_singles.add((uc_filenamelist[listcounter].strip("'")) + "\t" + str(uc_filesizelist[listcounter]) + "\t" + \
                            (uc_partnamelist[listcounter]) + "\t" + str(uc_requestslist[listcounter])+ "\t" + \
                            str(uc_acceptedrequestslist[listcounter]) + "\t" + str(uc_totaluploadlist[listcounter])+ "\t" + \
                            (uc_uploadprioritylist[listcounter]) + "\t" + (uc_keywordstatuslist[listcounter]) + "\n")
                
                listcounter += 1
        
            appwindow.writetoinfo(time.strftime("%H:%M:%S", time.localtime()) + " CSV-File written ("+outputfile+")\n")
            appwindow.writetoinfo(time.strftime("%H:%M:%S", time.localtime()) + " Write file without double entries\n")
              
            outputfile = os.path.join(self.outputpath, ("Volume_" + volume_uc_parse[0:-2].upper() + "_Unallocated_Clusters_No_Doubles.csv"))
            outfile = open(outputfile, "w", encoding = "utf-8", newline="") # newline="" needed for Windows
            outfile.write("Filname" + "\t" + "Filesize" + "\t" + "Partfile" + "\t" + "Requests" \
                         + "\t" + "Accepted"  + "\t" + "Uploaded"  + "\t" + "Upload Priority"  + "\t" + "Keywords\n")
            
            for index in uc_singles:
                outfile.write(index)
            outfile.close()    
                
            appwindow.writetoinfo(time.strftime("%H:%M:%S", time.localtime()) + " CSV-File written ("+outputfile+")")  
            appwindow.writetoinfo(time.strftime("\n%H:%M:%S", time.localtime()) + " Parsing unallocated clusters done.")
            appwindow.button_start.setDisabled(False)
            appwindow.button_start.setText("Start")

def main():
    
    app = QtGui.QApplication(sys.argv)
    global appwindow
    appwindow = MainDialog()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()  
      
#TODO: Live Long And Prosper!

