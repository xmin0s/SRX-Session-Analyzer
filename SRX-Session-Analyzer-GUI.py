import tkinter
from tkinter import *
from tkinter import ttk
from tkinter import StringVar
from tkinter import filedialog
from tkinter import messagebox
from tkinter.ttk import *
import os
import re
import sys
import math
import string
import operator 

##########################################################
##########################################################
# Written by Tim Eberhard
# Requires Python 3.0 or above
# For bugs or feature additions please contact:
# xmin0s@gmail.com
# If you managed to get the source code for this, please do not steal/borrow any of it without my permission
# I spent a lot of time on the filters and they are mine. Please get permission from me to reuse it or change.
#
#To do:
# -Process the XML data directly vs the formatted output. XML data shouldn't change as often.
# -Once the XML backend is built it'd be nice to build a netconf interface to pull the data directly. 
# -Write various plugins to analyze log/traceoption files as well. 
#
#
#History:
#12/08/11 - Version 1.5 - Added the first set of plugins for SRX Session Analyzer. These plugins can analyze traffic log files (syslog or locally logged)
#             and give you the ability to parse for top talkers by various data points. Needs additional testing as it's only been tested on 11.2 syslog output.
#12/07/11 - Version 1.3 - Added some basic GUI items, file, edit, plugins and help. Fixed a couple of minor bugs.
#12/02/11 - Version 1.2 - Fixed the "all" option within the drop down menu. Previously this didn't work.
#11/03/11 - Version 1.1 - Minor bug fixes and code clean up. Added protocol lookup (much like port lookups). 
#10/14/11 - Version 1.0 - Base version released. It does basic top 10 with filters
# How to use Session Analyzer:
#	1)Login to your SRX and save off the session table:
#		show security flow session | save sessiontable.txt
#
#	2)Then copy off the session table to your local box and load it into the SRX Session Analyzer program.
#	3)Select the filters and the number of results you wish to be displayed
#	4)Hit the Analyze Session table button. 
#	5)Enjoy!
#
# Plugins:
#	There are three plugins currently written. All analyze traffic log files (either local on the box that have been downloaded)
#	or data stored on a syslog server. Either way.. you can analyzer three types of log entries. There are multiple filters in place to show you top talkers
#	by source/dest, service, policy, bytes, zones, and how your session was closed. 
#
#	1) Session Create - These are logs are created when 'log session init' is configured on the policy. This log entry means a session has been opened. 
#	2) Session Close - These are logs are created when 'log session close' is configured on the policy. This log entry means a session has been removed from the session table.
#	3) Session Deny - These are logs when logging is configured on a deny policy and the traffic was dropped. 
#
#	I wrote these log file plugins because the session analyzer is real time, and there are no SRX specific log analyzers out there for historical analyzing of traffic patterns. 
#	Juniper sells the STRM box for this but many customers cannot justify that kind of cost. These plugins are very beta, if you have feedback, a feature request or just want to
#	tell me it sucks, feel free to email me.
#
#
#
##########################################################

"""
Just a quick example of a session to parse. 11.2r2.5
juniper@SRX240Template> show security flow session
Session ID: 42598, Policy name: self-traffic-policy/1, Timeout: 1782, Valid
  In: 172.16.10.1/53024 --> 172.16.10.2/179;tcp, If: .local..0, Pkts: 11557, Bytes: 710954
  Out: 172.16.10.2/179 --> 172.16.10.1/53024;tcp, If: ge-0/0/14.0, Pkts: 11553, Bytes: 710746
"""

"""
Nov  3 19:06:50  SRX220RGA RT_FLOW: RT_FLOW_SESSION_DENY: session denied 88.198.106.22/0->67.52.223.15/0 ICMP 1(3) unknown untrust unknown ICMP ICMP unknown(unknown) ge-0/0/7.0
 session denied source-address/source-port->destination-address/destination-port service-name protocol-id(icmp-type) policy-name source-zone-name destination-zone-nam

Dec  6 13:10:49  SRX220RGA RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.183.1.1/16138->10.194.201.112/9100 None 10.183.1.1/16138->192.168.168.12/9100 None vpn_printer 6 default-permit vpn trust 60756 N/A(N/A) st0.0
 session created source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-3

Dec  6 13:11:20  SRX220RGA RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 10.183.1.1/16138->10.194.201.112/9100 None 10.183.1.1/16138->192.168.168.12/9100 None vpn_printer 6 default-permit vpn trust 60756 98(78354) 56(2986) 31   N/A(N/A) st0.0
 session closed reason: source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name
destination-zone-name session-id-32 packets-from-client(bytes-from-client) packets-from-server(bytes-from-server) elapsed-tim
"""



#Basic stuff to use for later. This is static and should never change.
protocolnum = {0:" HOPOPT ", 1: "ICMP", 2: "IGMP", 3: "GGP ", 4: "IP ", 5: "ST ", 6: "TCP ", 7: "CBT ", 8: "EGP ", 9: "IGP ", 10: "BBN-RCC-MON ", 11: "NVP-II ", 12: "PUP ", \
13: "ARGUS ", 14: "EMCON ", 15: "XNET ", 16: "CHAOS ", 17: "UDP ", 18: "MUX ", 19: "DCN-MEAS ", 20: "HMP ", 21: "PRM ", 22: "XNS-IDP ", 23: "TRUNK-1 ", 24: "TRUNK-2 ", \
25: "LEAF-1 ", 26: "LEAF-2 ", 27: "RDP ", 28: "IRTP ", 29: "ISO-TP4 ", 30: "NETBLT ", 31: "MFE-NSP ", 32: "MERIT-INP ", 33: "DCCP ", 34: "3PC ", 35: "IDPR ", 36: "XTP ", \
37: "DDP ", 38: "IDPR-CMTP ", 39: "TP++ ", 40: "IL ", 41: "IPv6 ", 42: "SDRP ", 43: "IPv6-Route ", 44: "IPv6-Frag ", 45: "IDRP ", 46: "RSVP ", 47: "GRE ", 48: "DSR ", \
49: "BNA ", 50: "ESP ", 51: "AH ", 52: "I-NLSP ", 53: "SWIPE ", 54: "NARP ", 55: "MOBILE ", 56: "TLSP ", 57: "SKIP ", 58: "IPv6-ICMP ", 59: "IPv6-NoNxt ", 60: "IPv6-Opts ", \
61: "any ", 62: "CFTP ", 63: "any ", 64: "SAT-EXPAK ", 65: "KRYPTOLAN ", 66: "RVD ", 67: "IPPC ", 68: "any ", 69: "SAT-MON ", 70: "VISA ", 71: "IPCV ", 72: "CPNX ", \
73: "CPHB ", 74: "WSN ", 75: "PVP ", 76: "BR-SAT-MON ", 77: "SUN-ND ", 78: "WB-MON ", 79: "WB-EXPAK ", 80: "ISO-IP ", 81: "VMTP ", 82: "SECURE-VMTP ", 83: "VINES ", \
84: "TTP ", 85: "NSFNET-IGP ", 86: "DGP ", 87: "TCF ", 88: "EIGRP ", 89: "OSPFIGP ", 90: "Sprite-RPC ", 91: "LARP ", 92: "MTP ", 93: "AX.25 ", 94: "IPIP ", 95: "MICP ", \
96: "SCC-SP ", 97: "ETHERIP ", 98: "ENCAP ", 99: "any ", 100: "GMTP ", 101: "IFMP ", 102: "PNNI ", 103: "PIM ", 104: "ARIS ", 105: "SCPS ", 106: "QNX ", 107: "A/N ", \
108: "IPComp ", 109: "SNP ", 110: "Compaq-Peer ", 111: "IPX-in-IP ", 112: "VRRP ", 113: "PGM ", 114: "any ", 115: "L2TP ", 116: "DDX ", 117: "IATP ", 118: "STP ", \
119: "SRP ", 120: "UTI ", 121: "SMP ", 122: "SM ", 123: "PTP ", 124: "ISIS over IPv4 ", 125: "FIRE ", 126: "CRTP ", 127: "CRUDP ", 128: "SSCOPMCE ", 129: "IPLT ", \
130: "SPS ", 131: "PIPE ", 132: "SCTP ", 133: "FC ", 134: "RSVP-E2E-IGNORE ", 135: "Mobility Header  ", 136: "UDPLite ", 137: "MPLS-in-IP ", \
138-252: "Unassigned ", 253: "Use for experimentation and testing ", 254: "Use for experimentation and testing ", 255: "Reserved"}




versionnum = "1.5 Beta"
class Application:
    def __init__(self, root):

        #Create the root tk 
        self.root = root
        self.root.title('SRX Session Analyzer')

        #init the widgets. 
        self.init_widgets()
            
            
    def init_widgets(self):
       #Hacks-a-plenty
        self.sourceipf = False
        self.sourceportf = False
        self.destinationipf = False
        self.destinationportf = False
        self.protocolf = False
        self.policyf = False
        self.interfacef = False
        self.packetf = False
        self.bytef = False
        self.sourceipcreatelogf = False
        self.destinationipcreatelogf = False
        self.sourceportcreatelogf = False
        self.destinationportcreatelogf = False
        self.servicecreatelogf = False
        self.protocolcreatelogf = False
        self.policycreatelogf = False
        self.sourcezonecreatelogf = False
        self.destinationzonecreatelogf = False
        self.sourceipcloselogf = False
        self.destinationipcloselogf = False
        self.sourceportcloselogf = False
        self.destinationportcloselogf = False
        self.servicecloselogf = False
        self.protocolcloselogf = False
        self.policycloselogf = False
        self.sourcezonecloselogf = False
        self.destinationzonecloselogf = False
        self.closetypecloselogf = False
        self.bytesfromclientcloselogf = False
        self.bytesfromservercloselogf = False
        self.sessionlengthcloselogf = False
        self.sourceipdenylogf = False
        self.destinationipdenylogf = False
        self.sourceportdenylogf = False
        self.destinationportdenylogf = False
        self.servicedenylogf = False
        self.protocoldenylogf = False
        self.policydenylogf = False
        self.sourcezonedenylogf = False
        self.destinationzonedenylogf = False        
        
        self.filename = False
        
        #Number of results to be displayed
        self.rawnumdisplayed = StringVar()
        
        self.content = ttk.Frame(self.root)
        self.frame = ttk.Frame(self.content, borderwidth=5, relief="sunken", width=50, height=500)     		
        self.frame2 = ttk.Frame(self.content, borderwidth=5, relief="sunken", width=100, height=100)
        self.content.grid(column=0, row=0)
        self.frame.grid(column=0, row=0, columnspan=3, rowspan=2)		
        self.frame2.grid(column=10, row=1, sticky='nw', columnspan=3)		




        #Standard Menu bar. Things like file, edit, help, etc go here.
        self.menu = Menu(tearoff=False)
        self.root.config(menu = self.menu)
        filemenu = self.file_menu = None
        filemenu = Menu(self.menu, tearoff = False)
        editmenu = Menu(self.menu, tearoff = False)
        plugmenu = Menu(self.menu, tearoff = False)
        helpmenu = Menu(self.menu, tearoff = False)
        
        
        self.menu.add_cascade(label='File', menu = filemenu)
        self.menu.add_cascade(label='Edit', menu = editmenu)
        self.menu.add_cascade(label='Plugins', menu = plugmenu)
        self.menu.add_cascade(label='Help', menu = helpmenu)


        #File Menu Bar
        filemenu.add_command(label="Load Session table", command=self.loadsessiontable)
        filemenu.add_separator()
        filemenu.add_command(label='Quit', command=self.root.quit)

        #Edit Menu Bar
        editmenu.add_command(label="Copy Output To Clipboard", command=self.copyoutput)
        editmenu.add_command(label="Clear", command=self.cleartext)
        

        #Plugin Menu Bar
        plugmenu.add_command(label="Load Traffic Session Log File - Session Flow Created", command=self.createloganalyzerdialog)
        plugmenu.add_command(label="Load Traffic Session Log File - Session Flow Closed", command=self.closeloganalyzerdialog)    
        plugmenu.add_command(label="Load Traffic Session Log File - Session Flow Deny", command=self.denyloganalyzerdialog)

        #Help Menu Bar
        helpmenu.add_command(label="About", command=self.aboutme)






        self.vlabel = ttk.Label(self.content, text="SRX Session Analyzer - Version: %s" %(versionnum))
        self.vlabel.grid(column=10, row=0, sticky='w') 	

        #self.vlabel = ttk.Label(self.content, text=versionnum)
        #self.vlabel.grid(column=11, row=0, sticky='e')		

		
        #A text box to output stuff.
        self.txt = tkinter.Text(self.frame2, width=100, height=20)
        self.txt.grid(column=4, row=1, sticky='w')
        
        #A scroll bar for our text box.
        sb = ttk.Scrollbar(self.frame2, command=self.txt.yview, orient='vertical')
        sb.grid(column=30, row=1, sticky='ns')
        self.txt['yscrollcommand'] = sb.set
		
   
        #This is a simple button. Given a name and a command or action. Belonging to self.frame
        self.btn = ttk.Button(self.frame, command=self.loadsessiontable, text='Load Session Table', width=16) 
        self.btn.grid(column=0, row=0, sticky='nw', pady= 20)
        
        self.dropboxlabel = ttk.Label(self.frame, text="Number of Results")
        self.dropboxlabel.grid(column=0, row=9, sticky='w')

        self.combobox = ttk.Combobox(self.frame, textvariable=self.rawnumdisplayed, values=('10', '20', '30', '40', '50', 'all'))
        
        self.combobox.grid(column=0, row=10, sticky='w')

        self.dropboxlabel = ttk.Label(self.frame, text="Filters:")
        self.dropboxlabel.grid(column=0, row=29, sticky='w', pady= 10)
		
        self.checkbutton = ttk.Checkbutton(self.frame, text="Source IP Filter", command=self.sourceipfilter)
        self.checkbutton.grid(column=0, row=30, sticky='w')
        
        self.checkbutton2 = ttk.Checkbutton(self.frame, text="Destination IP Filter", command=self.destinationipfilter)
        self.checkbutton2.grid(column=0, row=40, sticky='w')

        self.checkbutton3 = ttk.Checkbutton(self.frame, text="Source Port Filter", command=self.sourceportfilter)
        self.checkbutton3.grid(column=0, row=50, sticky='w')        

        self.checkbutton4 = ttk.Checkbutton(self.frame, text="Destination Port Filter", command=self.destinationportfilter)
        self.checkbutton4.grid(column=0, row=60, sticky='w')		

        self.checkbutton6 = ttk.Checkbutton(self.frame, text="Protocols", command=self.protocolfilter)
        self.checkbutton6.grid(column=0, row=80, sticky='w')	

        self.checkbutton7 = ttk.Checkbutton(self.frame, text="Policies", command=self.policyfilter)
        self.checkbutton7.grid(column=0, row=90, sticky='w')	

        self.checkbutton8 = ttk.Checkbutton(self.frame, text="Interface", command=self.interfacefilter)
        self.checkbutton8.grid(column=0, row=100, sticky='w')			

        self.checkbutton9 = ttk.Checkbutton(self.frame, text="Packets", command=self.packetfilter)
        self.checkbutton9.grid(column=0, row=110, sticky='w')

        self.checkbutton10 = ttk.Checkbutton(self.frame, text="Bytes", command=self.bytefilter)
        self.checkbutton10.grid(column=0, row=120, sticky='w')



        self.btn2 = ttk.Button(self.frame, command=self.analyzeme, text='Analyze Session Table', width=20)
        self.btn2.grid(column=0, row=200, sticky='w', pady=20)        
        
        #Standard text entry. 
        #self.entry = ttk.Entry(self.root, width=60)
        #self.entry.grid(column=0, row=0, sticky='e')




    #Base functions                                
    def aboutme(self):
            aboutmessage = "Written by Tim Eberhard \
                            \
                            Version: %s \
                            \
                            Please report bugs and feedback to: xmin0s@gmail.com \n \n"%(versionnum) 
                            
            
            messagebox.showinfo(message=aboutmessage)

    def cleartext(self):
             self.txt.delete(1.0, END)

    def copyoutput(self):
            clippy = self.txt.get(1.0, END)
            self.txt.clipboard_clear() 
            self.txt.clipboard_append(clippy, type='STRING')

    def loadsessiontable(self):
            self.filename = filedialog.askopenfilename()


    def hex2dec(s):
        return int(s, 16)
            
        
    #A hack for my on/off buttons since I can't figure out how to natively do it in ttk. Yes it's messy.. wanna fight about it?
    def sourceipfilter(self):
        if self.sourceipf == True:
            self.sourceipf = False
        else:    
            self.sourceipf = True

    def destinationipfilter(self):
        if self.destinationipf == True:
            self.destinationipf = False
        else:    
            self.destinationipf = True
            
    def sourceportfilter(self):
        if self.sourceportf == True:
            self.sourceportf = False
        else:    
            self.sourceportf = True                
            
    def destinationportfilter(self):
        if self.destinationportf == True:
            self.destinationportf = False
        else:    
            self.destinationportf = True                

    def protocolfilter(self):
        if self.protocolf == True:
            self.protocolf = False
        else:    
            self.protocolf = True
            
    def policyfilter(self):
        if self.policyf == True:
            self.policyf = False
        else:    
            self.policyf = True 

    def interfacefilter(self):
        if self.interfacef == True:
            self.interfacef = False
        else:    
            self.interfacef = True 

    def packetfilter(self):
        if self.packetf == True:
            self.packetf = False
        else:    
            self.packetf = True
            
    def bytefilter(self):
        if self.bytef == True:
            self.bytef = False
        else:    
            self.bytef = True 

    def loadsessiontable(self):
        self.filename = filedialog.askopenfilename()

    
    #Log Create analyzer hacks.
    def sourceipcreatelogfilter(self):
        if self.sourceipcreatelogf == True:
            self.sourceipcreatelogf = False
        else:    
            self.sourceipcreatelogf = True


    def destinationipcreatelogfilter(self):
        if self.destinationipcreatelogf == True:
            self.destinationipcreatelogf = False
        else:    
            self.destinationipcreatelogf = True
            
    def sourceportcreatelogfilter(self):
        if self.sourceportcreatelogf == True:
            self.sourceportcreatelogf = False
        else:    
            self.sourceportcreatelogf = True                
            
    def destinationportcreatelogfilter(self):
        if self.destinationportcreatelogf == True:
            self.destinationportcreatelogf = False
        else:    
            self.destinationportcreatelogf = True                



    def servicecreatelogfilter(self):
        if self.servicecreatelogf == True:
            self.servicecreatelogf = False
        else:    
            self.servicecreatelogf = True
            

    def protocolcreatelogfilter(self):
        if self.protocolcreatelogf == True:
            self.protocolcreatelogf = False
        else:    
            self.protocolcreatelogf = True
            
    def policycreatelogfilter(self):
        if self.policycreatelogf == True:
            self.policycreatelogf = False
        else:    
            self.policycreatelogf = True 

            
    def sourcezonecreatelogfilter(self):
        if self.sourcezonecreatelogf == True:
            self.sourcezonecreatelogf = False
        else:    
            self.sourcezonecreatelogf = True 

    def destinationzonecreatelogfilter(self):
        if self.destinationzonecreatelogf == True:
            self.destinationzonecreatelogf = False
        else:    
            self.destinationzonecreatelogf = True 


    #Log close analyzer hacks.
    def sourceipcloselogfilter(self):
        if self.sourceipcloselogf == True:
            self.sourceipcloselogf = False
        else:    
            self.sourceipcloselogf = True


    def destinationipcloselogfilter(self):
        if self.destinationipcloselogf == True:
            self.destinationipcloselogf = False
        else:    
            self.destinationipcloselogf = True
            
    def sourceportcloselogfilter(self):
        if self.sourceportcloselogf == True:
            self.sourceportcloselogf = False
        else:    
            self.sourceportcloselogf = True                
            
    def destinationportcloselogfilter(self):
        if self.destinationportcloselogf == True:
            self.destinationportcloselogf = False
        else:    
            self.destinationportcloselogf = True                



    def servicecloselogfilter(self):
        if self.servicecloselogf == True:
            self.servicecloselogf = False
        else:    
            self.servicecloselogf = True
            

    def protocolcloselogfilter(self):
        if self.protocolcloselogf == True:
            self.protocolcloselogf = False
        else:    
            self.protocolcloselogf = True
            
    def policycloselogfilter(self):
        if self.policycloselogf == True:
            self.policycloselogf = False
        else:    
            self.policycloselogf = True 

            
    def sourcezonecloselogfilter(self):
        if self.sourcezonecloselogf == True:
            self.sourcezonecloselogf = False
        else:    
            self.sourcezonecloselogf = True 

    def destinationzonecloselogfilter(self):
        if self.destinationzonecloselogf == True:
            self.destinationzonecloselogf = False
        else:    
            self.destinationzonecloselogf = True 


    def closetypecloselogfilter(self):
        if self.closetypecloselogf == True:
            self.closetypecloselogf = False
        else:    
            self.closetypecloselogf = True 


    def bytesfromclientcloselogfilter(self):
        if self.bytesfromclientcloselogf == True:
            self.bytesfromclientcloselogf = False
        else:    
            self.bytesfromclientecloselogf = True 

    def bytesfromservercloselogfilter(self):
        if self.bytesfromservercloselogf == True:
            self.bytesfromservercloselogf = False
        else:    
            self.bytesfromserverecloselogf = True 


    def sessionlengthcloselogfilter(self):
        if self.sessionlengthcloselogf == True:
            self.sessionlengthcloselogf = False
        else:    
            self.sessionlengthcloselogf = True 


   #Log deny analyzer hacks.
    def sourceipdenylogfilter(self):
        if self.sourceipdenylogf == True:
            self.sourceipdenylogf = False
        else:    
            self.sourceipdenylogf = True


    def destinationipdenylogfilter(self):
        if self.destinationipdenylogf == True:
            self.destinationipdenylogf = False
        else:    
            self.destinationipdenylogf = True
            
    def sourceportdenylogfilter(self):
        if self.sourceportdenylogf == True:
            self.sourceportdenylogf = False
        else:    
            self.sourceportdenylogf = True                
            
    def destinationportdenylogfilter(self):
        if self.destinationportdenylogf == True:
            self.destinationportdenylogf = False
        else:    
            self.destinationportdenylogf = True                



    def servicedenylogfilter(self):
        if self.servicedenylogf == True:
            self.servicedenylogf = False
        else:    
            self.servicedenylogf = True
            

    def protocoldenylogfilter(self):
        if self.protocoldenylogf == True:
            self.protocoldenylogf = False
        else:    
            self.protocoldenylogf = True
            
    def policydenylogfilter(self):
        if self.policydenylogf == True:
            self.policydenylogf = False
        else:    
            self.policydenylogf = True 

            
    def sourcezonedenylogfilter(self):
        if self.sourcezonedenylogf == True:
            self.sourcezonedenylogf = False
        else:    
            self.sourcezonedenylogf = True 

    def destinationzonedenylogfilter(self):
        if self.destinationzonedenylogf == True:
            self.destinationzonedenylogf = False
        else:    
            self.destinationzonedenylogf = True 




    def createloganalyzerdialog(self):
        #reset this values in the event you go back to re-run this analyzer
        self.sourceipcreatelogf = False
        self.destinationipcreatelogf = False
        self.sourceportcreatelogf = False
        self.destinationportcreatelogf = False
        self.servicecreatelogf = False
        self.protocolcreatelogf = False
        self.policycreatelogf = False
        self.sourcezonecreatelogf = False
        self.destinationzonecreatelogf = False

       
        self.filename2 = filedialog.askopenfilename()
        self.createloganalyzerwindow = Toplevel(self.root)
        
        self.content2 = ttk.Frame(self.createloganalyzerwindow)
        self.frame2 = ttk.Frame(self.content2, borderwidth=5, relief="sunken", width=50, height=500)              
        self.content2.grid(column=0, row=0)
        self.frame2.grid(column=0, row=0, columnspan=3, rowspan=2)


        self.vlabel2 = ttk.Label(self.frame2, text="Overview:")
        self.vlabel2.grid(column=0, row=1, sticky='w') 

        self.vlabel2 = ttk.Label(self.frame2, text="\t This log analyzer will parse your log for session created log messages.")
        self.vlabel2.grid(column=0, row=2, sticky='w') 


        self.vlabel2 = ttk.Label(self.frame2, text="\t Please select the filters of the data you wish to see.")
        self.vlabel2.grid(column=0, row=3, sticky='w') 

        self.btn2 = ttk.Button(self.frame2, command=self.createloganalyzer, text='Analyze Log File', width=20)
        self.btn2.grid(column=0, row=200, sticky='w', pady=20)        
        


        self.ndropboxlabel = ttk.Label(self.frame2, text="Filters:")
        self.ndropboxlabel.grid(column=0, row=29, sticky='w', pady= 10)
		
        self.ncheckbutton = ttk.Checkbutton(self.frame2, text="Source IP Filter", command=self.sourceipcreatelogfilter)
        self.ncheckbutton.grid(column=0, row=30, sticky='w')
        
        self.ncheckbutton2 = ttk.Checkbutton(self.frame2, text="Destination IP Filter", command=self.destinationipcreatelogfilter)
        self.ncheckbutton2.grid(column=0, row=40, sticky='w')

        self.ncheckbutton3 = ttk.Checkbutton(self.frame2, text="Source Port Filter", command=self.sourceportcreatelogfilter)
        self.ncheckbutton3.grid(column=0, row=50, sticky='w')        

        self.ncheckbutton4 = ttk.Checkbutton(self.frame2, text="Destination Port Filter", command=self.destinationportcreatelogfilter)
        self.ncheckbutton4.grid(column=0, row=60, sticky='w')		

        self.ncheckbutton6 = ttk.Checkbutton(self.frame2, text="Services", command=self.servicecreatelogfilter)
        self.ncheckbutton6.grid(column=0, row=80, sticky='w')	

        self.ncheckbutton6 = ttk.Checkbutton(self.frame2, text="Protocols", command=self.protocolcreatelogfilter)
        self.ncheckbutton6.grid(column=0, row=80, sticky='w')	

        self.ncheckbutton7 = ttk.Checkbutton(self.frame2, text="Policies", command=self.policycreatelogfilter)
        self.ncheckbutton7.grid(column=0, row=90, sticky='w')

        self.ncheckbutton8 = ttk.Checkbutton(self.frame2, text="Source Zone", command=self.sourcezonecreatelogfilter)
        self.ncheckbutton8.grid(column=0, row=100, sticky='w')			

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Destination Zone", command=self.destinationzonecreatelogfilter)
        self.ncheckbutton9.grid(column=0, row=110, sticky='w')


    def closeloganalyzerdialog(self):

        #reset this values in the event you go back to re-run this analyzer
        self.sourceipcloselogf = False
        self.destinationipcloselogf = False
        self.sourceportcloselogf = False
        self.destinationportcloselogf = False
        self.servicecloselogf = False
        self.protocolcloselogf = False
        self.policycloselogf = False
        self.sourcezonecloselogf = False
        self.destinationzonecloselogf = False
        self.closetypecloselogf = False
        self.bytesfromclientcloselogf = False
        self.bytesfromservercloselogf = False
        self.sessionlengthcloselogf = False
        
        self.filename3 = filedialog.askopenfilename()
        self.closeloganalyzerwindow = Toplevel(self.root)
        
        self.content2 = ttk.Frame(self.closeloganalyzerwindow)
        self.frame2 = ttk.Frame(self.content2, borderwidth=5, relief="sunken", width=50, height=500)              
        self.content2.grid(column=0, row=0)
        self.frame2.grid(column=0, row=0, columnspan=3, rowspan=2)


        self.vlabel2 = ttk.Label(self.frame2, text="Overview:")
        self.vlabel2.grid(column=0, row=1, sticky='w') 

        self.vlabel2 = ttk.Label(self.frame2, text="\t This log analyzer will parse your log for session closed log messages.")
        self.vlabel2.grid(column=0, row=2, sticky='w') 


        self.vlabel2 = ttk.Label(self.frame2, text="\t Please select the filters of the data you wish to see.")
        self.vlabel2.grid(column=0, row=3, sticky='w') 

        self.btn2 = ttk.Button(self.frame2, command=self.closeloganalyzer, text='Analyze Log File', width=20)
        self.btn2.grid(column=0, row=200, sticky='w', pady=20)        
        


        self.ndropboxlabel = ttk.Label(self.frame2, text="Filters:")
        self.ndropboxlabel.grid(column=0, row=29, sticky='w', pady= 10)
		
        self.ncheckbutton = ttk.Checkbutton(self.frame2, text="Source IP Filter", command=self.sourceipcloselogfilter)
        self.ncheckbutton.grid(column=0, row=30, sticky='w')
        
        self.ncheckbutton2 = ttk.Checkbutton(self.frame2, text="Destination IP Filter", command=self.destinationipcloselogfilter)
        self.ncheckbutton2.grid(column=0, row=40, sticky='w')

        self.ncheckbutton3 = ttk.Checkbutton(self.frame2, text="Source Port Filter", command=self.sourceportcloselogfilter)
        self.ncheckbutton3.grid(column=0, row=50, sticky='w')        

        self.ncheckbutton4 = ttk.Checkbutton(self.frame2, text="Destination Port Filter", command=self.destinationportcloselogfilter)
        self.ncheckbutton4.grid(column=0, row=60, sticky='w')		

        self.ncheckbutton6 = ttk.Checkbutton(self.frame2, text="Services", command=self.servicecloselogfilter)
        self.ncheckbutton6.grid(column=0, row=80, sticky='w')	

        self.ncheckbutton6 = ttk.Checkbutton(self.frame2, text="Protocols", command=self.protocolcloselogfilter)
        self.ncheckbutton6.grid(column=0, row=80, sticky='w')	

        self.ncheckbutton7 = ttk.Checkbutton(self.frame2, text="Policies", command=self.policycloselogfilter)
        self.ncheckbutton7.grid(column=0, row=90, sticky='w')

        self.ncheckbutton8 = ttk.Checkbutton(self.frame2, text="Source Zone", command=self.sourcezonecloselogfilter)
        self.ncheckbutton8.grid(column=0, row=100, sticky='w')			

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Destination Zone", command=self.destinationzonecloselogfilter)
        self.ncheckbutton9.grid(column=0, row=110, sticky='w')

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Close Type", command=self.closetypecloselogfilter)
        self.ncheckbutton9.grid(column=0, row=120, sticky='w')

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Bytes From Client", command=self.bytesfromclientcloselogfilter)
        self.ncheckbutton9.grid(column=0, row=130, sticky='w')

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Bytes From Server", command=self.bytesfromservercloselogfilter)
        self.ncheckbutton9.grid(column=0, row=140, sticky='w')

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Session Length", command=self.sessionlengthcloselogfilter)
        self.ncheckbutton9.grid(column=0, row=150, sticky='w')


    def denyloganalyzerdialog(self):
        #reset this values in the event you go back to re-run this analyzer
        self.sourceipdenylogf = False
        self.destinationipdenylogf = False
        self.sourceportdenylogf = False
        self.destinationportdenylogf = False
        self.servicedenylogf = False
        self.protocoldenylogf = False
        self.policydenylogf = False
        self.sourcezonedenylogf = False
        self.destinationzonedenylogf = False

       
        self.filename4 = filedialog.askopenfilename()
        self.denyloganalyzerwindow = Toplevel(self.root)
        
        self.content2 = ttk.Frame(self.denyloganalyzerwindow)
        self.frame2 = ttk.Frame(self.content2, borderwidth=5, relief="sunken", width=50, height=500)              
        self.content2.grid(column=0, row=0)
        self.frame2.grid(column=0, row=0, columnspan=3, rowspan=2)


        self.vlabel2 = ttk.Label(self.frame2, text="Overview:")
        self.vlabel2.grid(column=0, row=1, sticky='w') 

        self.vlabel2 = ttk.Label(self.frame2, text="\t This log analyzer will parse your log for session deny log messages.")
        self.vlabel2.grid(column=0, row=2, sticky='w') 


        self.vlabel2 = ttk.Label(self.frame2, text="\t Please select the filters of the data you wish to see.")
        self.vlabel2.grid(column=0, row=3, sticky='w') 

        self.btn2 = ttk.Button(self.frame2, command=self.denyloganalyzer, text='Analyze Log File', width=20)
        self.btn2.grid(column=0, row=200, sticky='w', pady=20)        
        


        self.ndropboxlabel = ttk.Label(self.frame2, text="Filters:")
        self.ndropboxlabel.grid(column=0, row=29, sticky='w', pady= 10)
		
        self.ncheckbutton = ttk.Checkbutton(self.frame2, text="Source IP Filter", command=self.sourceipdenylogfilter)
        self.ncheckbutton.grid(column=0, row=30, sticky='w')
        
        self.ncheckbutton2 = ttk.Checkbutton(self.frame2, text="Destination IP Filter", command=self.destinationipdenylogfilter)
        self.ncheckbutton2.grid(column=0, row=40, sticky='w')

        self.ncheckbutton3 = ttk.Checkbutton(self.frame2, text="Source Port Filter", command=self.sourceportdenylogfilter)
        self.ncheckbutton3.grid(column=0, row=50, sticky='w')        

        self.ncheckbutton4 = ttk.Checkbutton(self.frame2, text="Destination Port Filter", command=self.destinationportdenylogfilter)
        self.ncheckbutton4.grid(column=0, row=60, sticky='w')		

        self.ncheckbutton6 = ttk.Checkbutton(self.frame2, text="Services", command=self.servicedenylogfilter)
        self.ncheckbutton6.grid(column=0, row=80, sticky='w')	

        self.ncheckbutton6 = ttk.Checkbutton(self.frame2, text="Protocols", command=self.protocoldenylogfilter)
        self.ncheckbutton6.grid(column=0, row=80, sticky='w')	

        self.ncheckbutton7 = ttk.Checkbutton(self.frame2, text="Policies", command=self.policydenylogfilter)
        self.ncheckbutton7.grid(column=0, row=90, sticky='w')

        self.ncheckbutton8 = ttk.Checkbutton(self.frame2, text="Source Zone", command=self.sourcezonedenylogfilter)
        self.ncheckbutton8.grid(column=0, row=100, sticky='w')			

        self.ncheckbutton9 = ttk.Checkbutton(self.frame2, text="Destination Zone", command=self.destinationzonedenylogfilter)
        self.ncheckbutton9.grid(column=0, row=110, sticky='w')


        


    def denyloganalyzer(self):
        try:self.numdisplayed = int(self.rawnumdisplayed.get())
        except:
            if self.rawnumdisplayed.get() == "all":
                self.numdisplayed = 99999
            else:
                self.numdisplayed = 10 #if nothing is selected. Default to top 10.


        try:
            portnumx = open("port_list.txt", "r")
            portnums = portnumx.read()
            portnum = eval(portnums)
        except:pass #If port_list.txt isn't present, oh well..

                       
        #self.filename3 = filedialog.askopenfilename()
        #if messagebox.askyesno(message='Analyze permit traffic log file?', icon='question', title='Permit Log Analyzer'):
                #If yes is selected, do stuff here.

        namefilename4 = "File loaded:"+str(self.filename4)+"\n\n\n"
        self.txt.insert(tkinter.INSERT, namefilename4)
        denylogfile = open(self.filename4, "r")
        denylogdata = denylogfile.readlines()

        
        srclist = list() #Creates an empty list
        dstlist = list()
        srcportlist = list()
        dstportlist = list()
        interfacelist = list()
        protocollist = list()
        servicenamelist = list()
        protocollist = list()
        policylist = list()
        srczonelist = list()
        dstzonelist = list()


        #Setting all our counters
        source_ips = 0
        dest_ips = 0
        source_ports = 0
        dest_ports = 0
        interface = 0
        protocol = 0
        servicename = 0
        policy = 0
        srczone = 0
        dstzone = 0
        sessiondeny = 0

        for data in denylogdata:
            #data we're matching on..
            #Jan  7 12:07:05  SRX5800 RT_FLOW: RT_FLOW_SESSION_DENY: session denied 10.1.1.100/53906->172.31.100.60/21
            #junos-ftp 6(0) web_deny trust web-dmz
            #
            #session denied [source-address/source-port->destination-address/destination-port]
            #[service-name] [protocol-id](icmp-type) [policy-name] [source-zone-name] [destination-zone-name]
            if re.search("FLOW_SESSION_DENY", data) != None:
                    #try:
                    sessiondeny = sessiondeny+1
                    
                    ##Split's the IP's into a source group and a destination group.
                    ipheader = data.split("denied")[1].split()[0].replace("->"," ").split()
                    src, dest = ipheader[0:]
                    
                    #Takes Destination and seperates IP from port
                    srcip, srcport = src.split("/")
                    destip,destport = dest.split("/")       

                    #Adds the data to our lists
                    srclist.append(srcip)            
                    dstlist.append(destip)               
                    srcportlist.append(srcport)            
                    dstportlist.append(destport)   
                    
                    #Source/Destination IP/Port
                    source_ips = source_ips + 1     #For every session increament packet counter 
                    dest_ports = dest_ports + 1
                    dest_ips = dest_ips + 1
                    source_ports = source_ports + 1


                    #Orginize the data from the log entry for later use.
                    sessiondata = data.split("denied")[1].split()

                    #Service
                    servicedata = sessiondata[1]
                    servicename = servicename+1
                    servicenamelist.append(servicedata)
            

                    #Protocol
                    protocoldata = sessiondata[2].split("(")[0]
                    protocol = protocol+1
                    protocollist.append(protocoldata)

                    #Policy
                    policydata = sessiondata[3]
                    policy = policy+1
                    policylist.append(policydata)

 
                    #Source Zone
                    srczonedata = sessiondata[4]
                    srczone = srczone+1
                    srczonelist.append(srczonedata)
                   
                    #Destination Zone
                    dstzonedata = sessiondata[5]
                    dstzone = dstzone+1
                    dstzonelist.append(dstzonedata)
                    #except:pass            





        #top talkers - source ip
        counts = {}
        srclist.sort()
        for s in srclist: #Count IP's
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srcipl = [(v, k) for k, v in alist.items()]
        srcipl.sort()
        srcipl.reverse()
        srcipl = [(k, v) for v, k in srcipl]
        total_source_ips = source_ips



        #top talkers - dest ip
        counts = {}
        dstlist.sort()
        for s in dstlist: #Count IP's
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        dstipl = [(v, k) for k, v in alist.items()]
        dstipl.sort()
        dstipl.reverse()
        dstipl = [(k, v) for v, k in dstipl]
        total_dest_ips = dest_ips



        #top ports - source
        counts = {}
        srcportlist.sort()
        for s in srcportlist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srcportl = [(v, k) for k, v in alist.items()]
        srcportl.sort()
        srcportl.reverse()
        srcportl = [(k, v) for v, k in srcportl]
        total_source_ports = source_ports

        #top ports - dest
        counts = {}
        dstportlist.sort()
        for s in dstportlist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        destportl = [(v, k) for k, v in alist.items()]
        destportl.sort()
        destportl.reverse()
        destportl = [(k, v) for v, k in destportl]
        total_dest_ports = dest_ports



        #top service
        counts = {}
        servicenamelist.sort()
        for s in servicenamelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        servicenamel = [(v, k) for k, v in alist.items()]
        servicenamel.sort()
        servicenamel.reverse()
        servicenamel= [(k, v) for v, k in servicenamel]
        total_servicename = servicename




        #top protocol
        counts = {}
        protocollist.sort()
        for s in protocollist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        protocoll = [(v, k) for k, v in alist.items()]
        protocoll.sort()
        protocoll.reverse()
        protocoll= [(k, v) for v, k in protocoll]
        total_protocol = protocol



        #top policy
        counts = {}
        policylist.sort()
        for s in policylist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        policyl = [(v, k) for k, v in alist.items()]
        policyl.sort()
        policyl.reverse()
        policyl= [(k, v) for v, k in policyl]
        total_policy = policy

        #top srczone
        counts = {}
        srczonelist.sort()
        for s in srczonelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srczonel = [(v, k) for k, v in alist.items()]
        srczonel.sort()
        srczonel.reverse()
        srczonel= [(k, v) for v, k in srczonel]
        total_srczone = srczone

        
        #top dstzone
        counts = {}
        dstzonelist.sort()
        for s in dstzonelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        dstzonel = [(v, k) for k, v in alist.items()]
        dstzonel.sort()
        dstzonel.reverse()
        dstzonel= [(k, v) for v, k in dstzonel]
        total_dstzone = dstzone


        self.txt.insert(tkinter.INSERT,"-SRX Session Analyzer-\n")
        self.txt.insert(tkinter.INSERT,"-Session Flow Deny Report-\n")
        self.txt.insert(tkinter.INSERT,"-Written By Tim Eberhard-\n")
        text = ("-Version:%s -\n\n\n" %versionnum)
        self.txt.insert(tkinter.INSERT,text)

        
        text = ("Total Number of Session Denies Log Entries Parsed: %s \n\n" %sessiondeny)
        self.txt.insert(tkinter.INSERT,text)


        if self.sourceipdenylogf == True:
            text = ("Top %d Source IP addresses: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       IP Address\n")
            self.txt.insert(tkinter.INSERT,text)
            
            for i,j in srcipl[:self.numdisplayed]:                                  
                 pp = int(j)
                 source_ips_percent = pp/total_source_ips
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(source_ips_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)




        if self.destinationipdenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination IP addresses: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       IP Address \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in dstipl[:self.numdisplayed]:                                  
                 pp = int(j)
                 dest_ips_percent = pp/dest_ips
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(dest_ips_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)

    
        if self.sourceportdenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Source Ports: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -  Port -  Possible Service \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in srcportl[:self.numdisplayed]:
                 p = int(i)
                 pp = int(j)
                 source_ports_percent = pp/total_source_ports                                    
                 try:text = ("%s    -    %s   [%s] (%s Percent) \n"%(pp, i, portnum[p], round(source_ports_percent*100,2)))
                 except:text = ("%s    -    %s   [Not listed] (%s Percent) \n"%(pp, i, round(source_ports_percent*100,2) ))
                 self.txt.insert(tkinter.INSERT,text)


        if self.destinationportdenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination Ports:\n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -  Port -  Possible Service\n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in destportl[:self.numdisplayed]:
                 p = int(i)
                 pp = int(j)
                 dest_ports_percent = pp/total_dest_ports                                        
                 try: text = ( "%s    -    %s   [%s] (%s Percent) \n"%(pp, i, portnum[p], round(dest_ports_percent*100,2)))
                 except:text = ( "%s    -    %s   [Not listed] (%s Percent) \n"%(pp, i, round(dest_ports_percent*100,2) ))
                 self.txt.insert(tkinter.INSERT,text)


        if self.servicedenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Services \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Service Name \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in servicenamel[:self.numdisplayed]:                                  
                 pp = int(j)
                 servicename_percent = pp/servicename
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(servicename_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)



        if self.protocoldenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Protocols \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Protocol \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in protocoll[:self.numdisplayed]:                                  
                 pp = int(j)
                 p = int(i)
                 protocol_percent = pp/protocol
                 protocolnum
                 try:text = ("%s    -       %s  [%s]    (%s Percent) \n"%(pp, i, protocolnum[p], round(protocol_percent*100, 2)))
                 except:text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(protocol_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.policydenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Policies \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Policy Name \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in policyl[:self.numdisplayed]:                                  
                 pp = int(j)
                 policy_percent = pp/policy
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(policy_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.sourcezonedenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Source Zones \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Source Zone \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in srczonel[:self.numdisplayed]:                                  
                 pp = int(j)
                 srczone_percent = pp/srczone
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(srczone_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)



        if self.destinationzonedenylogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination Zones \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Destination Zone \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in dstzonel[:self.numdisplayed]:                                  
                 pp = int(j)
                 dstzone_percent = pp/dstzone
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(dstzone_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)

             #We're done, kill off the window. 
        self.denyloganalyzerwindow.destroy()





################################################################
################################################################
################################################################
################################################################

    def createloganalyzer(self):
        try:self.numdisplayed = int(self.rawnumdisplayed.get())
        except:
            if self.rawnumdisplayed.get() == "all":
                self.numdisplayed = 99999
            else:
                self.numdisplayed = 10 #if nothing is selected. Default to top 10.


        try:
            portnumx = open("port_list.txt", "r")
            portnums = portnumx.read()
            portnum = eval(portnums)
        except:pass #If port_list.txt isn't present, oh well..

                       
        
        #if messagebox.askyesno(message='Analyze permit traffic log file?', icon='question', title='Permit Log Analyzer'):
                #If yes is selected, do stuff here.

        namefilename2 = "File loaded:"+str(self.filename2)+"\n\n\n"
        self.txt.insert(tkinter.INSERT, namefilename2)
        permitlogfile = open(self.filename2, "r")
        permitlogdata = permitlogfile.readlines()


        srclist = list() #Creates an empty list
        dstlist = list()
        srcportlist = list()
        dstportlist = list()
        interfacelist = list()
        protocollist = list()
        servicenamelist = list()
        protocollist = list()
        policylist = list()
        srczonelist = list()
        dstzonelist = list()



        #Setting all our counters
        source_ips = 0
        dest_ips = 0
        source_ports = 0
        dest_ports = 0
        interface = 0
        protocol = 0
        servicename = 0
        policy = 0
        srczone = 0
        dstzone = 0
        sessioncreate = 0
        sessionclose = 0


        for data in permitlogdata:
            #data we're matching on..
            #Dec  6 13:10:49  SRX220 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.183.1.1/16138->10.194.201.112/9100 None
            #10.183.1.1/16138->192.168.168.12/9100 None vpn_printer 6 default-permit vpn trust 60756 N/A(N/A) st0.0
            #
            #session created source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port
            #src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-3
            #
            if re.search("FLOW_SESSION_CREATE", data) != None:
                    try:
                        sessioncreate = sessioncreate+1
                        
                        ##Split's the IP's into a source group and a destination group.
                        ipheader = data.split("created")[1].split()[0].replace("->"," ").split()
                        src, dest = ipheader[0:]
                        
                        #Takes Destination and seperates IP from port
                        srcip, srcport = src.split("/")
                        destip,destport = dest.split("/")       

                        #Adds the data to our lists
                        srclist.append(srcip)            
                        dstlist.append(destip)               
                        srcportlist.append(srcport)            
                        dstportlist.append(destport)   
                        
                        #Source/Destination IP/Port
                        source_ips = source_ips + 1     #For every session increament packet counter 
                        dest_ports = dest_ports + 1
                        dest_ips = dest_ips + 1
                        source_ports = source_ports + 1


                        #Orginize the data from the log entry for later use.
                        sessiondata = data.split("created")[1].split()

                        #Service
                        servicedata = sessiondata[1]
                        servicename = servicename+1
                        servicenamelist.append(servicedata)
                
                        #Going to ignore this one for now. Nat processing maybe added later if someone wants it.                    
                        natedipaheaderdata = sessiondata[2]
                        srcnatruledata = sessiondata[3]
                        dstnatruledata = sessiondata[4]


                        #Protocol
                        protocoldata = sessiondata[5]
                        protocol = protocol+1
                        protocollist.append(protocoldata)

                        #Policy
                        policydata = sessiondata[6]
                        policy = policy+1
                        policylist.append(policydata)

     
                        #Source Zone
                        srczonedata = sessiondata[7]
                        srczone = srczone+1
                        srczonelist.append(srczonedata)
                       
                        #Destination Zone
                        dstzonedata = sessiondata[8]
                        dstzone = dstzone+1
                        dstzonelist.append(dstzonedata)
                    except:pass

                            





        #top talkers - source ip
        counts = {}
        srclist.sort()
        for s in srclist: #Count IP's
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srcipl = [(v, k) for k, v in alist.items()]
        srcipl.sort()
        srcipl.reverse()
        srcipl = [(k, v) for v, k in srcipl]
        total_source_ips = source_ips



        #top talkers - dest ip
        counts = {}
        dstlist.sort()
        for s in dstlist: #Count IP's
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        dstipl = [(v, k) for k, v in alist.items()]
        dstipl.sort()
        dstipl.reverse()
        dstipl = [(k, v) for v, k in dstipl]
        total_dest_ips = dest_ips



        #top ports - source
        counts = {}
        srcportlist.sort()
        for s in srcportlist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srcportl = [(v, k) for k, v in alist.items()]
        srcportl.sort()
        srcportl.reverse()
        srcportl = [(k, v) for v, k in srcportl]
        total_source_ports = source_ports

        #top ports - dest
        counts = {}
        dstportlist.sort()
        for s in dstportlist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        destportl = [(v, k) for k, v in alist.items()]
        destportl.sort()
        destportl.reverse()
        destportl = [(k, v) for v, k in destportl]
        total_dest_ports = dest_ports



        #top service
        counts = {}
        servicenamelist.sort()
        for s in servicenamelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        servicenamel = [(v, k) for k, v in alist.items()]
        servicenamel.sort()
        servicenamel.reverse()
        servicenamel= [(k, v) for v, k in servicenamel]
        total_servicename = servicename




        #top protocol
        counts = {}
        protocollist.sort()
        for s in protocollist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        protocoll = [(v, k) for k, v in alist.items()]
        protocoll.sort()
        protocoll.reverse()
        protocoll= [(k, v) for v, k in protocoll]
        total_protocol = protocol



        #top policy
        counts = {}
        policylist.sort()
        for s in policylist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        policyl = [(v, k) for k, v in alist.items()]
        policyl.sort()
        policyl.reverse()
        policyl= [(k, v) for v, k in policyl]
        total_policy = policy

        #top srczone
        counts = {}
        srczonelist.sort()
        for s in srczonelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srczonel = [(v, k) for k, v in alist.items()]
        srczonel.sort()
        srczonel.reverse()
        srczonel= [(k, v) for v, k in srczonel]
        total_srczone = srczone

        
        #top dstzone
        counts = {}
        dstzonelist.sort()
        for s in dstzonelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        dstzonel = [(v, k) for k, v in alist.items()]
        dstzonel.sort()
        dstzonel.reverse()
        dstzonel= [(k, v) for v, k in dstzonel]
        total_dstzone = dstzone



        self.txt.insert(tkinter.INSERT,"-SRX Session Analyzer-\n")
        self.txt.insert(tkinter.INSERT,"-Session Flow Create Report-\n")
        self.txt.insert(tkinter.INSERT,"-Written By Tim Eberhard-\n")
        text = ("-Version:%s -\n\n\n" %versionnum)
        self.txt.insert(tkinter.INSERT,text)

        
        text = ("Total Number of Session Create Log Entries Parsed: %s \n\n" %sessioncreate)
        self.txt.insert(tkinter.INSERT,text)


        if self.sourceipcreatelogf == True:
            text = ("Top %d Source IP addresses: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       IP Address\n")
            self.txt.insert(tkinter.INSERT,text)
            
            for i,j in srcipl[:self.numdisplayed]:                                  
                 pp = int(j)
                 source_ips_percent = pp/total_source_ips
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(source_ips_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)




        if self.destinationipcreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination IP addresses: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       IP Address \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in dstipl[:self.numdisplayed]:                                  
                 pp = int(j)
                 dest_ips_percent = pp/dest_ips
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(dest_ips_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)

    
        if self.sourceportcreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Source Ports: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -  Port -  Possible Service \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in srcportl[:self.numdisplayed]:
                 p = int(i)
                 pp = int(j)
                 source_ports_percent = pp/total_source_ports                                    
                 try:text = ("%s    -    %s   [%s] (%s Percent) \n"%(pp, i, portnum[p], round(source_ports_percent*100,2)))
                 except:text = ("%s    -    %s   [Not listed] (%s Percent) \n"%(pp, i, round(source_ports_percent*100,2) ))
                 self.txt.insert(tkinter.INSERT,text)


        if self.destinationportcreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination Ports:\n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -  Port -  Possible Service\n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in destportl[:self.numdisplayed]:
                 p = int(i)
                 pp = int(j)
                 dest_ports_percent = pp/total_dest_ports                                        
                 try: text = ( "%s    -    %s   [%s] (%s Percent) \n"%(pp, i, portnum[p], round(dest_ports_percent*100,2)))
                 except:text = ( "%s    -    %s   [Not listed] (%s Percent) \n"%(pp, i, round(dest_ports_percent*100,2) ))
                 self.txt.insert(tkinter.INSERT,text)


        if self.servicecreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Services \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Service Name \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in servicenamel[:self.numdisplayed]:                                  
                 pp = int(j)
                 servicename_percent = pp/servicename
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(servicename_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)



        if self.protocolcreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Protocols \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Protocol \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in protocoll[:self.numdisplayed]:                                  
                 pp = int(j)
                 p = int(i)
                 protocol_percent = pp/protocol
                 protocolnum
                 try:text = ("%s    -       %s  [%s]    (%s Percent) \n"%(pp, i, protocolnum[p], round(protocol_percent*100, 2)))
                 except:text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(protocol_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.policycreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Policies \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Policy Name \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in policyl[:self.numdisplayed]:                                  
                 pp = int(j)
                 policy_percent = pp/policy
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(policy_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.sourcezonecreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Source Zones \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Source Zone \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in srczonel[:self.numdisplayed]:                                  
                 pp = int(j)
                 srczone_percent = pp/srczone
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(srczone_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)



        if self.destinationzonecreatelogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination Zones \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Destination Zone \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in dstzonel[:self.numdisplayed]:                                  
                 pp = int(j)
                 dstzone_percent = pp/dstzone
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(dstzone_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)

         #We're done, kill off the window. 
        self.createloganalyzerwindow.destroy()

################################################################
################################################################
################################################################
################################################################

    def closeloganalyzer(self):
        try:self.numdisplayed = int(self.rawnumdisplayed.get())
        except:
            if self.rawnumdisplayed.get() == "all":
                self.numdisplayed = 99999
            else:
                self.numdisplayed = 10 #if nothing is selected. Default to top 10.


        try:
            portnumx = open("port_list.txt", "r")
            portnums = portnumx.read()
            portnum = eval(portnums)
        except:pass #If port_list.txt isn't present, oh well..

                       
        #self.filename2 = filedialog.askopenfilename()
        #if messagebox.askyesno(message='Analyze permit traffic log file?', icon='question', title='Permit Log Analyzer'):
                #If yes is selected, do stuff here.

        namefilename3 = "File loaded:"+str(self.filename3)+"\n\n\n"
        self.txt.insert(tkinter.INSERT, namefilename3)
        permitlogfile = open(self.filename3, "r")
        permitlogdata = permitlogfile.readlines()


        srclist = list() #Creates an empty list
        dstlist = list()
        srcportlist = list()
        dstportlist = list()
        interfacelist = list()
        protocollist = list()
        servicenamelist = list()
        protocollist = list()
        policylist = list()
        srczonelist = list()
        dstzonelist = list()
        #Below are only available in closed sessions
        paksfromclientlist = list()
        paksfromserverlist = list()
        elapsedtimelist = list()
        reasoncloselist = list()


        #Setting all our counters
        source_ips = 0
        dest_ips = 0
        source_ports = 0
        dest_ports = 0
        interface = 0
        protocol = 0
        servicename = 0
        policy = 0
        srczone = 0
        dstzone = 0
        paksfromclient = 0
        paksfromserver = 0
        elapsedtime = 0
        sessioncreate = 0
        sessionclose = 0
        reasonclose = 0
        totalbytesclient = 0
        totalbytesserver = 0


        for data in permitlogdata:
            #data we're matching on..

            #Dec  6 13:11:20  SRX220 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 10.183.1.1/16138->10.194.201.112/9100 None 10.183.1.1/16138->192.168.168.12/9100 None vpn_printer 6 default-permit vpn trust 60756 98(78354) 56(2986) 31   N/A(N/A) st0.0
            #session closed reason: source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name
            #destination-zone-name session-id-32 packets-from-client(bytes-from-client) packets-from-server(bytes-from-server) elapsed-tim

            if re.search("FLOW_SESSION_CLOSE", data) != None:
                    try:
                        sessionclose = sessionclose+1
                        
                        ##Split's the IP's into a source group and a destination group.
                        ipheader = data.split(":")[5].split()[0].replace("->"," ").split()
                        src, dest = ipheader[0:]
                        
                        #Takes Destination and seperates IP from port
                        srcip, srcport = src.split("/")
                        destip,destport = dest.split("/")       

                        #Adds the data to our lists
                        srclist.append(srcip)            
                        dstlist.append(destip)               
                        srcportlist.append(srcport)            
                        dstportlist.append(destport)   
                        
                        #Source/Destination IP/Port
                        source_ips = source_ips + 1     #For every session increament packet counter 
                        dest_ports = dest_ports + 1
                        dest_ips = dest_ips + 1
                        source_ports = source_ports + 1

                        reasonclosedata = data.split("closed")[1].split(":")[0]
                        reasonclose = reasonclose+1
                        reasoncloselist.append(reasonclosedata)



                        #Orginize the data from the log entry for later use.
                        sessiondata = data.split(":")[5].split()

                        #Service
                        servicedata = sessiondata[1]
                        servicename = servicename+1
                        servicenamelist.append(servicedata)
                
                        #Going to ignore this one for now. Nat processing maybe added later if someone wants it.                    
                        natedipaheaderdata = sessiondata[2]
                        srcnatruledata = sessiondata[3]
                        dstnatruledata = sessiondata[4]


                        #Protocol
                        protocoldata = sessiondata[5]
                        protocol = protocol+1
                        protocollist.append(protocoldata)

                        #Policy
                        policydata = sessiondata[6]
                        policy = policy+1
                        policylist.append(policydata)

     
                        #Source Zone
                        srczonedata = sessiondata[7]
                        srczone = srczone+1
                        srczonelist.append(srczonedata)
                       
                        #Destination Zone
                        dstzonedata = sessiondata[8]
                        dstzone = dstzone+1
                        dstzonelist.append(dstzonedata)


                        #paks from client 

                        bytesfromclientdata = sessiondata[10].split("(")[1].split(")")[0]
                        paksfromclientdata = sessiondata[10].split("(")[0] 
                        #need to grab the previous lines configuration here or the last source/dest in their respective lists
                        xferpaks = int(bytesfromclientdata), paksfromclientdata, srclist[-1], dstlist[-1], srcportlist[-1], dstportlist[-1]
                        paksfromclientlist.append(xferpaks)
                        totalbytesclient = totalbytesclient+int(bytesfromclientdata)                                    
            
                

                        #paks from server

                        bytesfromserverdata = sessiondata[11].split("(")[1].split(")")[0]
                        paksfromserverdata = sessiondata[11].split("(")[0]                                   
                        #need to grab the previous lines configuration here or the last source/dest in their respective lists
                        xferpaks2 = int(bytesfromserverdata), paksfromserverdata, srclist[-1], dstlist[-1], srcportlist[-1], dstportlist[-1]
                        paksfromserverlist.append(xferpaks2)
                        totalbytesserver = totalbytesserver+int(bytesfromserverdata)

                        

                        #elapsed time Need to add to this and improve it.
                        elapsedtimedata = sessiondata[12]
                        totalbytes = int(bytesfromserverdata)+int(bytesfromclientdata)
                        timepak = int(elapsedtimedata), totalbytes,  srclist[-1], dstlist[-1], srcportlist[-1], dstportlist[-1]
                        elapsedtimelist.append(timepak)
                        
                       
                    except:pass

                        



        #top talkers - source ip
        counts = {}
        srclist.sort()
        for s in srclist: #Count IP's
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srcipl = [(v, k) for k, v in alist.items()]
        srcipl.sort()
        srcipl.reverse()
        srcipl = [(k, v) for v, k in srcipl]
        total_source_ips = source_ips



        #top talkers - dest ip
        counts = {}
        dstlist.sort()
        for s in dstlist: #Count IP's
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        dstipl = [(v, k) for k, v in alist.items()]
        dstipl.sort()
        dstipl.reverse()
        dstipl = [(k, v) for v, k in dstipl]
        total_dest_ips = dest_ips



        #top ports - source
        counts = {}
        srcportlist.sort()
        for s in srcportlist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srcportl = [(v, k) for k, v in alist.items()]
        srcportl.sort()
        srcportl.reverse()
        srcportl = [(k, v) for v, k in srcportl]
        total_source_ports = source_ports

        #top ports - dest
        counts = {}
        dstportlist.sort()
        for s in dstportlist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        destportl = [(v, k) for k, v in alist.items()]
        destportl.sort()
        destportl.reverse()
        destportl = [(k, v) for v, k in destportl]
        total_dest_ports = dest_ports



        #top service
        counts = {}
        servicenamelist.sort()
        for s in servicenamelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        servicenamel = [(v, k) for k, v in alist.items()]
        servicenamel.sort()
        servicenamel.reverse()
        servicenamel= [(k, v) for v, k in servicenamel]
        total_servicename = servicename




        #top protocol
        counts = {}
        protocollist.sort()
        for s in protocollist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        protocoll = [(v, k) for k, v in alist.items()]
        protocoll.sort()
        protocoll.reverse()
        protocoll= [(k, v) for v, k in protocoll]
        total_protocol = protocol



        #top policy
        counts = {}
        policylist.sort()
        for s in policylist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        policyl = [(v, k) for k, v in alist.items()]
        policyl.sort()
        policyl.reverse()
        policyl= [(k, v) for v, k in policyl]
        total_policy = policy

        #top srczone
        counts = {}
        srczonelist.sort()
        for s in srczonelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        srczonel = [(v, k) for k, v in alist.items()]
        srczonel.sort()
        srczonel.reverse()
        srczonel= [(k, v) for v, k in srczonel]
        total_srczone = srczone

        
        #top dstzone
        counts = {}
        dstzonelist.sort()
        for s in dstzonelist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        dstzonel = [(v, k) for k, v in alist.items()]
        dstzonel.sort()
        dstzonel.reverse()
        dstzonel= [(k, v) for v, k in dstzonel]
        total_dstzone = dstzone



        
        #top reason close
        counts = {}
        reasoncloselist.sort()
        for s in reasoncloselist: #Count ports
            if s in counts:
                counts[s] += 1
            else:
                counts[s] = 1
        alist = counts
        reasonclosel = [(v, k) for k, v in alist.items()]
        reasonclosel.sort()
        reasonclosel.reverse()
        reasonclosel= [(k, v) for v, k in reasonclosel]
        total_reasonclose = reasonclose



        #Top Talkers - From Client - Bytes
        paksfromclientlist.sort()
        paksfromclientlist.reverse() 

        #Top Talkers - From Server Bytes
        paksfromserverlist.sort()
        paksfromserverlist.reverse()


        #Longest running sessions (I'm sure this isn't as easy as it seems)
        elapsedtimelist.sort()
        elapsedtimelist.reverse()

        

        self.txt.insert(tkinter.INSERT,"-SRX Session Analyzer-\n")
        self.txt.insert(tkinter.INSERT,"-Session Flow Close Report-\n")
        self.txt.insert(tkinter.INSERT,"-Written By Tim Eberhard-\n")
        text = ("-Version:%s -\n\n\n" %versionnum)
        self.txt.insert(tkinter.INSERT,text)

        text = ("Total Number of Session Close Log Entries Parsed: %s \n\n" %sessionclose)
        self.txt.insert(tkinter.INSERT,text)



        if self.sourceipcloselogf == True:
            text = ("Top %d Source IP addresses: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       IP Address\n")
            self.txt.insert(tkinter.INSERT,text)
            
            for i,j in srcipl[:self.numdisplayed]:                                  
                 pp = int(j)
                 source_ips_percent = pp/total_source_ips
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(source_ips_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)




        if self.destinationipcloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination IP addresses: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       IP Address \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in dstipl[:self.numdisplayed]:                                  
                 pp = int(j)
                 dest_ips_percent = pp/dest_ips
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(dest_ips_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.sourceportcloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Source Ports: \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -  Port -  Possible Service \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in srcportl[:self.numdisplayed]:
                 p = int(i)
                 pp = int(j)
                 source_ports_percent = pp/total_source_ports                                    
                 try:text = ("%s    -    %s   [%s] (%s Percent) \n"%(pp, i, portnum[p], round(source_ports_percent*100,2)))
                 except:text = ("%s    -    %s   [Not listed] (%s Percent) \n"%(pp, i, round(source_ports_percent*100,2) ))
                 self.txt.insert(tkinter.INSERT,text)


        if self.destinationportcloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination Ports:\n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -  Port -  Possible Service\n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in destportl[:self.numdisplayed]:
                 p = int(i)
                 pp = int(j)
                 dest_ports_percent = pp/total_dest_ports                                        
                 try: text = ( "%s    -    %s   [%s] (%s Percent) \n"%(pp, i, portnum[p], round(dest_ports_percent*100,2)))
                 except:text = ( "%s    -    %s   [Not listed] (%s Percent) \n"%(pp, i, round(dest_ports_percent*100,2) ))
                 self.txt.insert(tkinter.INSERT,text)


        if self.servicecloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Services \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Service Name \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in servicenamel[:self.numdisplayed]:                                  
                 pp = int(j)
                 servicename_percent = pp/servicename
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(servicename_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.protocolcloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Protocols \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Protocol \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in protocoll[:self.numdisplayed]:                                  
                 pp = int(j)
                 p = int(i)
                 protocol_percent = pp/protocol
                 protocolnum
                 try:text = ("%s    -       %s  [%s]    (%s Percent) \n"%(pp, i, protocolnum[p], round(protocol_percent*100, 2)))
                 except:text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(protocol_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.policycloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Policies \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Policy Name \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in policyl[:self.numdisplayed]:                                  
                 pp = int(j)
                 policy_percent = pp/policy
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(policy_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)



        if self.sourcezonecloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Source Zones \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Source Zone \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in srczonel[:self.numdisplayed]:                                  
                 pp = int(j)
                 srczone_percent = pp/srczone
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(srczone_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.destinationzonecloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Destination Zones \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Destination Zone \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in dstzonel[:self.numdisplayed]:                                  
                 pp = int(j)
                 dstzone_percent = pp/dstzone
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(dstzone_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)


        if self.closetypecloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Session Close Types \n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Number of Connections  -       Close Type \n")
            self.txt.insert(tkinter.INSERT,text)
            for i,j in reasonclosel[:self.numdisplayed]:                                  
                 pp = int(j)
                 reasonclose_percent = pp/reasonclose
                 text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(reasonclose_percent*100, 2)))
                 self.txt.insert(tkinter.INSERT,text)

        if self.bytesfromclientcloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Bytes from Client:\n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Source IP	-	Destination IP	-	Source Port 	-	Destination Port	-		Bytes (Packets)  \n")
            self.txt.insert(tkinter.INSERT,text)
            for line in paksfromclientlist[:self.numdisplayed]:
                    pp = int(line[0])
                    client_percent = pp/totalbytesclient
                    text = ( "%s \t\t %s \t\t %s \t\t\t %s \t\t %s(%s) %s percent of client traffic \n"%(line[2],line[3], line[4], line[5], line[0], line[1], round(client_percent*100,2)))
                    self.txt.insert(tkinter.INSERT,text)


        if self.bytesfromservercloselogf == True:                    
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Bytes from Server:\n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Source IP	-	Destination IP	-	Source Port 	-	Destination Port	-		 Bytes (Packets) \n")
            self.txt.insert(tkinter.INSERT,text)
            for line in paksfromserverlist[:self.numdisplayed]:
                    pp = int(line[0])
                    server_percent = pp/totalbytesserver
                    text = ( "%s \t\t %s \t\t %s \t\t\t %s \t\t %s(%s) %s percent of server traffic \n"%(line[2],line[3], line[4], line[5], line[0], line[1], round(server_percent*100,2)))
                    self.txt.insert(tkinter.INSERT,text)

        if self.sessionlengthcloselogf == True:
            text = ('*'*72)
            self.txt.insert(tkinter.INSERT,text)
            text = ('\n'*3)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Top %d Longest Sessions By Time :\n" %self.numdisplayed)
            self.txt.insert(tkinter.INSERT,text)
            text = ("Source IP	-	Destination IP	-	Source Port 	-	Destination Port	-		 Time (Bytes Transfered) \n")
            self.txt.insert(tkinter.INSERT,text)
            for line in elapsedtimelist[:self.numdisplayed]:
                    pp = int(line[1])
                    totalbytesall = totalbytesserver+totalbytesclient
                    server_percent = pp/totalbytesall
                    text = ( "%s \t\t %s \t\t %s \t\t\t %s \t\t %s(%s) %s percent of traffic \n"%(line[2],line[3], line[4], line[5], line[0], line[1], round(server_percent*100,2)))
                    self.txt.insert(tkinter.INSERT,text)

         #We're done, kill off the window. 
        self.closeloganalyzerwindow.destroy()




################################################################
################################################################
################################################################
################################################################




    def analyzeme(self):
        try:self.numdisplayed = int(self.rawnumdisplayed.get())
            
        except:
            if self.rawnumdisplayed.get() == "all":
                self.numdisplayed = 99999
            else:
                self.numdisplayed = 10 #if nothing is selected. Default to top 10.


        if self.filename == False:
            self.txt.insert(tkinter.INSERT, "PLEASE LOAD A SESSION FILE FIRST.\n \n \n")  
        else:
            namefilename = "File loaded:"+str(self.filename)+"\n\n\n"
            self.txt.insert(tkinter.INSERT, namefilename)        

            #Core SSA Code#
            sessionfile = open(self.filename, "r")

            try:
                portnumx = open("port_list.txt", "r")
                portnums = portnumx.read()
                portnum = eval(portnums)
            except:pass #If port_list.txt isn't present, oh well..


            #Create our lists for the different filters
            srclist = list()
            dstlist = list()
            srcportlist = list()
            destportlist = list()
            policylist = list()
            protocollist = list()
            interfacelist = list()
            xferlist = list()
            xferbytelist = list()


            #Counters for later use.
            source_ips = 0
            dest_ips = 0
            dest_ports = 0
            source_ports = 0
            policies = 0
            protocols = 0
            interfaces = 0

            sessiondata = sessionfile.readlines()




            for connection in sessiondata:
                    #parse to see if this is the start of a new session
                    if re.search("Session ID:", connection) != None:
                            #Policy name
                            try:
                                    policy = connection.split("Policy name:")[1].split(",")[0]
                                    policylist.append(policy)
                                    policies = policies  + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (policy)",policy)
                            except:pass		
                            
                    #parse to see if this is the inbound portion of the session.	
                    if re.search("In:", connection) != None:
                            #Source IP
                            try:
                                    srcip = connection.split(":")[1].split("/")[0]
                                    srclist.append(srcip)
                                    source_ips = source_ips + 1
                                    if debug == "debug":
                                            print ("DEBUG: (srcip)",srcip)
                            except:pass
                            
                            #Dest IP
                            try:
                                    dstip = connection.split("-->")[1].split("/")[0]
                                    dstlist.append(dstip)
                                    dest_ips = dest_ips + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (dstip)",dstip)
                            except:pass
                            
                            #Source Port
                            try:
                                    srcport = connection.split("/")[1].split()[0]
                                    srcportlist.append(srcport)
                                    source_ports = source_ports + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (srcport)",srcport)
                            except:pass

                            #Dest Port
                            try:
                                    destport = connection.split("/")[2].split(";")[0]
                                    destportlist.append(destport)
                                    dest_ports = dest_ports + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (destport)",destport)
                            except:pass



                            #Protocol
                            try:
                                    protocol = connection.split(";")[1].split(",")[0]
                                    protocollist.append(protocol)
                                    protocols = protocols  + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (protocol)",protocol)
                            except:pass			
                            
                            #Interface
                            try:
                                    interface = connection.split("If:")[1].split(",")[0]
                                    interfacelist.append(interface)
                                    interfaces = interfaces  + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (interface)",interface)
                            except:pass			

                            #Packets
                            try:
                                    packets = connection.split("Pkts:")[1].split(",")[0]
                                    #need to grab the previous lines configuration here or the last source/dest in their respective lists
                                    xferpaks = int(packets), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
                                    xferlist.append(xferpaks)
                            except:pass			
                    
                            #Bytes
                            try:
                                    bytes = connection.split("Bytes:")[1]
                                    #need to grab the previous lines configuration here or the last source/dest in their respective lists
                                    xferbytes = int(bytes), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
                                    xferbytelist.append(xferbytes)
                            except:pass	
                            
                    #parse to see if this is the outbound portion of the session.
                    if re.search("Out:", connection) != None:
                            #Interface
                            try:
                                    interface = connection.split("If:")[1].split(",")[0]
                                    interfacelist.append(interface)
                                    interfaces = interfaces  + 1	#For every session increase 1
                                    if debug == "debug":
                                            print("DEBUG: (interface)",interface)
                            except:pass			

                            #Packets
                            try:
                                    packets = connection.split("Pkts:")[1].split(",")[0]
                                    #need to grab the previous lines configuration here or the last source/dest in their respective lists
                                    xferpaks = int(packets), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
                                    xferlist.append(xferpaks)
                            except:pass			
                    
                    #Bytes
                            try:
                                    bytes = connection.split("Bytes:")[1]
                                    #need to grab the previous lines configuration here or the last source/dest in their respective lists
                                    xferbytes = int(bytes), srclist[-1], dstlist[-1], srcportlist[-1], destportlist[-1]
                                    xferbytelist.append(xferbytes)
                            except:pass				
                    
            ########################################################################################################################		
            ########################################################################################################################		
            ########################################################################################################################	


            #top talkers - source ip
            counts = {}
            srclist.sort()
            for s in srclist: #Count IP's
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            srcipl = [(v, k) for k, v in alist.items()]
            srcipl.sort()
            srcipl.reverse()
            srcipl = [(k, v) for v, k in srcipl]
            total_source_ips = source_ips



            #top talkers - dest ip
            counts = {}
            dstlist.sort()
            for s in dstlist: #Count IP's
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            dstipl = [(v, k) for k, v in alist.items()]
            dstipl.sort()
            dstipl.reverse()
            dstipl = [(k, v) for v, k in dstipl]
            total_dest_ips = dest_ips



            #top ports - source
            counts = {}
            srcportlist.sort()
            for s in srcportlist: #Count ports
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            srcportl = [(v, k) for k, v in alist.items()]
            srcportl.sort()
            srcportl.reverse()
            srcportl = [(k, v) for v, k in srcportl]
            total_source_ports = source_ports

            #top ports - dest
            counts = {}
            destportlist.sort()
            for s in destportlist: #Count ports
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            destportl = [(v, k) for k, v in alist.items()]
            destportl.sort()
            destportl.reverse()
            destportl = [(k, v) for v, k in destportl]
            total_dest_ports = dest_ports

            #top talkers - Policies
            counts = {}
            policylist.sort()
            for s in policylist: #Count IP's
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            policyl = [(v, k) for k, v in alist.items()]
            policyl.sort()
            policyl.reverse()
            policyl = [(k, v) for v, k in policyl]
            total_policies = policies


            #top talkers - Protocols
            counts = {}
            protocollist.sort()
            for s in protocollist: #Count IP's
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            protocoll = [(v, k) for k, v in alist.items()]
            protocoll.sort()
            protocoll.reverse()
            protocoll = [(k, v) for v, k in protocoll]
            total_protocols = protocols


            #top talkers - Interfaces
            counts = {}
            interfacelist.sort()
            for s in interfacelist: #Count IP's
                    if s in counts:
                            counts[s] += 1
                    else:
                            counts[s] = 1
            alist = counts
            interfacel = [(v, k) for k, v in alist.items()]
            interfacel.sort()
            interfacel.reverse()
            interfacel = [(k, v) for v, k in interfacel]
            total_protocols = interfaces


            #Top Talkers - Packets
            xferlist.sort()
            xferlist.reverse() 

            #Top Talkers - Bytes
            xferbytelist.sort()
            xferbytelist.reverse()
            

            ########################################################################################################################		
            ########################################################################################################################		
            ########################################################################################################################	

                            

           #Print stuff here

            self.txt.insert(tkinter.INSERT,"-SRX Session Analyzer-\n")
            self.txt.insert(tkinter.INSERT,"-Written By Tim Eberhard-\n")
            text = ("-Version:%s -\n\n\n" %versionnum)
            self.txt.insert(tkinter.INSERT,text)

            
            if self.sourceipf == True:
                self.txt.insert(tkinter.INSERT,'\n\n')	
                text = ("Top %d Source IP addresses: \n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections	-	IP Address\n")
                self.txt.insert(tkinter.INSERT,text)
                
                for i,j in srcipl[:self.numdisplayed]:					
                         pp = int(j)
                         source_ips_percent = pp/total_source_ips
                         text = ("%s	-	%s    (%s Percent) \n"%(pp, i, round(source_ips_percent*100, 2)))
                         self.txt.insert(tkinter.INSERT,text)



            if self.destinationipf == True:


                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Destination IP addresses: \n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections	-	IP Address \n")
                self.txt.insert(tkinter.INSERT,text)
                for i,j in dstipl[:self.numdisplayed]:					
                         pp = int(j)
                         dest_ips_percent = pp/dest_ips
                         text = ("%s	-	%s    (%s Percent) \n"%(pp, i, round(dest_ips_percent*100, 2)))
                         self.txt.insert(tkinter.INSERT,text)

            
            if self.sourceportf == True:
                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Source Ports: \n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections  -  Port -  Possible Service \n")
                self.txt.insert(tkinter.INSERT,text)
                for i,j in srcportl[:self.numdisplayed]:
                         p = int(i)
                         pp = int(j)
                         source_ports_percent = pp/total_source_ports					 
                         try:text = ("%s    -    %s   (%s) (%s Percent) \n"%(pp, i, portnum[p], round(source_ports_percent*100,2)))
                         except:text = ("%s    -    %s   (Not listed) (%s Percent) \n"%(pp, i, round(source_ports_percent*100,2) ))
                         self.txt.insert(tkinter.INSERT,text)

                
            if self.destinationportf == True:
                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Destination Ports:\n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections  -  Port -  Possible Service\n")
                self.txt.insert(tkinter.INSERT,text)
                for i,j in destportl[:self.numdisplayed]:
                         p = int(i)
                         pp = int(j)
                         dest_ports_percent = pp/total_dest_ports					 
                         try: text = ( "%s    -    %s   (%s) (%s Percent) \n"%(pp, i, portnum[p], round(dest_ports_percent*100,2)))
                         except:text = ( "%s    -    %s   (Not listed) (%s Percent) \n"%(pp, i, round(dest_ports_percent*100,2) ))
                         self.txt.insert(tkinter.INSERT,text)
                         



            if self.protocolf == True:
                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Protocols \n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections  -       Protocol \n")
                self.txt.insert(tkinter.INSERT,text)
                for i,j in protocoll[:self.numdisplayed]:                                  
                     pp = int(j)
                     p = int(i)
                     protocol_percent = pp/protocol
                     protocolnum
                     try:text = ("%s    -       %s  [%s]    (%s Percent) \n"%(pp, i, protocolnum[p], round(protocol_percent*100, 2)))
                     except:text = ("%s    -       %s    (%s Percent) \n"%(pp, i, round(protocol_percent*100, 2)))
                     self.txt.insert(tkinter.INSERT,text)


            
            if self.policyf == True:
                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Policies:\n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections	-	Policy\n")
                self.txt.insert(tkinter.INSERT,text)
                for i,j in policyl[:self.numdisplayed]:					
                         pp = int(j)
                         policies_percent = pp/policies
                         text = ("%s	-	%s    (%s Percent) \n"%(pp, i, round(policies_percent*100, 2)))
                         self.txt.insert(tkinter.INSERT,text)

            
            if self.interfacef == True:

                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Interfaces:\n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Number of Connections	-	Interface\n")
                self.txt.insert(tkinter.INSERT,text)
                for i,j in interfacel[:self.numdisplayed]:					
                         pp = int(j)
                         interfaces_percent = pp/interfaces
                         text = ("%s	-	%s    (%s Percent) \n"%(pp, i, round(interfaces_percent*100, 2)))
                         self.txt.insert(tkinter.INSERT,text)


                            
            if self.packetf == True:
                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Packets:\n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Source IP	-	Destination IP	-	Source Port 	-	Destination Port	-		Packets \n")
                self.txt.insert(tkinter.INSERT,text)
                for line in xferlist[:self.numdisplayed]:
                        text = ( "%s \t\t %s \t\t %s \t\t\t %s \t\t %s \n"%(line[1],line[2], line[3], line[4], line[0]))
                        self.txt.insert(tkinter.INSERT,text)
                        



            if self.bytef == True:
                text = ('*'*72)
                self.txt.insert(tkinter.INSERT,text)
                text = ('\n'*3)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Top %d Bytes:\n" %self.numdisplayed)
                self.txt.insert(tkinter.INSERT,text)
                text = ("Source IP	-	Destination IP	-	Source Port 	-	Destination Port	-		Bytes \n")
                self.txt.insert(tkinter.INSERT,text)
                for line in xferbytelist[:self.numdisplayed]:
                        text = ( "%s \t\t %s \t\t %s \t\t\t %s \t\t %s \n"%(line[1],line[2], line[3], line[4], line[0]))
                        self.txt.insert(tkinter.INSERT,text)
                                



if __name__ == '__main__':
    root = tkinter.Tk()
    Application(root)
    root.mainloop()

