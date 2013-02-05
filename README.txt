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
