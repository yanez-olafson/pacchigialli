# REGEX CLASS for SNIGIO3, a SATS/LT1 Sniffer 
# Version 3.2.2
# DHL Express Italy S.r.l. - 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com

#############################################################
#                          REGEXP                           #
#                           SATS                            #
#############################################################
#############################################################

def typeofcode(MQCODE):
    mqtypecode_source = ["0xr", "0x86", "0x82", "0x81", "0x91", "0x86", "0x84", "0x94", "0x92", "0x83", "0x93", "0x0c", "0x0e", "0x0f", "ini", "0xa8", "0x0d", "0x86"]
    mqname = ["ASYNC_MESSAGE", "MQPUT", "MQDISC", "MQCONN", "MQCONN_REPLY", "MQPUT_REPLY", "MQCLOSE", "MQCLOSE_REPLY", "MQDISC_REPLY", "MQOPEN", "MQOPEN_REPLY", "SOCKET_ACTION", "REQUEST_MSGS", "NOTIFICATION", "INITIAL_DATA", "USERID_DATA", "ASYNC_MESSAGE", "MQPUT"]
    MQCODE = mqname[mqtypecode_source.index(MQCODE)]
    return MQCODE

# Regexp for MQ data messages (MQPUT, ..)
regexp_MSG_MQ = r"^b\'(0x0d|0x86)"

regexp_MSG_extract = r"^b\'(.+)\\t0x0018\\t(.+)\\t(.+)\\t(.+)\\t(.+)\\t(.+)\'"

# Regexp for MQ data without data messages (MQDISC, MQDISC_REPLY, INITIAL_DATA, ..)
regexp_MSG_MSG = r"(?<=\<MSG\>)(.*?)(?=\<\/MSG\>)"

# Regexp for MQ data messages (MQPUT, ..)
regexp_MSG_DISC = r"^b\'(0x82|0x92)"

# Extract HDEVTM for Frame Time
regexp_DATE = r"(?<=\<HDEVTM\>)(.*?)(?=\<\/HDEVTM\>)"

# Reg exp for MQTYPE code
regexp_MQTYPE = r"^b\'(0xr0|0x86|0x82|0x81|0x91|0x86|0x84|0x94|0x92|0x83|0x93|0x0c|0x0e|0x0f|ini|0xa8)"

# Regexp for NCY SATS data messages (TCP)
regexp_MSG_NCY = r"^b\'(0x0018|0x0010|0x0019)\\t(.+)\\t(.+)\\t\\t(.+)\'"

# Regexp for NCY SATS data messages (TCP)
#regexp_NCY_data = r"(?<=:Body>)(.*?)(?=:Body>)"
#regexp_NCY_data2 = r":Body>(.+)""
regexp_NCY_data3 = r"<ser:(.+)"
regexp_NCY_data4 = r"<ns2:(.+)"
regexp_NCY_time = r"(?<=Date:\ )(.*?)(?=\ GMT)"


#############################################################
#                          REGEXP                           #
#                           LT1                             #
#############################################################
#############################################################

#MSG
regexp_MSG_LT1 = r"^(b\'(.+)\\t\\t\\t(.+)\\t(.+)\\t(.+))\'"
#FRAMETIME
regexp_Frametime = r"(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{3})"
#I_SR RegExp
regex_I_SR = r"(I_SR)(\d{16})(\d{6}|\s{6})(.{10})(\d{15})(Y|N)(D)(Y|N)(S|E)(\d{16})(\d{5})(\d{5})(\d{5})(\d{5})(W)(Y|N)(S|E)(\d{16})(\d{5})(B)(\w{10})(\d{15})(G|B)(\d{2})"
regex_I_SR_B = r"(I_SR)(\d{16})(\d{6}|\s{6})(.{10})(\d{15})(Y|N)(D)(Y|N)(S|E)(\d{16})(\d{5})(\d{5})(\d{5})(\d{5})(W)(Y|N)(S|E)(\d{16})(\d{5})(B)(\w{10})(\d{15})(G)(\d{2})(.+)"
reg_msg_I_SR = r"(I_SR)"
#I_SI RegExp
regex_I_SI = r"(I_SI)(\d{16})(.{50})(S|N)(\d{2})(.+)"
reg_msg_I_SI = r"(I_SI)"
#I_DR RegExp
regex_I_DR = r"(I_DR)(\d{16})(P|V)(OK\ \ |FAIL|OVER)"
regex_I_DR_OK = r"(I_DR)(\d{16})(P|V)(OK\ \ |FAIL|OVER)(.+)"
reg_msg_I_DR = r"(I_DR)"
#Barcode_ext
barcode_ext01 = r"^(\d{2})(\d{4})(\d+)"
#Captured_barcode multivalid
regexp_multivalid = r"(JJD\\d+JJD\\d+)|(0500\\w+0500\\w+)|(0500\\w+0600\\w+)|(0600\\w+0500\\w+)"
#Snigio message
regexp_snigio = r"(Sniffer\ is\ alive)|(Error\, packet lost\. S\-\-t happens\!)|(Sniffer\ is\ stopped)|(Sniffer\ Started)|(No\ Active\ Process)|(No\ active\ PID)"
#FailureCode Parser
FailureCode_source = ["0000", "0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "09"]
FailureName = ["No failure", "Sort Instruction received too late to be executed", "No sort instruction received", "Destination full", "Destination does not exist", "Item not detected on carrier / Piece lost", "Chute disabled", "FLY Chute buffer is full and discharge flap closed", "Sorter speed out of threshold", "Too many simultaneous discharge"]
#JJD Extraction
JJD_Extract = r"(21JJD\d{18})"
       
   
#############################################################
#   MQ Message Types (with row identification, could be used as RegExp):
#   
#
#   MSG_TYPE = "MQDISC"         T2 > T1
#                               (820\\)
#   MSG_TYPE = "MQDISC_REPLY"   T1 > T2
#                               ("920\\")
#   MSG_TYPE = "INITIAL_DATA"   T1 > T2
#                               ("\\x00\\x00\\x00\"\\")                            
#   MSG_TYPE = "USERID_DATA"    T2 > T1
#                               ("\\xa8\\")
#   MSG_TYPE = "MQCONN"         T2 > T1
#                               ("810\\")
#   MSG_TYPE = "MQCONN_REPLY"   T1 > T2
#                               ("910\\")
#   MSG_TYPE = "MQOPEN"         T2 > T1
#                               ("830\\")
#   MSG_TYPE = "MQOPEN_REPLY"   T1 > T2
#                               ("930\\")
#   MSG_TYPE = "MQCLOSE"        T2 > T1
#                               ("840\\")
#   MSG_TYPE = "MQCLOSE_REPLY"  T1 > T2
#                               ("940\\")
#   MSG_TYPE = "REQUEST_MSGS"   T2 > T1
#                               ("0e\\")
#   MSG_TYPE = "NOTIFICATION"   T1 > T2
#                               ("0f\\")
#   MSG_TYPE = "SOCKET_ACTION"  T1 > T2
#                               ("0c\\")
#   MSG_TYPE = "MQPUT"          T2 > T1
#                               ("860\\") => Find the <MSG>
#   MSG_TYPE = "MQPUT_REPLY"    T1 > T2
#                               ("960\\")
#   MSG_TYPE = "ASYNC_MESSAGE"  T1 > T2
#                               ("0d\\") => Find the <MSG>      

## TSHARK SATS MQ MESSAGE
#INITIAL_DATA    1
#USERID_DATA     8
#SOCKET_ACTION   12
#ASYNC_MESSAGE   13
#REQUEST_MSGS    14
#NOTIFICATION    15
#MQCONN          129
#MQCONN_REPLY    145
#MQPUT           134
#MQPUT_REPLY     150
#MQCLOSE         132
#MQCLOSE_REPLY   148	
#MQDISC          130
#MQDISC_REPLY    146
#MQOPEN          131
#MQOPEN_REPLY    147
#REQUEST_MSG     150
