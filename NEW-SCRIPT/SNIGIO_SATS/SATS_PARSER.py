# PARSER CLASS for SNIGIO3, a SATS/LT1 Sniffer 
# Version 3.2.3
# DHL Express Italy S.r.l. - 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com

#############################################################
#                      Message PARSER                       #
#############################################################
#############################################################
import sys
import logging
from logging.handlers import RotatingFileHandler
#from time import gmtime, strftime
from datetime import datetime
import signal
import os
import subprocess as sub
import re
import SNIGIO.REGEXP
import SNIGIO.LOGGER

############################################################
#                       LIVE SNIFFER                       #
############################################################
############################################################

def snigio_SATS_sniffer_live():
    import SNIGIO.my_global as var_g
    # Configure and start sniffer
    if var_g.CLI_DEBUG == 'YES':
        print(var_g.command)
    var_g.sniff = sub.Popen(var_g.command, stdout=sub.PIPE, shell=True,
                      stderr=sub.STDOUT)
    # Send start to graylog
    SNIGIO.LOGGER.messages.snigio3_start()
    # Main sniffer loop
    while var_g.run:
        #sys.stdout=open("/tmp/pacchetti.txt","a")
        output = var_g.sniff.stdout.readline()
        #print (output)
        #print ("ciao")
        #sys.stdout.close()
        if var_g.sniff.poll() is not None:
            break
        if output:
            try:
                load = str(output.strip())
                if var_g.CLI_DEBUG == 'YES':
                    print("_____________START LOAD___________")
                    print(load)
                    print("______________END LOAD____________")
                try:
                    # MQ PACKETS BETWEEN T1 and T2
                    if re.search(SNIGIO.REGEXP.regexp_MSG_MQ, load):
                        # Add frametime from sats msg
                        load_sats_tshark = re.search(SNIGIO.REGEXP.regexp_MSG_extract, load)
                        MQCODE = load_sats_tshark.group(1)
                        MQTYPE = SNIGIO.REGEXP.typeofcode(MQCODE)
                        IPSRC = load_sats_tshark.group(3)
                        IPDST = load_sats_tshark.group(5)
                        DATA = load_sats_tshark.group(4)
                        # ESTRAZIONE ARRIVAL TIME FRAME TCP DA TSHARK
                        ARRIVALTIME = load_sats_tshark.group(6)
                        #if re.search(SNIGIO.REGEXP.regexp_DATE, DATA):
                        #    Frame_Time = re.search(SNIGIO.REGEXP.regexp_DATE, DATA)
                        #    Frame_Time = Frame_Time.group(1)
                        #    print(Frame_Time)
                        #else:
                        #Frame_Time = strftime("%Y-%m-%d %H:%M:%S.%f", gmtime())
                        #ESTRAZIONE TEMPO MACCHINA IN ESECUZIONE SNIGIO
                        #ORA = datetime.now()                        
                        #TTZ = str(ORA.astimezone())
                        #Frame_Time = TTZ[:19]+","+TTZ[20:23]+TTZ[26:]
                        # TRASFORMAZIONE ARRIVAL TIME NEL FORMATO ATTESO DA LOGICA SUCCESSIVA E NXLOG
                        AT = ARRIVALTIME[:28]
                        FORMATO_DATA = '%b %d, %Y %H:%M:%S.%f'
                        AT = datetime.strptime(AT, FORMATO_DATA)
                        AT = str(AT.astimezone())
                        AT = AT[:19]+","+AT[20:23]+AT[26:]
                        Frame_Time = AT
                        MSG = DATA + "<IP_SOURCE: " + IPSRC + ">" + "<IP_DESTINATION: " + IPDST + ">" + "<MQCODE:" + MQCODE + ">"
                        SNIGIO.LOGGER.messages.gray_logger_SATS(MSG, Frame_Time, MQTYPE)
                    # ALERT DISCONNECTING PACKETS BETWEEN T1 and T2    
                    elif re.search(SNIGIO.REGEXP.regexp_MSG_DISC, load):
                        load_sats_tshark = re.search(SNIGIO.REGEXP.regexp_MSG_DISC, load)
                        MQCODE = load_sats_tshark.group(1)
                        MQTYPE = SNIGIO.REGEXP.typeofcode(MQCODE)
                        SNIGIO.LOGGER.messages.gray_logger_MQDEBUG(MQCODE, MQTYPE)  
                    # NCY PACKETS BETWEEN T1 and Laser Scanner
                    elif re.search(SNIGIO.REGEXP.regexp_MSG_NCY, load):
                        load_sats_tshark = re.search(SNIGIO.REGEXP.regexp_MSG_NCY, load)
                        MQTYPE = load_sats_tshark.group(1)
                        MQCODE = "TCP-NCY"
                        DATA = load_sats_tshark.group(2)
                        IPSRC = load_sats_tshark.group(3)
                        IPDST = load_sats_tshark.group(4)
                        DATA = bytearray.fromhex(DATA).decode()
                        DATA = DATA.rstrip()
                        DATA = re.sub('&lt;', '<', DATA)
                        if re.search(SNIGIO.REGEXP.regexp_NCY_time, DATA, re.MULTILINE):
                            Frame_Time = re.search(SNIGIO.REGEXP.regexp_NCY_time, DATA, re.MULTILINE)
                            Frame_Time = str(Frame_Time.group(1)) + " GMT"
                        if re.search(SNIGIO.REGEXP.regexp_NCY_data3, DATA, re.MULTILINE):
                            DATA = re.search(SNIGIO.REGEXP.regexp_NCY_data3, DATA, re.MULTILINE)
                            DATA = DATA.group(1)
                        #elif re.search(SNIGIO.REGEXP.regexp_NCY_data, DATA, re.MULTILINE):
                        #    DATA = re.search(SNIGIO.REGEXP.regexp_NCY_data, DATA, re.MULTILINE)
                        #    DATA = DATA.group(1)
                        #elif re.search(SNIGIO.REGEXP.regexp_NCY_data3, DATA, re.MULTILINE):
                        #    DATA = re.search(SNIGIO.REGEXP.regexp_NCY_data3, DATA, re.MULTILINE)
                        #    DATA = DATA.group(1)
                        elif re.search(SNIGIO.REGEXP.regexp_NCY_data4, DATA, re.MULTILINE):
                            DATA = re.search(SNIGIO.REGEXP.regexp_NCY_data4, DATA, re.MULTILINE)
                            DATA = DATA.group(1)
                        else:
                            if var_g.CLI_DEBUG == 'YES':
                                print("No NCY Message")
                        MSG = DATA + "<IP_SOURCE: " + IPSRC + ">" + "<IP_DESTINATION: " \
                                + IPDST + ">" + "<MQCODE:" + MQCODE + ">"
                        SNIGIO.LOGGER.messages.gray_logger_SATS_NCY(MSG, Frame_Time, MQTYPE)
                    #MQ DEBUG for all MQ packets
                    elif var_g.MQDEBUG == "YES":
                        if re.search(SNIGIO.REGEXP.regexp_MQTYPE, load):
                            load_sats_tshark = re.search(SNIGIO.REGEXP.regexp_MQTYPE, load)
                            MQCODE = load_sats_tshark.group(1)
                            MQTYPE = SNIGIO.REGEXP.typeofcode(MQCODE)
                            SNIGIO.LOGGER.messages.gray_logger_MQDEBUG(MQCODE, MQTYPE)
                    else:
                        mess = "No MQ or NCY data"
                except:
                    SNIGIO.LOGGER.messages.gray_logger_SATS_error(load)
            except:
                SNIGIO.LOGGER.messages.gray_logger_SATS_error2(load)
    else:
        if var_g.MODE == "ON":
            try:
                os.killpg(os.getpgid(sniff.pid), signal.SIGTERM)
            except:
                SNIGIO.LOGGER.messages.gray_logger_SATS_error5(load)
            try:
                var_g.snigio3.terminate()
            except:
                SNIGIO.LOGGER.messages.gray_logger_SATS_error6(load)
