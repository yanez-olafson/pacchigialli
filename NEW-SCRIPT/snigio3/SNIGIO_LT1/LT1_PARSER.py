# PARSER CLASS for SNIGIO3, a SATS/LT1 Sniffer 
# Version 3.1.1
# DHL Express Italy S.r.l. - 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com

#############################################################
#                      Message PARSER                       #
#############################################################
#############################################################
import logging
from logging.handlers import RotatingFileHandler
import signal
import os
import subprocess as sub
import re
import SNIGIO.REGEXP
import SNIGIO.LOGGER

def snigio_LT1_sniffer_live():
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
        output = var_g.sniff.stdout.readline()
        if var_g.sniff.poll() is not None:
            break
        if output:
            try:
                load = str(output.strip())
                if var_g.CLI_DEBUG == 'YES':
                    print(load)
                try:
                    if re.search(SNIGIO.REGEXP.regexp_MSG_LT1, load):
                        load_sats_light = re.search(SNIGIO.REGEXP.regexp_MSG_LT1, load)
                        Frame_Time = load_sats_light.group(2)
                        IPSRC = load_sats_light.group(3)
                        IPDST = load_sats_light.group(4)
                        DATA = load_sats_light.group(5)
                        DATA = str(bytearray.fromhex(DATA).decode())
                        DATA = DATA[1:-1]
                        MQTYPE = "LT1 TCP/IP"
                        MSG = DATA + '"' + "<IP_SOURCE: " + IPSRC + ">" + "<IP_DESTINATION: " \
                                + IPDST + ">"
                        SNIGIO.LOGGER.messages.gray_logger_LT1(MSG, Frame_Time, MQTYPE)
                        
                    #elif re.search(SNIGIO.REGEXP.SATS_REGEXP.regexp_MSG_MQ, load):
                    #
                    #    load_sats_light = re.search(SNIGIO.REGEXP.SATS_REGEXP.regexp_MSG_MQ, load)
                    #    Frame_Time = load_sats_light.group(2)
                    #    MQTYPE = load_sats_light.group(3)
                    #    MQCODE = "130"
                    #    IPSRC = load_sats_light.group(4)
                    #    IPDST = load_sats_light.group(5)
                    #    load = "<IP_SOURCE: " + IPSRC + ">" + "<IP_DESTINATION: " \
                    #           + IPDST + ">" + "<MQCODE:" + MQCODE + ">"
                    #    SNIGIO.LOGGER.messages.gray_logger_SATS(load)

                    else:
                        MQTYPE = "No MQ Data Message"
                except:
                    SNIGIO.LOGGER.messages.gray_logger_SATS_error(load)
            except:
                SNIGIO.LOGGER.messages.gray_logger_SATS_error2(load)
    else:
        try:
            os.killpg(os.getpgid(sniff.pid), signal.SIGTERM)
        except:
            SNIGIO.LOGGER.messages.gray_logger_SATS_error5(load)

        try:
            var_g.snigio3.terminate()
        except:
            SNIGIO.LOGGER.messages.gray_logger_SATS_error6(load)