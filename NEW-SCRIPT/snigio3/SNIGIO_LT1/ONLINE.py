# ONLINE SNIFFER for SNIGIO3, a SATS/LT1 Sniffer 
# Version 3.2.3
# DHL Express Italy S.r.l. - 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com


import sys
import logging
import time
import signal
import re
import os
from multiprocessing import Process
import subprocess as sub
from logging.handlers import RotatingFileHandler

# SNIGIO IMPORT

#import LT1_PARSER

import SNIGIO.LOGGER
from SNIGIO.SATS_PARSER import *
from SNIGIO.LT1_PARSER import *


#############################################################
#                      ALIVE MESSAGE                        #
#############################################################
#############################################################


def handler_stop_signals(signum, frame):
    import SNIGIO.my_global as var_g
    var_g.run = False


#############################################################
#                    SATS LIVE SNIFFER                      #
#############################################################
#############################################################
def start_LIVE():
    import SNIGIO.my_global as var_g
    # Signals
    var_g.run = True
    # Define signal for service stop
    signal.signal(signal.SIGTERM, handler_stop_signals)
    var_g.logger = logging.getLogger('Snigio')
    var_g.logger.setLevel(logging.DEBUG)
    #20971520 = 20M
    var_g.handler = RotatingFileHandler(var_g.LOG_PATH, maxBytes=409715200, backupCount=0)
    var_g.logger.addHandler(var_g.handler)
    # Process configuration
    procs = []
    # Start snigio
    if var_g.ENV_TYPE == "SATS":
        var_g.snigio3 = Process(target=snigio_SATS_sniffer_live)
    elif var_g.ENV_TYPE == "LT1":
        var_g.snigio3 = Process(target=snigio_LT1_sniffer_live)
    else:
        sys.exit(0)
    var_g.snigio3.daemon = True
    var_g.snigio3.start()
    
    time.sleep(5)
    while var_g.run:
        while var_g.run:          
            if var_g.snigio3.is_alive():

                SNIGIO.LOGGER.messages.snigio3_alive()
            else:
                SNIGIO.LOGGER.messages.snigio3_stop()
                if var_g.ENV_TYPE == "SATS":
                    var_g.snigio3 = Process(target=snigio_SATS_sniffer)
                elif var_g.ENV_TYPE == "LT1":
                    var_g.snigio3 = Process(target=snigio_LT1_sniffer_live)
                var_g.snigio3.daemon = True
                var_g.snigio3.start()
                time.sleep(5)
            time.sleep(var_g.alive_time)
    else:
        try:
            os.killpg(os.getpgid(var_g.sniff.pid), signal.SIGTERM)
        except:
            SNIGIO.LOGGER.messages.snigio3_pid()
        try:
            var_g.snigio3.terminate()
        except:
            SNIGIO.LOGGER.messages.snigio3_process()
        SNIGIO.LOGGER.messages.snigio3_stop()
        sys.exit(0)