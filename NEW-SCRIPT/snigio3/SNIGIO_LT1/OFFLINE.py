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

def start_READ():
    import SNIGIO.my_global as var_g
    # Define signal for service stop
    var_g.logger = logging.getLogger('Snigio')
    var_g.logger.setLevel(logging.DEBUG)
    #20971520 = 20M
    var_g.handler = RotatingFileHandler(var_g.LOG_PATH, maxBytes=409715200, backupCount=0)
    var_g.logger.addHandler(var_g.handler)
    # Start reading pcap
    if var_g.ENV_TYPE == "SATS" and var_g.MQDEBUG == "NO":
        var_g.snigio3 = Process(target=snigio_SATS_sniffer)
    elif var_g.ENV_TYPE == "LT1" and var_g.MQDEBUG == "NO":
        var_g.snigio3 = Process(target=snigio_LT1_sniffer_offline)
    else:
        sys.exit(0)
    
    var_g.snigio3.start()