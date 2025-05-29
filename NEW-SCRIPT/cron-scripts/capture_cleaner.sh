#! /bin/bash
# SATS/LT1 Sniffer configuration and install script for RHEL
# Version 3.0.3
# DHL Express Italy 2022
# Requiremets: TSHARK for live capture and SCAPY for Offline pcap analysis
# For info, please contact alberto.biasibtti@dhl.com
echo ""
echo "[*] Stop Snigio and NXLOG"
systemctl stop snigio && systemctl stop nxlog
systemctl status snigio
systemctl status nxlog
echo  ""
echo "[*] Dalete temp file"
rm -rf /var/log/SNIGIO3/snigio3.log
rm -rf /home/capture/*
echo ""
echo "[*] Start Snigio and NXLOG"
echo ""
systemctl start snigio && systemctl start nxlog
systemctl status snigio
systemctl status nxlog
echo ""