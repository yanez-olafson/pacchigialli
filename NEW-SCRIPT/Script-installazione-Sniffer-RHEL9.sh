#!/usr/bin/bash
# NEW SATS/LT1 Sniffer configuration and installation script for RHEL9
# Version 1.00
# DHL Express Italy 2025
# Color: https://gist.github.com/vratiu/9780109



#*******************************************************************************************************************************
#VARIABLES



Yellow='\033[0;33m'         # Yellow
RED='\033[0;31m'            # Red
BYellow="\033[1;33m"        # Bold Yellow
Green="\033[0;32m"          # Green
NC='\033[0m'                # No color
parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )



#*******************************************************************************************************************************
#FUNCTIONS DEFINITION (for functions execution go at the end of the script)



abort-or-continue () {
while true; do
echo -e "${RED}Continue with the installation? [yn]: "
read yn
case $yn in
    [Yy]* ) echo -e "${RED}I will proceed with the next installation steps..${NC}";
            sleep 2;
            break;;
    [Nn]* ) echo -e "${RED}ABORTED!${NC}"; echo -e "${RED}TERMINATION OF THE SCRIPT!${NC}"; exit 1; break;;
    * ) echo -e "${RED}PLEASE ANSWER y or n";;
esac
done
echo ""
}




prerequisites () {
#Prerequisites
clear
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "                    ${RED}[*] ${BYellow}SATS/LT1 SNIFFER CONFIGURATION SCRIPT - NEW Version 1.00"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
echo "PREREQUISITES: please check the list below before continuing with installation"
echo ""
echo "1 - Verify that all files required for installation are present in the folder you launched the script"
echo ""
echo "2 - Check if there is an additional network card (eno1)"
echo ""
echo "3 - The script should be executed as root"
echo ""
echo "4 - This script works for RHEL 9.X. In case you are working with different versions, please edit properly repos installation step and check packages compatibility"
echo ""
echo -e "     ${Green}IF ALL REQUIREMENTS ARE MET, GO AHEAD AND CONTINUE WITH THE INSTALLATION${NC}"
echo ""
}

## aggiungere parte in cui viene aggiunto il certificato da usare per tutti gli sniffer e che ti dice quando scade


setvar () {
#Set default variables (CAMBIATO DEFAULT, MESSO LT1)
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "                    ${RED}[*] ${BYellow}Define Snigio3 Type (choose between SATS or LT1, default LT1)"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
echo -e "${BYellow}[*] ${Green}Insert the SNIFFER TYPE (choose between SATS or LT1, default LT1)${NC} [and press ENTER]:"
read Snigio
if [ "$Snigio" = "SATS" ] || [ "$Snigio" = "LT1" ] 
then
    Snigio=$Snigio
else
    Snigio="LT1"
fi
echo ""

#------------

echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "                    ${RED}[*] ${BYellow}Define site information"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
echo -e "${BYellow}[*] ${Green}Insert the DHL Express location, default is \"SGM-SATSLIGHT\" (EG: BGYBYD)${NC} [and press ENTER]:"
read Site_name
if [ -z $Site_name ]
then
    Site_name="SGM-SATSLIGHT"
fi
echo ""

#------------

echo -e "${BYellow}[*] ${Green}Insert the Maintenance windows (about 15 minutes) for the location, default is \"13\"${NC} [and press ENTER]:"
read hour
if [ -z $hour ]
then
    hour='13'
fi
echo ""

#------------

echo -e "${BYellow}[*] ${Green}Insert the enterface name to use as sniffer, default is \"eno1\"${NC} [and press ENTER]:"
read Sniff_interface
if [ -z $Sniff_interface ]
then
    Sniff_interface='eno1'
fi
echo -e "${BYellow}[*] ${Green}Insert specific filter for the capture session, default is \"tcp and port 8003\"${NC} [and press ENTER]:"
read Sniff_filter
if [ -z "$Sniff_filter" ]
then
    Sniff_filter='tcp and port 8003'
fi
Sniff_filter="$Sniff_filter"
echo ""

#------------

echo -e "${BYellow}[*] ${Green}Insert the OUTPUT PORT number for nxlog, default is \"4001\"${NC} [and press ENTER]:"
read output_port
if [ -z $output_port ]
then
    output_port='4001'
fi
echo ""

#------------
echo -e "Below are all the variables that will be used during installation:"
echo -e "${Green}Type of installation: ${BYellow}$Snigio"
echo -e "${Green}Site name: ${BYellow}$Site_name"
echo -e "${Green}Maintenance value used fron cron: ${BYellow}$hour"
echo -e "${Green}Sniffer interface: ${BYellow}$Sniff_interface"
echo -e "${Green}Sniffer filter: ${BYellow}$Sniff_filter${NC}"
echo -e "${Green}Graylog port: ${BYellow}$output_port${NC}"
echo ""
}




folders () {
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "         ${RED}[*] ${BYellow}Create folders"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
#Create folder for log, capture pcap and cert
mkdir /home/capture
mkdir /opt/cert && mkdir /opt/cert/snigio
mkdir /var/log/SNIGIO3
echo "The following folders have been created:"
echo "/home/capture"
echo "/opt/cert" 
echo "/opt/cert/snigio"
echo "/var/log/SNIGIO3"
echo ""
}




proxy () {
#Setup RHEL for internal Proxy
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "         ${RED}[*] ${BYellow}Configure proxy"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
sed -i "s/proxy_hostname =/proxy_hostname = b2b-http.dhl.com/g" /etc/rhsm/rhsm.conf
sed -i "s/proxy_hostname =.*/proxy_hostname = b2b-http.dhl.com/g" /etc/rhsm/rhsm.conf
sed -i "s/proxy_port =/proxy_port = 8080/g" /etc/rhsm/rhsm.conf
sed -i "s/proxy_port =.*/proxy_port = 8080/g" /etc/rhsm/rhsm.conf
rm -rf /etc/environment
echo "
export http_proxy=http://b2b-http.dhl.com:8080
export https_proxy=http://b2b-http.dhl.com:8080
export ftp_proxy=http://b2b-http.dhl.com:8080
export no_proxy=127.0.0.1,localhost,2.108.46.52,gititaly.dhl.com" >> /etc/environment
source /etc/environment
}




repos-rhel9 () {
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "         ${RED}[*] ${BYellow}Install Repos"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
#Install repos
subscription-manager repos --enable rhel-9-for-x86_64-baseos-rpms
subscription-manager repos --enable rhel-9-for-x86_64-appstream-rpms
#Install epel
epel=$(yum repolist | grep "epel")
if [[ -z $epel ]]
then
    subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
    yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
else
   echo "Repository 'epel' is already installed for this system."
fi
#Install Development Tools
devtool=$(yum grouplist Dev* installed | grep "Development tools")
if [[ -z $devtool ]]
then
    yum -y group install "Development Tools"
else
   echo "package group 'Development Tools' is already installed for this system."
fi
#-->check-repo
echo ""
echo -e "${RED}Here is the list of the repositories installed:${NC}"
echo -e "${Green}$(yum repolist | awk -F "repolist:" 'NR >3 {print $1}')${NC}"
echo ""
#update packages
echo -e "${Green}Updating packages..${NC}"
echo ""
yum update -y
}



dependecies () {
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "         ${RED}[*] ${BYellow}Install and configure dependencies (tshark, snigio, nxlog, scapy)"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
#Install related dependecies
yum -y install gcc gcc-c++ nano net-tools glib* libpcap-devel libgcrypt python3 python3-pip tcpdump libgcrypt-devel c-ares c-ares-dev* bison flex gettext libtool zlib-devel make patch binutils autoconf automake pkgconfig redhat-rpm-config rpm-build
#Install local dependecy for tshark build
# --> Valutare se installare cmake4
yum install cmake3
echo ""
# --> Verificare se rimuovere questa parte ******************************************
echo "Firewall configuration (for Check_MK agent)"
firewall-cmd --permanent --add-port=6556/tcp
firewall-cmd --reload
sed -i "s/#only_from      = 127.0.0.1 10.0.20.1 10.0.20.2/only_from      = 2.108.45.200/g" /etc/xinetd.d/check-mk-agent
systemctl restart check_mk.socket
netstat -lpn | grep 655
echo ""
echo "Continue to install and configure dependencies.."
# *******************************************************************************
mkdir /var/log/nxlog
#yum -y install ./snigio3/nxlog/*.rpm 
# installare specifici pacchetti e mantenere tutti gli rpm nella folder. Da tenere: base, odbc, python, perl.
yum -y install ./snigio3/nxlog/nxlog-6.3.9431_rhel9_x86_64.rpm
yum -y install ./snigio3/nxlog/nxlog-odbc-6.3.9431_rhel9_x86_64.rpm
yum -y install ./snigio3/nxlog/nxlog-python-6.3.9431_rhel9_x86_64.rpm
yum -y install ./snigio3/nxlog/nxlog-perl-6.3.9431_rhel9_x86_64.rpm
# ****************************************
which cmake3
cp -rf ./wireshark/wireshark*.tar.xz ./wireshark/wireshark.tar.xz
tar xJf ./wireshark/wireshark.tar.xz
mkdir wireshark-4.4.6/build
wireshark-4.4.6/tools/rpm-setup.sh --install-rpm-deps
wireshark-4.4.6/tools/rpm-setup.sh --install-optional
cd wireshark-4.4.6/build
#Build wireshark
cmake .. -G Ninja -DBUILD_wireshark=OFF -DCMAKE_BUILD_TYPE=Debug
ninja
ninja install
which tshark
# Install scapy
cd $parent_path
yum install python3-scapy
echo ""
}




nxlog () {
echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "   ${RED}[*] ${BYellow}Copy and configuration of nxlog file conf"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
echo ""
# Copy file for Snigio3 and NXLOG
cd $parent_path
if [ "$Snigio" = "SATS" ]
then
    # copy files for SATS
    cp -rf ./snigio3/nxlog/nxlog_SATS.conf /opt/nxlog/etc/nxlog.conf
    cp -rf ./snigio3/snigio3_SATS.py /usr/bin/snigio3.py
    cp -rf ./snigio3/SNIGIO_SATS /usr/bin/SNIGIO
else
    # copy files for LT1
    cp -rf ./snigio3/nxlog/nxlog_LT1.conf /opt/nxlog/etc/nxlog.conf
    cp -rf ./snigio3/snigio3_LT1.py /usr/bin/snigio3.py
    cp -rf ./snigio3/SNIGIO_LT1 /usr/bin/SNIGIO
fi
#sed -i "s/SGM-SATSLIGHT/$Site_name/g" /opt/nxlog/etc/nxlog.conf
#sed -i "s/5085/$output_port/g" /opt/nxlog/etc/nxlog.conf
cp -rf ./snigio3/nxlog/PARSER /opt/nxlog/etc
echo "nxlog.conf file copied and properly edited"
echo "snigio.py copied"
echo "SNIGIO and PARSER folder copied"
echo ""
# Set hostname in nxlog.conf
#servername=$(hostname)
#sed -i "s/servername/$servername/g" /opt/nxlog/etc/nxlog.conf
}



# DA TESTARE SEPARATAMENTE E POI INTEGRARE
#cron () {
#echo -e "${BYellow}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
#echo -e "   ${RED}[*] ${BYellow}Configure CRON"
#echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~${NC}"
#echo ""
#Copy scripts
#cp -rf cron-scripts/snigio_start_and_stop.sh cron-scripts/capture_cleaner.sh /opt/
#Set up crontab for daily clean up with maintenance windows set up early
#crontab -r
#echo ""
#echo "New Crontab configuration:"
#(crontab -l 2>/dev/null; echo "00 $hour * * * root /opt/snigio_start_and_stop.sh") | crontab -
#(crontab -l 2>/dev/null; echo "15 $hour */3 * * root /opt/capture_cleaner.sh") | crontab -
#crontab -l
#echo ""
#}




snigio () {
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "               [*] ${BYellow}Install snigio as service${NC}"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""
echo "[Unit]
Description=DHL Express Italy SNIFFER for SATS / LT1  (Tier 1 Vs. Tier 2)
After=multi-user.target
Conflicts=getty@tty1.service

[Service]
Type=idle
User=root
ExecStart=/usr/bin/python3 /usr/bin/snigio3.py --SedeDHL $Site_name --iface $Sniff_interface --Type $Snigio --filter $Sniff_filter
KillSignal=SIGTERM
StandardInput=tty-force

[Install]
WantedBy=multi-user.target" > /lib/systemd/system/snigio.service
systemctl daemon-reload
systemctl enable snigio.service
systemctl restart snigio.service
sleep 5
systemctl enable nxlog.service
systemctl restart nxlog.service
echo ""
}




check-snigio-svc () {
snigio_svc=$(systemctl status snigio.service | grep "active (running)")
if [[ -z $snigio_svc ]]
then
    echo -e "${RED}NOT OK. Snigio service is NOT up and running. Please check it with ${Yellow}journalctl -u snigio.service${NC}"
else
    echo -e "${Green}OK. Snigio service is UP and running!${NC}"
fi
echo ""
}




check-nxlog-svc () {
nxlog_svc=$(systemctl status nxlog.service | grep "active (running)")
if [[ -z $nxlog_svc ]]
then
    echo -e "${RED}NOT OK. Nxlog service is NOT up and running. Please check it with ${Yellow}journalctl -u nxlog.service${NC}"
else
    echo -e "${Green}OK. Nxlog service is UP and running!${NC}"
fi
echo ""
}




check-nxlog-port () {
graylog_port=$(netstat -punta | grep $output_port)
if [[ -z $graylog_port ]]
then
    echo -e "${RED}NOT OK. Graylog port $output_port is NOT REACHABLE. Please check your application${NC}"
    echo ""
    sleep 2
    echo -e "END OF THE SCRIPT. INSTALLATION COMPLETED WITH ERRORS"
else
    echo -e "${Green}OK. Graylog port $output_port is CONNECTED!${NC}"
    echo ""
    sleep 2
    echo -e "END OF THE SCRIPT. INSTALLATION COMPLETED"
fi
}




services () {
#check services: snigio, nxlog
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "               [*] ${BYellow}FINAL CHECKS${NC}"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""
echo -e "CHECKING SNIGIO SERVICE.."
sleep 2
check-snigio-svc
echo -e "CHECKING NXLOG SERVICE.."
sleep 2
check-nxlog-svc
echo -e "CHECKING CONNECTION TO GRAYLOG.."
sleep 2
check-nxlog-port
}

certificates () {
#Install certificate and check if it is still valid
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "               [*] ${BYellow}INSTALL NXLOG CERTIFICATE${NC}"
echo -e "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo ""
echo -e "To make nxlog work properly, is needed to install the certificate in the /opt/cert/snigio folder"
echo ""
sleep 2
echo -e "Checking if certificate, currently present in this repository, is still valid.."
cert_expiration=$(openssl x509 -enddate -noout -in ./snigio3/nxlog/graylog-cluster-ita.dhl.com.pem | cut -d= -f2)
cert_expiration_date=$(date -d "$cert_expiration" +%s)
current_date=$(date +%s)
if [[ $cert_expiration_date -lt $current_date ]]
then
    echo -e "${RED}The certificate is EXPIRED! Please renew it and copy it in the /opt/cert/snigio folder${NC}"
    echo ""
else
    echo -e "${Green}The certificate is VALID until $cert_expiration${NC}"
    echo ""
    echo -e "Copying certificate in the /opt/cert/snigio folder.."
    cp -rf ./snigio3/nxlog/graylog-cluster-ita.dhl.com.pem /opt/cert/snigio/
    echo -e "${Green}Certificate copied successfully!${NC}"
    echo ""
    ls -l /opt/cert/snigio/ 
    echo "" 
fi      
}


#*******************************************************************************************************************************
#FUNCTION EXECUTION (IN THE RIGHT ORDER)



# 1 -PREREQUISITES
prerequisites
abort-or-continue

#------------
# 2 - SET DEFAULT VARIABLES (CAMBIATO DEFAULT, MESSO LT1)
setvar
abort-or-continue

#------------
# 3 - CREATE FOLDERS FOR Snigio3
folders

#------------
# 4- SET PROXY
proxy
abort-or-continue

#------------
# 5 - INSTALL REPOS
repos-rhel9
abort-or-continue

#------------
# 6 - INSTALL DEPENDENCY
dependecies
abort-or-continue

#------------
# 7 - NXLOG CONFIG
nxlog
abort-or-continue

#------------
# 8 - NXLOG CERTIFICATES
certificates
abort-or-continue

#------------
# 9 - CONFIGURE CRON
#cron
#abort-or-continue

#------------
# 10 - INSTALL SNIGIO SERVICE
snigio

#------------
# 11 - CHECK SERVICES: snigio, nxlog
services



#*******************************************************************************************************************************
#END OF SCRIPT
