import sys
import os
from libnmap.parser import NmapParser
import multiprocessing as mp
import threading

#### GLOBAL variables ########

EUID=os.geteuid()
SCRIPT_NAME=os.path.basename(__file__)

##### NMAP OPTIONS ###########
NMAP_CMD="nmap"
TOP_UDP_PORTS="60"  ## this variable will hold top ports to scan change if needed
OUTPUT_OPT=" -oX " ## This will save result into XML file, change it to -oG or -oS if needed
QUICK_NMAP=" -Pn -sV -T5 " ## NOTE: this is a quick discovery -F option will scan less ports, use AGGRESSIVE to follow up
AGG_TCP_NMAP=" -sV -p- -T5 -A " ## This is aggressive scan all 65535 ports
TOP_UDP_NMAP=" -sU -A --top-ports=" + TOP_UDP_PORTS ## Scan top ports 

TCP_SVC_PORTS=[21,25,80,445]

###### FILE OUTPUT OPTIONS ########
QUICK_SCAN_XML="_QUICK_SCAN.xml"
AGG_SCAN_XML="_AGGRESSIVE_SCAN.xml"

##### XSLTPROC CMD ###
XSLT_CMD="xsltproc "

def printUsage():
   print("Usage:")
   print("\tsudo "+SCRIPT_NAME + " 10.11.1.2 /tmp")
   print("\tsudo "+SCRIPT_NAME + " 10.11.1.0/24 /tmp")

def dirExists(path):
   if len(path) > 0 and not os.path.exists(path):
        ### Create directory if doesn't exist
	os.mkdir(path)
      
def doTransform(xmlfile):
   os.system(XSLT_CMD + xmlfile +  " -o " + xmlfile.replace(".xml", ".html") )

def doXMLParse(xmlfile):
   _xml = NmapParser.parse_fromfile(xmlfile)
   for _host in _xml.hosts:
      ip = (_host.address)
      for services in _host.services:
	 _port = services.port
         if _port in TCP_SVC_PORTS:
	     doRecon(ip, _port)

def doHttpNmap( ip, port ):
	WEB_OUT_FILE = WIP_DIR + "/" + ip + "_http_scripts.txt"
  	http_scripts = ("http-enum,http-headers,http-methods,http-iis-webdav-vuln,"
		"http-php-version,http-put,http-wordpress-enum,http-wordpress-users,"
		"ssl-heartbleed,http-shellshock")
	http_cmd =  "nmap -sS -A -T4 --script=" + http_scripts + " -p " + str(port) + " " + ip + " >> " + WEB_OUT_FILE
	print("\n[*] Executing: " + http_cmd)
	os.system(http_cmd)

def doNikto( ip, port ):
	NIKTO_OUT_FILE = WIP_DIR + "/" + ip + "_nikto.txt"
	nikto_cmd =  "nikto -h http://" + ip + " >> " + NIKTO_OUT_FILE
	print("\n[*] Executing: " + nikto_cmd)
	os.system(nikto_cmd)

def doGoBuster( ip, port ):
	GB_OUT_FILE = WIP_DIR + "/" + ip + "_gobuster.txt"
	word_list = "/usr/share/seclists/Discovery/Web_Content/big.txt"
	gb_cmd =  "gobuster -u http://" + ip + " -w " + word_list + " >> " + GB_OUT_FILE
	print("\n[*] Executing: " + gb_cmd)
	os.system(gb_cmd)

def doFtp( ip, port ):
	FTP_OUT_FILE = WIP_DIR + "/" + ip + "_ftp_scripts.txt"
	ftp_cmd =  "nmap -sS -A -T4 --script=ftp* -p " + str(port) + " " + ip + " >> " + FTP_OUT_FILE
	print("\n[*] Executing: " + ftp_cmd)
	os.system(ftp_cmd)

def doSmtp( ip, port ):
	SMTP_OUT_FILE = WIP_DIR + "/" + ip + "_smtp_enum.txt"
	word_list = "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"
	smtp_cmd =  "smtp-user-enum -M VRFY -U " + word_list + " -t " + ip + " >> " + SMTP_OUT_FILE
	print("\n[*] Executing: " + smtp_cmd)
	os.system(smtp_cmd)

def doSmb( ip, port ):
	SMB_OUT_FILE = WIP_DIR + "/" + ip + "_smb_enum.txt"
	smb_cmd =  "enum4linux -a " + ip + " >> " + SMB_OUT_FILE
	print("\n[*] Executing: " + smb_cmd)
	os.system(smb_cmd)



def doRecon(ip, port):
   if len(ip) > 0 and port > 0:
	if port == 80:
	  ## do nikto, dirb, gobuster
	  ## Doing this in 3 different concurrent threads for speed??
 
	  t = threading.Thread(target=doHttpNmap, args=(ip,port))	
	  threads.append(t)
	  t.start()

	  t = threading.Thread(target=doNikto, args=(ip,port))	
	  threads.append(t)
	  t.start()

	  t = threading.Thread(target=doGoBuster, args=(ip,port))	
	  threads.append(t)
	  t.start()
	elif port == 21:
	  ## discover with nmap ftp* scripts
	  t = threading.Thread(target=doFtp, args=(ip,port))	
	  threads.append(t)
	  t.start()
	elif port == 25:
	  ## do smtp enum
	  t = threading.Thread(target=doSmtp, args=(ip,port))	
	  threads.append(t)
	  t.start()
        elif port == 445:
	  ## do enum4linux
	  t = threading.Thread(target=doSmb, args=(ip,port))	
	  threads.append(t)
	  t.start()
   else:
      print("Empty IP and/or Port, exiting!")
      exit

def doScan(option, filename, ip):
   cmd=""
   if option == "q":
      ## do quick scan
      cmd = NMAP_CMD + QUICK_NMAP + OUTPUT_OPT + filename + " " + ip 
      print("executing quick scan " + cmd)
   elif option == "a":
      ## do aggressive scan
      cmd = NMAP_CMD + AGG_TCP_NMAP + OUTPUT_OPT + filename + " " + ip 
      print("executing aggessive scan " + cmd)

   ## Execute nmap commands
   os.system(cmd)
   ## Do post processing
   doTransform(filename)  ## transform xml file to html format for viewing
   if option == "q":
      doXMLParse(filename)

if len(sys.argv) < 3:
   printUsage()
   sys.exit()
elif EUID > 0:
   print("You are not root!")
   printUsage()
else:
   threads = []
   IP_CDIR=sys.argv[1]
   WIP_DIR=sys.argv[2] 
  
   dirExists(WIP_DIR) ## making sure if directory exists first..if not create.

   quick_scan_file=WIP_DIR + "/" + IP_CDIR.replace("/","-") + QUICK_SCAN_XML
   agg_scan_file=WIP_DIR + "/" + IP_CDIR.replace("/","-") + AGG_SCAN_XML

   doScan("q", quick_scan_file, IP_CDIR) 
   #doScan("a", agg_scan_file, IP_CDIR) 


