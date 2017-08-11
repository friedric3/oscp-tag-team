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
         ix = TCP_SVC_PORTS.index(_port)
         if ix > 0:
	     doRecon(ip, TCP_SVC_PORTS[ix])

def doHttpNmap( ip, port ):
	WEB_OUT_FILE = WIP_DIR + "/" + ip + "_http_scripts.txt"
  	http_scripts = ("http-enum,http-headers,http-methods,http-iis-webdav-vuln,"
		"http-php-version,http-put,http-wordpress-enum,http-wordpress-users,"
		"ssl-heartbleed,http-shellshock")
	http_cmd =  "nmap -sS -A -T4 --script=" + http_scripts + " -p " + str(port) + " " + ip + ">>" + WEB_OUT_FILE
	print("\nExecuting: " + http_cmd)
	os.system(http_cmd)

def doNikto( ip, port ):
	NIKTO_OUT_FILE = WIP_DIR + "/" + ip + "_nikto.txt"
	nikto_cmd =  "nikto -h http://" + ip + " >>" + NIKTO_OUT_FILE
	print("\nExecuting: " + nikto_cmd)
	os.system(nikto_cmd)

def doGoBuster( ip, port ):
	GB_OUT_FILE = WIP_DIR + "/" + ip + "_gobuster.txt"
	word_list = "/usr/share/seclists/Discovery/Web_Content/big.txt"
	gb_cmd =  "gobuster -u http://" + ip + " -w " + word_list + " >> " + GB_OUT_FILE
	print("\nExecuting: " + gb_cmd)
	os.system(gb_cmd)


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
	   print(WIP_DIR) 
	elif port == 25:
	   ## do smtp enum
	   print(WIP_DIR) 
        elif port == 445:
	   ## do enum4linux
	   print(WIP_DIR) 
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


