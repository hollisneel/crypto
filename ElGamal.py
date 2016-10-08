#! /usr/bin/env python
import os, crypto, argparse

pvtkl = crypto.pvtkl
pblkl = crypto.pblkl

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--decrypt",action="store_true",help="Decrypt a file." )
    parser.add_argument("-e","--encrypt",action="store_true",help="Encrypt a file.")
    parser.add_argument("-pblk","-pblk",action="store_true",help="Create a public and private key.")
    parser.add_argument('path',help="Path of target file.")
    args = parser.parse_args()
    filepath = args.path
    if args.encrypt:
        print ''
        print "Encrypting: " + filepath
        print " "
        print "If using your public key press enter, else enter public key path."
        fl = raw_input("Public Key Path : ")
        print ' '
        print 'encrypting ...'
        crypto.encrypt_file(filepath,pblkl)
        print ' '
        print "Finished encrypting"
    if args.decrypt:
        print " "
        print "decrypting: ", filepath 
        crypto.decrypt_file(filepath,pblkl,pvtkl)
        print "Finised decrypting"

