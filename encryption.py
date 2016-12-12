#! /usr/bin/env python
import os, crypto, argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--decrypt",action="store_true",help="Decrypt a file.")
    parser.add_argument("-e","--encrypt",action="store_true",help="Encrypt a file.")
    parser.add_argument("-rsa",action="store_true",help="Uses RSA protocal.")
    parser.add_argument("-eg",action="store_true",help="Uses the El Gamal protocal")

    parser.add_argument('path',help='Path of target file.')
    args = parser.parse_args()

    pub_keyl = ''
    pvt_keyl = ''
    print "Enter public key location(Enter for default) : "
    pub_key = raw_input("Path : ")
    if pub_key != '':
        pub_key = crypto.read_public_key(pub_key)
    print ""

    if len(pub_key) == 0:
        if args.rsa:
            pub_keyl = crypto.rsa_pblkl
        if args.eg:
            pub_keyl = crypto.eg_pblkl





    if args.encrypt:
        print ""
        print "Encrypting : ",args.path
        print " "
        if args.rsa:
            crypto.rsa_encrypt_file(args.path,pub_keyl)
            print "Finished Encrypting Using RSA"
            print ""

        if args.eg:
            print " "
            print "Secret integer file path (optional):"
            pth = raw_input()
            print ""
            print "Encrypting..."
            if pth != "":
                s = read_private_key(pth)
            if pth == "":
                s = -1
            crypto.eg_encrypt_file(args.path,pub_keyl,s)
            print "Finished Encrypting Using El Gamal"
            print ""
    if args.decrypt:
        print ""
        print "Decrypting : ", args.path
    
        print ""

        print "Enter private key location(Enter for default)"
        pvt_key = raw_input("Path : ")
        if pvt_key != '':
            pvt_key = crypto.read_public_key(pvt_key)
        print ""

        print "Decrypting ..."
        if len(pvt_key) == 0:
            if args.rsa:
                pvt_key = crypto.rsa_pvtkl
            if args.eg:
                pvt_key = crypto.eg_pvtkl
        
        raw_path = args.path
        alg = raw_path[raw_path.index(".")+1:raw_path.index(".")+4]

        if alg == 'rsa':
            if pub_keyl == '':
                pub_keyl = crypto.rsa_pblkl
            if pvt_keyl == '':
                pvt_keyl = crypto.rsa_pvtkl

            crypto.rsa_decrypt_file(args.path,pub_keyl,pvt_keyl)



        if alg == 'egh':
            if pub_keyl == '':
                pub_keyl = crypto.eg_pblkl
            if pvt_keyl == '':
                pvt_keyl = crypto.eg_pvtkl
            crypto.eg_decrypt_file(args.path,pub_keyl,pvt_keyl)
        print ""
        print "Finished Decrypting"
