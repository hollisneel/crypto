#!/usr/bin/env python

import os, random, argparse

# Change to private key location
pvtkl = '/media/hollis/Hollis/private_keys/private_key.txt'
pblkl = '/home/hollis/dev/crypto/ElGamal/public_key.txt'
#############################

def string_to_ascii(message):
    ''' 
        This takes a string (message) and converts it into an 
        integer.

    '''
    int_mssg = '30'
    for a in message:
        spp = str(ord(a))
        while len(spp) < 3:
            spp = '0' + spp
        int_mssg += spp

    return int(int_mssg)

def ascii_to_string(integer):
    ''' 
        Takes an integer(with ascii values) and returns a message.

    '''
    message = str(integer)
    txt = ''
    chars = []
    message.replace('L','')
    message = message[2:len(message)]
    while len(message)%3 != 0:
        message = '0' + message
    for a in range(len(message)/3):
        chars.append(message[3*a:3*a+3])       

    for a in chars:
        if a.isalnum:
            txt += chr(int(a))
    return txt


def euclid_alg(num1,num2):
    ''' 
        Finds the GCD of two numbers.
        It returns all of the information 
        from the Euclidean algorithm.

        returns GCD if GCD != 1
    '''
    if num1 > num2:
        temp = int(num2)
        num2 = num1
        num1 = temp

    r = 2
    q = -1
    a = num2
    b = num1
    info = {'r':[],'q':[],'a':[],'b':[]}    

    while r != 0:
        q = a/b
        r = a - q*b
        if r == 0:
            break
        info['r'].append(r)
        info['q'].append(q)
        info['a'].append(a)
        info['b'].append(b) 

        a = int(b)
        b = int(r)

    if b != 1:
        return b        

    return info


def inverse(num,prime):
    '''

        Takes a number and a prime and computes an
        inverse mod p.

    '''

    info = euclid_alg(num,prime)
    X = [-info['q'][0]]
    Y = [1]

    if len(info['q']) > 1:
        X.append(info['q'][1]*info['q'][0]+1)
        Y.append(-info['q'][1])

    it = 2
    while it < len(info['q']):
        X.append(X[it-2]-info['q'][it]*X[it-1])
        Y.append(Y[it-2]-info['q'][it]*Y[it-1])
        it += 1

    return X[len(X)-1]%prime

def mult_mod_p(num1,num2,p):
    final = 0
    vals = []
    curr = num1
    mult = 1
    while mult < num2:
        vals.append([mult,curr])
        curr = (curr+curr)%p
        mult = mult + mult

    vals.reverse()
    countdown = int(num2)
    pos = 0
    while countdown != 0:
        if vals[pos][0] <= countdown:
            countdown = countdown - vals[pos][0]
            final = (final + vals[pos][1])%p
        if vals[pos][0] > countdown:
            pos += 1
    return final

def pow_mod_p(num1,power,p):
    '''

        Implementation of the square and add algorithm.
        Takes a number and the power and finds the exp
        mod p.

    '''

    vals = []
    curr = num1
    exp = 1
    while exp < power:
        vals.append([exp,curr])
        curr = (curr*curr)%p
        exp = exp*2
    
    vals.reverse()
    countdown = int(power)
    pos = 0    
    final = 1

    while countdown != 0:
        if vals[pos][0] <= countdown:
            countdown = countdown - vals[pos][0]
            final = (final*vals[pos][1])%p

        if vals[pos][0] > countdown:
            pos += 1

    return final


def create_public_key(prime,generator,pub_path,sec_path):
    z = open(pub_path+'public_key.txt','a')
    z2= open(sec_path+'private_key.txt','a')

    secret_int = random.randint(2,prime-2)
    # (prime,gen,gen^sec)
    z.write(str(prime)+','+str(generator)+','+str(pow_mod_p(generator,secret_int,prime)))
    z2.write(str(secret_int))

    z.close()
    z2.close()
    return


def read_public_key(path):
    z = open(path)
    raw = z.read()

    z.close()
    cmmapos = 0
    final = []

    for a in range(len(raw)):
        if raw[a] == ',':
            final.append(long(raw[cmmapos:a]))
            cmmapos = a+1
    final.append(long(raw[cmmapos:len(raw)]))
    return final


def split_message(asciistr,prime):
    if type(asciistr) == long:
        asciistr = str(asciistr)    

    messages = []
    while len(asciistr) > prime:

        if asciistr[prime-1] != '0':
            messages.append(asciistr[0:prime-1])
            asciistr = asciistr[prime-1:len(asciistr)]
            continue

        if asciistr[prime - 2] != '0':
            messages.append(asciistr[0:prime-2])
            asciistr = asciistr[prime-2:len(asciistr)]
            continue

        if asciistr[prime - 3] != '0':
            messages.append(asciistr[0:prime-3])
            asciistr = asciistr[prime-3:len(asciistr)]
            continue
        
        if asciistr[prime - 4] != '0':
            messages.append(asciistr[0:prime-4])
            asciistr = asciistr[prime-4:len(asciistr)]
            continue

        if asciistr[prime - 5] != '0':
            messages.append(asciistr[0:prime-5])
            asciistr = asciistr[prime-5:len(asciistr)]
            continue

        if asciistr[prime - 6] != '0':
            messages.append(asciistr[0:prime-6])
            asciistr = asciistr[prime-6:len(asciistr)]
            continue

        messages.append(long(asciistr))
    return messages


def g_encrypt(message,(p,g,gx),y):
    m = message
    gy = pow_mod_p(g,y,p)
    gxy = pow_mod_p(gx,y,p)
    mgxy = mult_mod_p(m,gxy,p)
    return (gy,mgxy)


def g_decrypt((gy,mgxy),(p,g,gx),x):
    gxyinv = inverse(pow_mod_p(gy,x,p),p)%p
    message = mult_mod_p(mgxy,gxyinv,p)
    return message


def encrypt_write(em,path):
    fle = open(path+'encrypted'+str(os.times()[4]).replace('.','')+'.hcrypt','a')
    stng = str(em)
    stng = stng.replace(' ','' )

    for a in range(1,len(stng)-2):
        if stng[a] == ',' and stng[a-1] == ')':
            stng = stng[0:a]+'/'+stng[a+1:len(stng)-1]       
    stng = stng.replace('[','')
    stng = stng.replace(']','')
    stng = stng.replace('(','')
    stng = stng.replace(')','')    
    fle.write(stng)
    fle.close()
    return


def encrypt_read(full_path):
    fle = open(full_path)
    rawm= fle.read()
    fle.close()
    r2m = rawm.split('/')
    m = []
    for a in r2m:
        m.append(a.split(','))
    
    for a in range(len(m)):
        for b in range(len(m[a])):

            m[a][b] = long(m[a][b])
        m[a] = tuple(m[a])
    return m
    

#######################################

def ElGamal_encrypt(message,public_key='/home/hollis/dev/crypto/ElGamal/Bob/public_key.txt'):

    '''

        Takes a message and a public key(or public_key_path) 
        of format p,g,gx and encrypts the message.

    '''

    # find public key
    if type(public_key) == str:
        public_key = read_public_key(public_key)

    prime = public_key[0]

    if type(message) == str:
        message = string_to_ascii(message)

    print 'splitting message start'
    if message >= prime:
        messages = split_message(message,public_key[0])
    print 'splitting message end' 
    if message < prime:
        messages = [message]
    encrypt = []
    print "begin finding rand int"
    y = random.randint(2,prime-1)
    print "found rand int"
    for a in messages:
        encrypt.append(g_encrypt(a,public_key,y))

    return encrypt


def ElGamal_decrypt(encrypted,public_key_path='/home/hollis/dev/crypto/ElGamal/Bob/public_key.txt',private_key_path='/home/hollis/dev/crypto/ElGamal/Bob/private_key.txt'):
    '''
        Takes an encrypted message list (from ElGamal_encrypt)
        Decrypts and returns the original message.

    '''

    final = []
    fil = open(private_key_path)
    x = int(fil.read())
    fil.close
    public_key = read_public_key(public_key_path)
    prime = public_key[0]

    for a in encrypted:    
        final.append(ascii_to_string(g_decrypt(a,public_key,x)%prime))

    return final


def encrypt_file(filepath,public_key):
    fle = open(filepath)
    mssg = fle.read()
    fle.close
    slshpos = 0
    for a in range(len(filepath)):
        if filepath[len(filepath)-1-a] == '/':
            slshpos = len(filepath)-a
            break

    name = filepath[slshpos:len(filepath)]
    path = filepath[0:slshpos]

    if type(public_key) == str:
        public_key = read_public_key(public_key)

    em = ElGamal_encrypt(name,public_key)
    em = em + ElGamal_encrypt(mssg,public_key)

    encrypt_write(em,path)
    os.remove(filepath)
    return


def decrypt_file(filepath,publickey_path,privatekey_path):
    em = encrypt_read(filepath)
    message = ElGamal_decrypt(em,publickey_path,privatekey_path)
    name = message[0]
    mssg = ''

    for a in range(1,len(message)):
        mssg += message[a]
    
    pos = 0
    for a in range(len(filepath)):
        if filepath[len(filepath)-1-a] == '/':
            pos = len(filepath)-a
            break

    fle = open(filepath[0:pos]+name,'a')
    fle.write(mssg)
    fle.close()
    return

prme = 'FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF'
prme = prme.replace(' ','')
prme = int(prme,16)

gen = 2

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--decrypt",action="store_true",help="Decrypt a file." )
    parser.add_argument("-e","--encrypt",action="store_true",help="Encrypt a file.")
    parser.add_argument("-pblk","-pblk",action="store_true",help="Create a public and private key.")
    parser.add_argument('path',help="Path of target file.")
    args = parser.parse_args()
    filepath = args.path
    print filepath
    if args.e:
        print "Encrypting " + filepath
        print " "
        print "If using your public key press enter, else enter public key path."
        fl = raw_input("Public Key Path : ")
        encrypt_file(filepath,pblkl)
        print "Finished encrypting"
    if args.d:
        decrypt_file(filepath,pblkl,pvtkl)
        print "Finised decrypting"
