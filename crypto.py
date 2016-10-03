#!/usr/bin/env python

import os, random, argparse

# Change to private key location
pvtkl = '/home/hollis/Documents/private_key.hpvtkey'
pblkl = '/home/hollis/dev/crypto/public_key.hpubkey'
#############################

def string_to_ascii(message):
    ''' 
        This takes a string (message) and converts it into an 
        integer.

    '''
    int_mssg = '333'
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
    message = message[3:len(message)]

    for a in range(len(message)/3):
        chars.append(message[3*a:3*a+3])       

    for a in chars:
        if a.isalnum and int(a) < 256 :
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
    '''
        Similar to the binary power algorithm,
        but with multiplication. This is much
        better in handling large numbers.
    '''

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
    '''
        Given a prime, generator, public key
        path, and private key path. This 
        generates a public key file and private
        key file at the specified location.
    '''
    z = open(pub_path+'public_key.hpubkey','a')
    z2= open(sec_path+'private_key.hpvtkey','a')

    secret_int = random.randint(2,prime-2)
    # (prime,gen,gen^sec)
    z.write(str(prime)+','+str(generator)+','+str(pow_mod_p(generator,secret_int,prime)))
    z2.write(str(secret_int))

    z.close()
    z2.close()
    return


def read_public_key(path):
    '''
        Reads a .hpubkey file to work with this 
        script. Only one input, the path of the
        file.
    '''

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

def read_private_key(path):
    '''
        Reads a .hpvtkey. Only needs the location
        of the file.
    '''
    z = open(path)
    sec = long(z.read())
    z.close()
    return sec


def split_message(asciistr,prime):
    '''
        Splits a large message into smaller
        messages which can be used.
    '''

    pdig = len(str(prime))-1

    if type(asciistr) == int or type(asciistr) == long:
        asciistr = str(asciistr)
    
    if (pdig-7)%3 == 0:
        sp = pdig-7

    if (pdig-6)%3 == 0:
        sp = pdig-6

    if (pdig-5)%3 == 0:
        sp = pdig-5

    messages = []

    while len(asciistr) > sp:
        messages.append(long('333' + asciistr[0:sp]))
        asciistr = asciistr[sp:len(asciistr)]

    if len(asciistr) > 0:
        messages.append(long('333'+asciistr))

    return messages
    
        

def g_encrypt(message,(p,g,gx),y):
    '''
        The simplest form of the El Gamal
        encryption protocal. 

        Takes a message (smaller than p-1), 
        public key (prime,generator,generator^pvtkey),
        where pvtkey is the private key of the owner 
        of the public key.

        y is your own secret integer. If you also have
        a private key, this can be your y.
    '''
    m = message
    gy = pow_mod_p(g,y,p)
    gxy = pow_mod_p(gx,y,p)
    mgxy = mult_mod_p(m,gxy,p)
    return (gy,mgxy)


def g_decrypt((gy,mgxy),(p,g,gx),x):
    '''
        The simplest form of the El Gamal
        decryption protocal.

        Takes an encrypted message with the format,
        (generator to the senders secret int, message
        times the generator to both secret ints.)

        The next input is your public key that was used
        in encrypting the message.

        The last input is your secret int.
    '''
    gxyinv = inverse(pow_mod_p(gy,x,p),p)%p
    message = mult_mod_p(mgxy,gxyinv,p)
    return message


def encrypt_write(em,path):
    '''
        Takes an encrypted message and the location
        where you want to put the file, and creates 
        a file with the message.
    '''

    fle = open(path+'encrypted'+str(os.times()[4]).replace('.','')+'.hcrypt','a')
    stng = str(em)
    stng = stng.replace(' ','' )

    for a in range(1,len(stng)-2):
        if stng[a] == ',' and stng[a-1] == ')':
            stng = stng[0:a]+'/'+stng[a+1:len(stng)]       
    stng = stng.replace('[','')
    stng = stng.replace(']','')
    stng = stng.replace('(','')
    stng = stng.replace(')','')    
    fle.write(stng)
    fle.close()
    return


def encrypt_read(full_path):
    '''
        Reads a .hcrypt file. This takes
        a path and returns the encrypted message(s).
    '''

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

def ElGamal_encrypt(message,public_key=pblkl,secret_int = -1):

    '''

        Takes a message(string or int), a public key
        (or public_key_path) of format p,g,gx, and 
        (optional: if you have a secret int) and 
        encrypts the message.

    '''

    # find public key
    if type(public_key) == str:
        public_key = read_public_key(public_key)

    prime = public_key[0]

    if type(message) == str:
        message = string_to_ascii(message)


    if message >= prime:
        messages = split_message(message,public_key[0])

    if message < prime:
        messages = [message]
    encrypt = []
    
    if secret_int == -1:
        y = random.randint(2,prime-1)
    if secret_int != -1:
        y = secret_int

    for a in messages:
        encrypt.append(g_encrypt(a,public_key,y))

    return encrypt


def ElGamal_decrypt(encrypted,public_key_path=pblkl,private_key_path=pvtkl):
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


def encrypt_file(filepath,public_key,sec_int=-1):

    '''
        Takes a file location and public key and encrypts
        the file.
    '''

    if type(sec_int) == str:
        sec_int = read_private_key(sec_int)


    fle = open(filepath)
    mssg = fle.read()
    fle.close()
    slshpos = 0
    for a in range(len(filepath)):
        if filepath[len(filepath)-1-a] == '/':
            slshpos = len(filepath)-a
            break

    name = filepath[slshpos:len(filepath)]
    path = filepath[0:slshpos]

    if type(public_key) == str:
        public_key = read_public_key(public_key)

    em = ElGamal_encrypt(name,public_key,sec_int)
    em = em + ElGamal_encrypt(mssg,public_key,sec_int)

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
    os.remove(filepath)
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
    if args.encrypt:
        print ''
        print "Encrypting: " + filepath
        print " "
        print "If using your public key press enter, else enter public key path."
        fl = raw_input("Public Key Path : ")
        print ' '
        print 'encrypting ...'
        encrypt_file(filepath,pblkl)
        print ' '
        print "Finished encrypting"
    if args.decrypt:
        print " "
        print "decrypting: ", filepath 
        decrypt_file(filepath,pblkl,pvtkl)
        print "Finised decrypting"

