# CRYPTR
CRYPTR: Secure File Sharing over the World Wide Web

The crypt program will support the following functions:
1. Generating a secret key
2. Encrypting a file using a secret key
3. Decrypting a file using a secret key
4. Encrypting a secret key using a public key
5. Decrypting a secret key using a private key

(1) I would generate a secret key to encrypt my file and upload it. 
(2) I can then download my friend’s public key and use it to encrypt the secret key. 
(3) I would then upload the encrypted secret key. 
(4) My friend can then download the encrypted file and encrypted key. 
(5) Using their private key, my friend can decrypt the secret key which then is used to decrypt the 
    encrypted file. Sharing my file with additional friends would involve steps 2 to 5.

First, since secret keys for block ciphers are smaller than public/private keys (128-bit for AES), I can be
sure I can securely encrypt my secret and use this approach to share the secret key in the future. Second,
since I only have to encrypt a small key every time I want to share my file with a friend, this is efficient
in terms of encryption computation and time it takes to upload. Finally, since my original file is stored on
the internet service and I’m securely sharing a secret key that can be used by anyone, I would not have to
perform any unnecessary re-encryption and re-uploading of the original file data.

To sum up, this approach allows us to do the following:

1. Enables us to share a file of an arbitrary size. Since we’re using a block cipher, we can encrypt a file of any size.
2. Enables secure transmission of both file and symmetric key. Even if the online storage or email server is compromised, no 
   one will be able to decrypt the file without the symmetric key. Although the symmetric key is also stored by some service, 
   no one can decrypt the symmetric key without the receivers private key.
3. Enables security with any internet storage provider. Due to the chain of security supported at the root by public-key
   cryptography, we can put our encrypted files and encrypted symmetric key anywhere, even on a public forum.
4. Enables efficient resource utilization. Due to the use of both public key and symmetric key encryption, we only need to 
   upload our encrypted file once followed by re-encrypting and re-uploading small secret keys.
5. Enables asynchronous distribution. Whenever I to give someone access to my file, they can download my file at any time and 
   also download the symmetric key at any time. In order to give someone access, I just have to encrypt the symmetric key and 
   share it via dropbox, google drive, email, etc.

Implementation
Provided should be a program template called Cryptr.java. This template already has a main runner
implemented. The program takes in multiple arguments depending on which function wants to carried
out. The usage is as follows:

    Cryptr generatekey <key output file>
    Cryptr encryptfile <file to encrypt> <secret key file> <encrypted output file>
    Cryptr decryptfile <file to decrypt> <secret key file> <decrypted output file>
    Cryptr encryptkey <key to encrypt> <public key to encrypt with> <encrypted key file>
    Cryptr decryptkey <key to decrypt> <private key to decrypt with> <decrypted key file>
    
   
Example Run and Testing

Compiling the Cryptr program
    
    Command Line 
        $ javac Cryptr.java
        
Generating a file to encrypt
    We’ll want to create a sample file to encrypt. We’ll just create a simple text file foo.txt that says "This is a text file 
    I want to share".

    Command Line
        $ echo "This is a text file I want to share" > foo.txt
        
Generating a key
    In order to encrypt our file, we will need a secret key stored within a file so that we can encrypt files, This secret key 
    file will not only be used to encrypt a file but the file itself will be encrypted itself to securely share the secret key 
    with whoever we want to be able to decrypt our file. We’ll generate a secret key and store it in the file secret.key.

    Command Line
        $ java Cryptr generatekey secret.key
        Generating secret key and writing it to secret.key
        
Encrypting File
    Now before we can share our file we have to encrypt it using the secret key. We’ll encrypt our file foo.txt with the 
    secret key file we generated secret.key and have the encrypted output be put into a file called foo.enc.

    Command Line
        $ java Cryptr encryptfile foo.txt secret.key foo.enc
        Encrypting foo.txt with key secret.key to foo.enc

Generating Key Pair
    We need to generate a sample RSA key pair to represent the public and private keys of our friend. These need to be 
    converted into the .der format to be used with our Java program. We’ll name the private key private_key.der and the 
    public key public_key.der.

    Command Line
        $ openssl genrsa -out private_key.pem 2048
        $ openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem \-out private_key.der -nocrypt
        $ openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
        
Encrypting the Secret Key
    Now that we have a sample key pair, let’s encrypt the secret key file secret.key with the public key public_key.der and 
    output it to a file called s.enckey.

    Command Line
        $ java Cryptr encryptkey secret.key public_key.der s.enckey
        Encrypting key file secrey.key with public key file public_key.der to s.enckey
    
Decrypting Key and File
    Finally in order to decrypt the file, we should be able to decrypt the encrypted secret key and then use that key to 
    decrypt the encrypted file. First we’ll decrypt the encrypted secret key file s.enkey with the private key private_key.der 
    and put it in a file called recovered−secret.key. Then we’ll decrypt the encrypted file foo.enc with the recovered secret 
    key recovered−secret.key and put it in a file called recovered−foo.txt.

    Command Line
        $ java Cryptr decryptkey s.enckey private_key.der recovered-secret.key
        Decrypting key file s.enckey with private key file private_key.der to recovered-secret.key
        $ java Cryptr decryptfile foo.enc recovered-secret.key recovered-foo.txt
        Decrypting foo.enc with key recovered-secret.key to recovered-foo.txt

Printing out the recovered text file using the cat command should show us the contents of our original
file.

    Command Line
        $ cat recovered-foo.txt
        This is a text file I want to share
