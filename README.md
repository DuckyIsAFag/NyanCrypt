# NyanCrypt
NyanCrypt - RSA Encryption program by DuckyIsAFag

Dependancies:
  Python 3+ (must be installed to path) and PIL module (pip install -m PIL)

Typical usage: {

  1.) Generate RSA key (which will ask for save as public_key and save as private_key for each)
  
  2.) Encyrpt file bytes using public key and save the newly encrypted file to the original
  
  3.) Decrypt file bytes using private key and save the newly encrypted file to the original
}

Issues:{

  1.) The current RSA key generation uses the default random.randrange(nx, ny) function; which produces a mersenne twister. This means that the RSA key generation is not totally cryptographically secure due to the "predictabilty" of the mersene twiseter function if an attacker is able to find the seed value and current index. (This issue will be resolved in the future, by an implementation of the blum blum shub algorithm which is more cryptographically secure as it is much less predictable due to the nature of its algorith)
  
  2.) Since the program will overwrite the current working file there is an optional backup directory button. The button should then set a backup directory in order to save an identical bytewise copy of the file you select when decrypting/encrypting in order to prevent data loss.
  
  3.) The program doesn't support key files which have been generated by other programs. If you want to create your own keys, then you must first create a tuple of (n, pk) where n is the product of p.q and pk is either e the relative prime of (p-1).(q-1) or the modular inverse of e where e is typically the private key.}
