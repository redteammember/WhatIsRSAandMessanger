# What is RSA?
Rivest– Shamir–Adleman’s cryptosystem, which appeared in 1977, revolutionized cryptography by becoming the first public key encryption algorithm. In classical symmetric key encryption schemes, the same secret key is used for encryption and decryption. But the public key algorithm, also known as asymmetric encryption, uses 2 keys: public - with its help, anyone who wants to write you a message will encrypt it; and the private key. which is necessary to decrypt messages encrypted with a public key.
RSA is a real breakthrough in the field of encryption and has been an example and workhorse of Internet security for 40 years. 
RSA is primarily an arithmetic trick. The work is based on a mathematical object called trapdoor permutation, which is a function that converts the number x to the number y in the same range, so it is easy to calculate y by x knowing the public key, but it is almost impossible to calculate x by y if you do not know the private secret key the entrance. (You can assume that x is plaintext and y is ciphertext.)


