RSA_Engine
==========

To implement RSA decryption and encryption that can use OpenSSL X509 certificates and can be used to encrypt and decrypt files that OpenSSL produced as well as producing files that OpenSSL can read back. Keep in mind that the final program you produce must be fully compatible with OpenSSL as that is what we will be using to test your program. To accomplish this you must implement the ability to fully parse OpenSSL X509 certificates as well as RSA encryption and decryption and then implement your own methods to reproduce the aforementioned functionality. A good idea would be to model your program commands along the same lines as OpenSSL so it is easy to use and more accessible. Look at the links provided below for more explanation. 

unzip the tar ball. 
> cd RSA_Engine
> make
-----------------
There should be two executable named rsa and genrsa. 
just type ./rsa or ./genrsa to see the usage. 