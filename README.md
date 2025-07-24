# RSA Encryption and Decryption on Server and Client

**Name:** Shounak Santosh Dighe

---

## Aim

This project shall seek to develop a secure client-server application in an attempt to execute RSA encryption and decryption. The aim shall be to provide evidence for the steps involved in performing secured information sending between the client and the server using RSA public-key cryptography.

---

## Objectives

* **Understand RSA Encryption**: Learn the principles of RSA encryption and decryption, including key generation, encryption, and decryption processes.
* **Implement RSA Algorithm**: Develop a client-server application where the server uses RSA to decrypt messages and the client uses RSA to encrypt messages.
* **Ensure Secure Communication**: Establish a secure communication channel between the client and server to demonstrate secure message transmission and reception.
* **Validate Implementation**: Test the client-server interaction to ensure that the encryption and decryption processes work as intended.

---

## Theory

RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem, one of the oldest still widely used for secure data transmission. In a public-key cryptosystem the encryption key is public and differs from the decryption key, which is kept secret, or private.



### The RSA Algorithm

**1. Key Generation**
* Selection of two large primes: p and q.
* Computation of their product: n = p × q.
* Calculate the totient: ϕ(n)=(p−1)×(q−1).
* Choose an encryption exponent e: 1 < e < ϕ(n), with gcd(e,ϕ(n))=1.
* Compute the decryption exponent d: d×e≡1 (mod ϕ(n)).

**2. Encryption**
To encrypt a message m, the sender uses the recipient's public key (e,n). The ciphertext c is computed as: `c = m^e (mod n)`

**3. Decryption**
The recipient decrypts the ciphertext c using his private key (d, n). The recovered original message m is computed by: `m = c^d (mod n)`

---

## Conclusion

The RSA client-server application is perfectly suited to showing how RSA encryption and decryption can be used for secure communication. The server decrypts messages with their private key, and the client encrypts messages with the server's public key. That way, one can keep the confidentiality and integrity of data transmitted over a network by implementing RSA.

---

## References

1.  Rivest, R., Shamir, A., & Adleman, L. (1978). A Method for Obtaining Digital Signatures and Public-Key Cryptosystems. Communications of the ACM, 21(2), 120-126.
2.  Stallings, W. (2017). Cryptography and Network Security: Principles and Practice. Pearson.
3.  Knuth, D. E. (1998). The Art of Computer Programming, Volume 2: Seminumerical Algorithms. Addison-Wesley.
4.  Python Documentation: https://docs.python.org/3/
5.  Python socket Module Documentation: https://docs.python.org/3/library/socket.html
