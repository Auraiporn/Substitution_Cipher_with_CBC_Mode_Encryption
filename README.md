# Substitution_Cipher_with_CBC_Mode_Encryption

Description:

Write a function that accepts a stream of ASCII characters and encrypts this input
using a substitution cipher with the Cipher Block Chaining mode. The block size
should be 8 bytes. The program should take plaintext from the standard input and
print the ciphertext on the standard output. For this problem, you are allowed to select
any reasonable system to determine that the end of the input is reached, and/or when
padding should be applied to complete the block. You may select any output format,
as long as it is unambiguous. The program should receive two parameters:

1. A pointer to the initializing vector; and
2. A number, k, representing the substitution cipher shift, such that each ASCII character would be encrypted by the kth character ahead of it in the alphabet.

For example, if x = 3, then A is encoded by D, B is encoded by E etc. Make reasonable assumptions with respect to reaching the last character in the ASCII set.
Make sure to document clearly in your code any assumptions you make about the
input and encryption algorithm