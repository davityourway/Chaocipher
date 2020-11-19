# Chaocipher
An implementation of John F. Byrne's cryptographic cipher in Python, with a backtracking algorithm to crack it (pretty quickly).
Created by Joshua Davitz and Jacob Bumgardner

## The Chaocipher

The Chaocipher is a century old cryptographic system whose mechanism was revealed to the public about ten years ago. For
 more details about its operation, see [Carl Scheffler's excellent explanation](http://www.inference.org.uk/cs482/projects/chaocipher/index.html)
 
 
Our implementation of the cipher takes in a text string, for either encryption or decryption, and a Rotor State. Every 
encryption of a decryption of a character in the Chaocipher permutes the plain and cipher rotors, so the relative ordering 
of the rotors in the Chaocipher is very important. We represent the Rotors of the Chaocipher as a RotorState object 
that has two Deques, a plain and cipher for each respective rotor, with the 0 position at the Zenith. The RotorState also
carries an index of its position in the string which points to the index it will encrypt _next_. The RotorState also has
a set of used characters for plain and cipher text which is used in the search.

In order to perform an Encryption or Decryption, first initialize a `RotorState` object with your chosen Rotors, `None` for
the plain and cipher set (which are only used for cracking), and the text index where you are starting 
your operation. If you are enccrypting a new string, that will be the 0th position. If you are decrypting from the end of
the string, that will simply be the len(string). 

Here is an example with both rotors initialized as simply the alphabet:

`
A = chaocipher.RotorState(0, alphlist.copy(), None, alphlist.copy(), None)`


Next, run `encode_string` or `decode_string` for your chosen operation. This will return the output string that corresponds
to the operation. It will also traverse the rotor to the end position of that operation. So encoding will bring it to the end 
of the string, and decoding will return it to the 0th position. As of now decode and encode will attempt to bring the rotor
to end of their respective strings, and incomplete strings will cause an out of range error. Ignore the `is_crypt` variable 
for simple encoding and decoding. 

As of right now these operations only work with strings that contain continuous lower case variables. We will be adding 
handling shortly.

## The Cracker

Here is the fun part. 

It's quite simple. All you need to do is input a plaintext string, a cipher string, and a starting position into
the `crack` function. This will return either A) a viable rotor configuration or B) `None` if there is no discoverable
rotor state. 

`test_rotor = chaocipher.crack(plaintext, ciphertext, 42)`


We have included a function, `find_starting_position` which selects an optimal position in the text to begin the dfs.
Simply input the two strings, and a "window size", and it will return the area with the fewest characters in that given
window size in both the plain and encrypted text. This will maximize the amount of information present at the 
beginning of the search and lead to MUCH faster results. You can simply call it inside the `crack` call for ease.

`test_rotor = chaocipher.crack(plaintext, ciphertext, find_starting_position(plaintext, ciphertext, 6))`

As of right now the cracker will only function on strings where both the plain and encrypted text are present. If you want
to use it to decrypt some unknown characters(like in Exhibit 1), simply traverse the rotor to the index just before the unknown
characters begin. Then, use encode or decode string on the string that you possess, this time making sure that you set
the flag indicating what type of string you are using.


