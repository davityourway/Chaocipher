#Chaocipher
An implementation of John F. Byrne's cryptographic cipher in Python, with a Depth First Search to crack it (pretty quickly).
Created by Joshua Davitz and Jacob Bumgardner

##The Chaocipher

The Chaocipher is a century old cryptographic system whose mechanism was revealed to the public about ten years ago. For
 more details about its operation, see Carl Scheffler's excellent explanation here: 
 http://www.inference.org.uk/cs482/projects/chaocipher/index.html

Our implementation of the cipher takes in a text string, for either encryption or decryption, and a Rotor State. Every 
encryption of a decryption of a character in the Chaocipher permutes the plain and cipher rotors, so the relative ordering 
of the rotors in the Chaocipher is very important. We represent the Rotors of the Chaocipher as a RotorState object 
that has two Deques, a plain and cipher for each respective rotor, with the 0 position at the Zenith. The RotorState also
carries an index of its position in the string which points to the index it will encrypt _next_. The RotorState also has
a set of used characters for plain and cipher text which is used in the search.

In order to perform an Encryption or Decryption, first initialize a RotorState object with your chosen Rotors, alphset for
the plain and cipher set (which is simply a set of the strings in the alphabet), and the text index where you are starting 
your operation. If you are enciphering a new string, that will be the 0th position. If you are decrypting from the end of
the string, that will simply be the len(string).

Next, run encode_string or decode_string for your respective operation. This will return the output string that corresponds
to the operation. It will also traverse the rotor to the end position of that operation. So encoding will bring it to the end 
of the string, and decoding will return it to the 0th position. As of now decode and encode will attempt to bring the rotor
to end of their respective strings, and incomplete strings will cause an out of range error.