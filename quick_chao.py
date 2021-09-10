from collections import deque
from string import ascii_lowercase as alphabet

from Chaocipher.chaocipher import RotorState, encode_string


def standard_rotor(add_chars=[]):
    alphlist = deque(letter for letter in alphabet)
    alphlist.extend(add_chars)
    return RotorState(0, alphlist.copy(), None, alphlist.copy(), None)


def quick_encode(key: str, string: str, add_chars = []):
    """
    Uses a provided key to permute a standard rotor before encoding a string
    :param key:
    :param string:
    :param add_chars:
    :return:
    """
    A = standard_rotor(add_chars)
    encode_string(key, A)
    A.text_index=0
    return encode_string(string, A)


def quick_decode(key: str, string:str, add_chars = []):
    """
    Uses a provided key to permute a standard rotor before decoding a string
    :param key:
    :param string:
    :param add_chars:
    :return:
    """
    A = standard_rotor(add_chars)
    encode_string(key, A)
    A.text_index = 0
    return encode_string(string, A, True)


def main():
    # key, secret = "this was a triumph", "im making a note here huge success"
    # encoded_secret = quick_encode(key, secret)
    # print(key, encoded_secret)
    #
    # decoded_secret = quick_decode(key, encoded_secret)
    # print(key, decoded_secret)

    A = standard_rotor()
    encoded_str = encode_string("ckqdi", A)
    print(encoded_str, A.plain_rotor, A.cipher_rotor)

if __name__ == '__main__':
    main()