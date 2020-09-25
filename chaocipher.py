from typing import List, Tuple, Optional, Deque, Set
from collections import deque
from string import ascii_lowercase as alphabet
alphset = set(alphabet)


class RotorState:
    def __init__(self, text_index: int, cipher: Optional[Deque[str]] = None, cipher_set: Optional[Set[str]] = None,
                 plaintext: Optional[Deque[str]] = None, plain_set: Optional[Set[str]] = None):
        """
        A representation of the plaintext rotor and cipher rotor for a given point in an encryption, decryption, or cracking process
        :param text_index: index in plaintext string that will be encoded next
        :param cipher: deque representation of cipher rotor
        :param cipher_set: set of characters used on the cipher rotor
        :param plaintext: deque representation of plaintext rotor
        :param plain_set: set of characters used on the plaintext rotor
        """
        self.cipher_rotor: deque[str] = cipher if cipher else deque("#" for _ in range(26))
        self.cipher_set = cipher_set if cipher_set else set()
        self.plain_rotor: deque[str] = plaintext if plaintext else deque("#" for _ in range(26))
        self.plain_set = plain_set if plain_set else set()
        self.text_index = text_index

    def initialize(self, plaintext, cryptext, start_index):
        """
        Initializes the Rotor State at 1 step after some start position
        :param plaintext: plaintext string
        :param cryptext: encrypted string
        :param start_index:
        :return:
        """
        self.cipher_rotor[0] = cryptext[start_index]
        self.cipher_set.add(cryptext[start_index])
        self.plain_rotor[-1] = plaintext[start_index]
        self.plain_set.add(plaintext[start_index])
        self.text_index += 1

class SearchRange:
    def __init__(self, start, end):
        """
        The search range for the depth first search function
        :param start: the index of the earliest (leftmost) character currently in our rotor set
        :param end: index - 1 is the last rightward character currently in our rotor set
        """
        self.start = start
        self.end = end

    def copy(self):
        return SearchRange(self.start, self.end)


def deque_insert(input_deque: Deque, index: int, value: any) -> None:
    """
    Inserts into a deque via rotating the insertion position to 0. Likely totally unnecessary
    """
    input_deque.rotate(-index)
    input_deque.appendleft(value)
    input_deque.rotate(index)


def deque_pop(input_deque: Deque, index: Optional[int] = 0) -> any:
    """
    Pops from a given index in the deque.
    """
    input_deque.rotate(-index)
    value = input_deque.popleft()
    input_deque.rotate(index)
    return value


def encode_char(string: str, rotor: RotorState, is_crypt: bool = False) -> None:
    """
    Permutes the rotor in the right (encryption) direction. For standard encryption it uses the plaintext string to do so.
    In the search function it can use the encrypted text, which enables it to place the rotor in the correct position to be
    filled in. This also allows it to permute across "?" as per the first exhibit.
    :param string: string being used for motion
    :param rotor: Rotor State to get there
    :param is_crypt: flag for whether or not the text string used for the traversal is plain or crypt text
    :return:
    """
    indexing_rotor = rotor.cipher_rotor if is_crypt else rotor.plain_rotor
    ring_index: int = indexing_rotor.index(string[rotor.text_index])
    rotor.cipher_rotor.rotate(-ring_index)
    rotor.plain_rotor.rotate(-ring_index)
    rotor.plain_rotor.rotate(-1)
    deque_insert(rotor.plain_rotor, 13, deque_pop(rotor.plain_rotor, 2))
    deque_insert(rotor.cipher_rotor, 13, deque_pop(rotor.cipher_rotor, 1))
    rotor.text_index += 1


def decode_char(string: str, rotor: RotorState, is_crypt: bool = False) -> None:
    """
    Permutes the rotor in left, or decryption direction. Can use either string. Parameters same as above
    :param string:
    :param rotor:
    :param is_crypt:
    :return:
    """
    indexing_rotor = rotor.cipher_rotor if is_crypt else rotor.plain_rotor
    ring_index: int = indexing_rotor.index(string[rotor.text_index - 1])
    rotation_offset = 0 if is_crypt else 1
    rotor.cipher_rotor.rotate(-(ring_index + rotation_offset))
    rotor.plain_rotor.rotate(-(ring_index + rotation_offset))
    deque_insert(rotor.cipher_rotor, 1, deque_pop(rotor.cipher_rotor, 13))
    rotor.plain_rotor.rotate(1)
    deque_insert(rotor.plain_rotor, 3, deque_pop(rotor.plain_rotor, 14))
    rotor.text_index -= 1


def encode_string(string: str, rotor: RotorState, is_crypt: bool = False) -> str:
    """
    Encodes a plaintext string given a rotor state.
    :param string:
    :param rotor:
    :param is_crypt:
    :return:
    """
    output_list = list()
    for i in range(len(string)):
        encode_char(string, rotor, is_crypt)
        output_list.append(rotor.plain_rotor[-1] if is_crypt else rotor.cipher_rotor[0])
    output_string = "".join(output_list)
    return output_string


def decode_string(string: str, rotor: RotorState, is_crypt: bool = True) -> str:
    """
    Decodes an encrypted string or outputs ciphertext in reverse
    :param string:
    :param rotor:
    :param is_crypt:
    :return:
    """
    output_list = list()
    while rotor.text_index > 0:
        decode_char(string, rotor, is_crypt)
        output_list.append(rotor.plain_rotor[0] if is_crypt else rotor.cipher_rotor[0])
    output_string = "".join(output_list)
    return output_string[::-1]


def traverse_to(string: str, target_index: int, rotor: RotorState, is_crypt: bool = False) -> None:
    """
    Brings the rotor to a target position in the enciphering process. Used primarily when executing the dfs and filling
    in values
    :param string:
    :param target_index:
    :param rotor:
    :param is_crypt:
    :return:
    """
    decrease = True if rotor.text_index > target_index else False
    while rotor.text_index != target_index:
        if decrease:
            decode_char(string, rotor, is_crypt)
        else:
            encode_char(string, rotor, is_crypt)


def crack(plaintext: str, cryptext: str, start_index: int) -> Optional[RotorState]:
    rotor = RotorState(start_index)
    rotor.initialize(plaintext, cryptext, start_index)
    return dfs(plaintext, cryptext, rotor, SearchRange(start_index, start_index+1), 0)


def dfs(plaintext: str, cryptext: str, rotor_state: RotorState, search_range: SearchRange, stack_depth: int) -> Optional[RotorState]:
    while check_function(plaintext, cryptext, rotor_state, search_range):
       # print(f"The search range is {search_range.end - search_range.start} wide and the stack is  {stack_depth} tall")
        if not fill_in(plaintext, cryptext, rotor_state, search_range):
            return None
    if rotor_state.plain_set == alphset and rotor_state.cipher_set == alphset:
        return rotor_state
    if search_range.end == len(plaintext) and search_range.start == 0:
        return rotor_state
    traverse_position = decide_direction(plaintext, cryptext, rotor_state, search_range)
    search_position = traverse_position - 1 if traverse_position == search_range.start else traverse_position
    traverse_to(plaintext, traverse_position, rotor_state)
    for positions in find_open_positions(rotor_state, traverse_position == search_range.start):
        new_rotor = RotorState(rotor_state.text_index, rotor_state.cipher_rotor.copy(), rotor_state.cipher_set.copy(),
                               rotor_state.plain_rotor.copy(), rotor_state.plain_set.copy())
        new_rotor.cipher_rotor[positions[0]], new_rotor.plain_rotor[positions[1]] = cryptext[search_position], \
                                                                            plaintext[search_position]
        new_rotor.cipher_set.add(cryptext[search_position])
        new_rotor.plain_set.add(plaintext[search_position])
        new_search_range = search_range.copy()
        completed = dfs(plaintext, cryptext, new_rotor, new_search_range, stack_depth + 1)
        if completed:
            return completed
    return rotor_state if rotor_state.plain_set == alphset and rotor_state.cipher_set == alphset else None


def decide_direction(plaintext: str, cryptext: str, rotor: RotorState, search_range: SearchRange) -> int:
    forward = 1
    backwards = -1
    if search_range.start == 0:
        return search_range.end
    if search_range.end == len(plaintext):
        return search_range.start
    while (plaintext[search_range.end+forward] not in rotor.plain_set or cryptext[search_range.end+forward] not in \
            rotor.cipher_rotor) and forward + search_range.end < len(plaintext):
        forward += 1
        if forward + search_range.end < len(plaintext):
            return search_range.start
    while (plaintext[search_range.start + backwards] not in rotor.plain_set or cryptext[
        search_range.start + backwards] not in rotor.cipher_rotor) and search_range.start + backwards > 0:
        backwards -= 1
        if search_range.start + backwards > 0:
            return search_range.end
    return search_range.end if forward <= abs(backwards) else search_range.start


def find_open_positions(rotor: RotorState, backwards: bool = False) -> List[Tuple[int, int]]:
    rotation_offset = -1 if backwards else 0
    return [(i, i+rotation_offset) for i in range(26) if rotor.plain_rotor[i+rotation_offset] == "#" and rotor.cipher_rotor[i] == "#"]


def check_function(plaintext: str, cryptext: str, rotor_state: RotorState, search_range: SearchRange) -> bool:
    if search_range.end != len(plaintext):
        if plaintext[search_range.end] in rotor_state.plain_set:
            return True
        if cryptext[search_range.end] in rotor_state.cipher_set:
            return True
    if search_range.start != 0:
        if plaintext[search_range.start - 1] in rotor_state.plain_set:
            return True
        if cryptext[search_range.start - 1] in rotor_state.cipher_set:
            return True
    return False


def valid_mutation(rotor_deque: Deque, rotor_set: Set, fill_char: str, modify_type: str, direction : str) -> bool:
    fill_position = -1 if modify_type == "plain" and direction == "forward" else 0
    return (rotor_deque[fill_position] in ("#", fill_char)) and (rotor_deque[fill_position] == fill_char or fill_char not in rotor_set)


def fill_character(plaintext: str, cryptext: str, rotor_state: RotorState, search_range: SearchRange, direction: str, modify_type: str):
    search_index = search_range.end if direction == "forward" else search_range.start
    index_mod = 0 if direction == "forward" else -1
    fill_position = -1 if (modify_type == "plain" and direction == "forward") else 0
    modify_rotor = rotor_state.plain_rotor if modify_type == "plain" else rotor_state.cipher_rotor
    modify_text = plaintext if modify_type == "plain" else cryptext
    modify_set = rotor_state.plain_set if modify_type == "plain" else rotor_state.cipher_set
    modify_rotor[fill_position] = modify_text[search_index + index_mod]
    modify_set.add(modify_text[search_index + index_mod])
    if direction == "forward":
        search_range.end += 1
    else:
        search_range.start -= 1


def fill_in(plaintext: str, cryptext: str, rotor_state: RotorState, search_range: SearchRange):
    if search_range.end != len(plaintext) and plaintext[search_range.end] in rotor_state.plain_set:
        traverse_to(plaintext, search_range.end+1, rotor_state, False)
        if not valid_mutation(rotor_state.cipher_rotor, rotor_state.cipher_set, cryptext[search_range.end], "cipher", "forward"):
            return None
        fill_character(plaintext, cryptext, rotor_state, search_range, "forward", "cipher")
    elif search_range.end != len(plaintext) and cryptext[search_range.end] in rotor_state.cipher_set:
        traverse_to(cryptext, search_range.end+1, rotor_state, True)
        if not valid_mutation(rotor_state.plain_rotor, rotor_state.plain_set, plaintext[search_range.end], "plain", "forward"):
            return None
        fill_character(plaintext, cryptext, rotor_state, search_range, "forward", "plain")
    elif search_range.start > 0 and plaintext[search_range.start - 1] in rotor_state.plain_set:
        traverse_to(plaintext, search_range.start-1, rotor_state, False)
        if not valid_mutation(rotor_state.cipher_rotor, rotor_state.cipher_set, cryptext[search_range.start-1], "cipher", "back"):
            return None
        fill_character(plaintext, cryptext, rotor_state, search_range, "back", "cipher")
    elif search_range.start > 0 and cryptext[search_range.start - 1] in rotor_state.cipher_set:
        traverse_to(cryptext, search_range.start-1, rotor_state, True)
        if not valid_mutation(rotor_state.plain_rotor, rotor_state.plain_set, plaintext[search_range.start-1], "plain", "back"):
            return None
        fill_character(plaintext, cryptext, rotor_state, search_range, "back", "plain")
    return True


def find_starting_position(plaintext: str, cryptext: str, window_size: int):
    best_start_index = 0
    best_start_set_size = 52
    plaintext_list = [character for character in plaintext]
    cryptext_list = [character for character in cryptext]
    for i in range(len(plaintext)-window_size):
        plaintext_set = set(plaintext_list[i:i+window_size])
        cryptext_set = set(cryptext_list[i:i+window_size])
        new_set_size = len(plaintext_set) + len(cryptext_set)
        if new_set_size < best_start_set_size:
            best_start_index = i + window_size//2
            best_start_set_size = new_set_size
    return best_start_index

def main():
    pass

    #
    #
    # alphlist = deque(letter for letter in alphabet)
    # A = RotorState(0, alphlist.copy(), None, alphlist.copy(), None)
    # Exhibit 1
    #
    # plain = 'ALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYWALLGOODQQUICKBROWNFOXESJUMPOVERLAZYDOGTOSAVETHEIRPARTYW'
    # plain = plain.lower()
    # cipher = "CLYTZPNZKLDDQGFBOOTYSNEPUAGKIUNKNCRINRCVKJNHTOAFQPDPNCVLTVFICOTSSLWYYIHBICFUTHXNUVKGIMVEZYWSTHEPIEWXNNGFTOGHSRTBZXTMVGLTJXCSQXLNJTENCSVLCWRTBENZLSUVYIDAXLAFATQSRNZOPHKYGQJTOGYSDBNVDJOWHKECRMLYWIQIFIKSCYJGCVXNSKYHRYVYEDSZRIFFZAQNHSOMJPORWTJOIJIPKVHZGPWQKRXDMAUEFFXIACFLCZMAFZSJEOZIFKJCFMETESYYHZUVLFFURRHRIIFFDZMTTOVKLZOVLPVPPGVGEWWEFRFYHKXOPKXRQSZKLCZKHZWXRJXLMVFGGFGYIFDAEINIWPOMOUVRFBUZLAGDBCUAMFQLACRWWTUGSMPPZBRFASROYIRCAGVEYNSRTOQTDLFJRUTKFKASGVLVYYFVRAIYNIVJKIUWPFZBVRUEOTEJGLCGYSSNHHQTIQWUKQASXKGSPWHRYMTQSOQBAMAPFQRLIIUGTIVBEBYXFBIUSEYHMLKGOECSWUHTBIZZHLBNDIWTQAMAZBMYMBEKCYKCABLYQYMELPJOWNRVFZVKREBVUJEQIAEMOHTGFHFFIDIQQJUAWDHLUYREUGSKTIMDWRRNONJKDPTCJDCJNBVEOUTWXOFGRXNDKITNLOXSLZWQRDERERHLXWAMYLRVPRJFHRASDJWWOIWEVAVMRRNLRJMIFDHHADDQCBZWYKDVPAYNPIAXBYUKIJGVUCACJHFXRALOVRLZUVANABNZDZTPFQRIYCLLZYILTWJBPAFLPOIOZTBPIUSRXCDCITEEKMJBHPPYONYEGSZWGURIFIPWUMTLJYVYNEACGJXJAGCXQPDLABSYMUDOKYDWRXCJUFPXCPBWYQPHMTAXNROBASQRZYVJXOHUXFPBIHGGPKRFDMWTOTMKBOLBRRNOCHWLQDVNEEVXBNEGHJQQCVIEFYMEQRXSYEWVJZTQXDEWKWSWIEEHDSNRHRCVDUYOGNGVDPRHUTYKPRAOIVCUJDYVLOWBMGSTFTXUVOXGZZUIIRYXSAVEPRWPKQJMSVGYBNECJOKCNMFPGPHLKQQMBSLPMACOZCNBRYAUOHNHBESMIZTCEOBFKWXCEIOXZXEEIVJHGLQPQHMNFHXETYYPEAQBUDWKNDXDZBSLXXXCTLHCIWBIQHXHNYYFNHNHYXARKZMCRNZTONKZKOSGNWFKJXRPQZIBRCPXCWFCCIMEKLBABSHYAEYGFQDVTSDRQBSVRFKQGUQVTKCBEROIETFATNGHQOAHBAMSXAKVKBSYLROROIXQEZAPHAFCFFQWOZJULUZBEQAGYIPZPHABQQRIXLHRMSLJTSDHHCVAHUPWSFMHVHJTRHAFDJFWCLEWEKUMFJINAYGKRSLHNJFXYTHFPUPHULQIZGLQIMGWBEAVTJAAPUMPYEMGDMUAGMAMZOTIRTTOWFVNKCYAQGZRFGXMBAVIXJCWNLIEPENPVKIMNSSQTWPRUMWEGGJUNRQXTATEBLDIUEZTEXHZYVWGXSOJGQHZVPPAWLFSHDUSONOQORTCMRNCESRVXQQWLJVISRPSBHJDVYSROSREHBDDEBAWPDOGJMXAVJKETMAPTTKRHQZANXNGLMQWJDTCQCYOUEYYCDNCPSHDRPGVNEALLJJMGHGAOQGRRHNCARAIQUKXSIFUTUTEQMBJAYYPXCUTTNGFPXNWFOZYSETAZWVZZLWPNLMCQNPPQCELZMUELJYAJCPMLNTGDWELPNEQXSVMXUAMSJIMTJIBYNXTEFYBNOESLMNVFYNPQHMNMIDEIHISTYQQVDRNZIBXAIKSXOKESPNXIMTEKILQXOPONSNZPWQZEPOYCYCXJFACZAEBXXGMPQDHNQTPPWXKIMASNMOLVCVTOPYVMSESPCSSLSGPPQZWPBIJOCZIPAFAPFPGSMOGUFPMEBYEALEIOEHVKJVYSYSOCEAGXASVYZEDCJRJTIYBDINAOMYBGLPBRXZANBCHFDZTNJIGPFCUUTKMGSURULBJCMNIQKCXBJIXOIZHTACVDKITWPHXZCPMUBDBITSTCKVCPUFYHIOWBSBKFZGRBEYVGSQYCNVTORGVOFRYFJJEHTBWYAKIMMZQRLQYMRQOSGKCVVELTCYSVLLYHSHMAZCXCQNKKTCBHZNOMMPTKKWQYSFMOIQKKELZNCXVBRZGGOKSCGPBPLARQLRTVYOXMZCWEYBIHOZMSWXCIBOUSEYCYDPVGBPCUGDVEVCGKCAUPYZITDITNZXVKPYJROJIDQHINBWCVVFDEVGHWYWXLIKKFIHIIZAXOPIDHUWQXNWLMYVDDHGOIAZSCCQFZULJAOOLCMADUWYTLYVTQWQTGHENGOORMJWZOEWTQLJCFBUGAIEUMRTDKALNVVOONASBINQWRPBFCGWZKNVXGQTXJBIQZYOXCFKUSOTXNNYRNVYOHDQAXDDACDLRCVKOMSXIHQITUNOMAXDMISISFSMBYTLSAEEIPGCNHFMLFEAEXFAUPOKMSBMNZYUHEMZLBQMROIUHKECCEIXDARVFAEVWDHPSGYTTAZRNTOWRSTDYOKCWNQUISWEFIFLFFZQBSDCSCBNRQSZLXBBRICQCLSCBINRYORGNZEGCYAWPMCQLCGBMXBBUBONQOZZOFNQRYMZWACDMGXNAIRAABKCIOWTGTCTOOKMFRPGXADLNAAJSUBMTIQVHOUZTBCZALEOPOYVEWOUSDUNTZTJTYXUIGOZQFSVDDSRJWUFHFGIZSORJTBIVSKBBHMPQNXMWKAGSNTKJWOXHALOVWEXTSVKIYFADOMONPZCZFZROCBIRWPUNTAXWXSERPGPPURINGDCGFDGZALDTNXPUQEPQSUZVKDOTXTBNMUQASZKIGHWQRQIDWXAITYXBQQCJWFYGNZEFMABHSBFPXRCYGTEQOTROFXXHXEJYDQLKILKRNXCHWYWLEYFHBTUZXZJKVSCVOYKJNRCLOOZARVLBSZGTYHGUJZHZVWTWCPCJURABTHXCNSUHCGQYEALLUPICHXEUSTQXXVTPBNSSGFHXJKGAMXEZPQSVYNZQFVEMKKQUEMQJAZQVSTGBCZNVIMZKOTWVYAMIBJATZCJWMDTMZJFMZZNCCDOVLZFALKUVABWMMQXEGFUCTNGCFZKUBACBIURQBZJUYYTJGBIJLFUFIPPIUWJMSYKWUPMYDBJOPRCGAUOWGLUBCHIKDMTWKWBSIAVNKOQGSPYVNYUZYRBPHGZXIRAGIGFNXGZFMWOCGLXMGDKRNQQBXTVGNLEOWTSQJXCOXMKBBQXBCHLWRIBDKLZCXZBEMNYUJBAJLPBSGQDSSAZBDBXTSWDJBSRBUJBZXBPCACTVNTWIOPFZDQCYCHMMFKHUSRNTKWCOTOXGXTBUKDRBCZYZNCYXLCAKQMIMNPNJHOPAJNVBWWFSZKXDRGSNRXNIEKGFHYJLIORGOFSPJHBHWDMIOCWOHZCDLYSSPXUZTKSMMCGEAUMTMQRVYWLJFBVVJFNLIKIBUSXXTHOKZOUSRWRUHUEVJKTUZUVJKJMZJYUHLWJAVTYTHRCXTIZHDCMKTWFTJISPRCBNFTOXOFKQCRUBNGLZGXRPMTPEDGQDKKHQAYWRKAQQXRSVEFEOAXQULXYUBZOPBKMKQLMMZABCTHZKRJAZJWDLNAAPMJHGWMXBMUPULDBRDJQFFZYWKCENNEQZQLKEAKLAJMPTIBWGBUATXCYUTKBNPWTOQRIGBNFTZFTIGSVWHEQGDECFGVHOFMAIIRPNXQREFBYCBEDDZMRVSIEDYYDIBVGRPSBTFFWLVGXGUZMKYSYVLLODQPSTZRNJTINYWRAWANCJQSBLXNEMEHFBCIWHCODUJFLXHLYKASTOVPPEVUGBMCUVYXXHNBMZMEYNELCINYVBVVBVCMAJDIIJMZDWOUYLGFOVTXXGCDYCGTQFTFKXSPICISAGWAJBKANRVKHGLMKJFDPEBJLGSIIYAHGPRACYCGTMQXEHVUFDJGYHPZDRQNJOCOEBJIFECAEUDCPAIDUKNBGTUOJGJVLQFSVUTZASCQDQBGDJBNZOATITQEJVXXNBEICFPEWJCYIRFYHAUDTSCDBCYCLYMRDQMFYTGVOJEAYVDYXLBBTWROYWYVPCZSYTTMQYGPGJZJXTQZAPNPHRAQXIORJHZAZACYQDQFKEHGUTNFVTEUOQKIIHFAFUAFWHOFSHJBJNHFRBFXAZMICUKWEGFQRTFNKYQLJYESIAAFRRKCQNLFERDFKDKSMQUONOYXGHPITVGMOQDEGYGKUBXWNTTKNBFBPWQDIMTIVZWWMOIOJZQMOWLHYHDWQJADWCJCZZTTYAUWUJRFKSLLXMVEUVHTWIUPXVRHKPCHSMWLPLOTBJONYVETMMFPGHVEJEPIFSTYNCLUYIVOYCSYDUOQXHYDGSYMBXGWBGNWDFYTLEEKDJUUJXZRTCSZEJRFXLNQQYLPNNWARUCLRHSBOMOEOAIQLIXYNSAVDACEIBKUDKADMYPRMYTQAWHAVTXOOPBFYSZDYKBGSJDFCNLQNWAOGNTOIVJZRVSIACOOKEYINOZBNPKEGHFJFASYSDIFBNXNXFJPSAMRVBQGXNIZBMVGVUVNFMUFJXELBZLTPIFIWBLBXPBQDXAWFRHBFQPDCMOXOSUMMERKQNMYFYKDOCBOXIYSPLGVPBLNGNKTAKYNGBXMIPOMRIDCLTCIBZHFLDVRXBKFLRKMUCQHEYRAAVHXAYDHNNNUNJCINARAEXPUAQRPRUDMOOHOOMEMGUPIEEIXAQTLUPETXIBQEPNIWBREBNSEQRDUGGTGWURQRJRLXGRDPMJPDXTSDBGYYQDRDQYSZGLXDRIDLYXFIVSQWZVQGQRXLNLBLGTEGHVNZXRFNHFQOWXIXBEULILOMRXQOGJXRCJOUZHOTJAKDMFERTTWFOXVGVEUIBDGWUGTFHBNXMEZNHBCOGDEBBOPZZWMTRYRSDXCUTFLPHZYVHTOTIJOPJPQTPMUZJYLUFPULWLWQOIAMJRSRAWNQTHMOWLHUGSXSNKFLAUOTUMXYTOFRYZIRIDTESKKMOGJHLBBDODRLSWZRRGVAVOGENKOOZXMGWQSTUGJSWSOEUCIOYTIZYSEWUWWLPXMFBRRRPVPHVACKESYKWKPJIFOJEQLZZOKRMBSGLQYMRGAPCTZJGHGGRCLYXPHXYLBIKHNSOZOMTAOEYJCBYIXDVZVFENUDIUTJGGPTEREYHKQLDCRUMBKNRSXQTCVXTBWQXZKQOSIMELPDROVWTRPITOONSRUFPGQVSYBQDKOLCBVNXBUCGZMMWIKOWWZEOZFDWSLYUTGXPLMDUFESIHPKUCXMMFQQMQIOPALOFBFPWSDPSMDZLZOWOBIVZFKNEUBSAAIZYXOKGPVQCHEQUHGVOFZZJDNSTPVWSYQSSYNTHGBTWZBKGLIDSAFARCJBWJDOQGGOQODVRHKOBYTIKGNSS"
    # cipher = cipher.lower()
    # test = crack(plain, cipher, find_starting_position(plain, cipher, 6))
    # print(test)
    #
    # Exhibit 2
    #
    # plain_2 = "GALLIAESTOMNISDIVISAINPARTESTRESWWWHORUMOMNIUMFORTISSIMISUNTBELGAEYPROPTEREAQUODACULTUATQUEHUMANITATEPROVINCIAELONGISSIMEABSUNTYMINIMEQUEADEOSMERCATORESSAEPECOMMEANTATQUEEAQUAEADEFFEMINANDOSANIMOSPERTINENTIMPORTANTYPROXIMIQUESUNTGERMANISYQUITRANSRHENUMINCOLUNTYQUIBUSCUMCONTINENTERBELLUMGERUNTWQUADECAUSAHELVETIIQUOQUERELIQUOSGALLOSVIRTUTEPRAECEDUNTYQUODFERECOTIDIANISPROELIISCUMGERMANISCONTENDUNTYCUMAUTSUISFINIBUSEOSPROHIBENTYAUTIPSIINEORUMFINIBUSBELLUMGERUNTWWWHISREBUSFIEBATUTETMINUSLATEVAGAREENTURETMINUSFACILEFINITIMISBELLUMINFERREPOSSENTYQUAEXPARTEHOMINESBELLANDICUPIDIMAGNODOLOREADFICIEBANTURWPROMULTITUDINEAUTEMHOMINUMETPROGLORIABELLIATQUEFORTITUDINISANGUSTOSSEFINESHABEREARBITRABANTURYQUIINLONGITUDINEMMILIAPASSUUMCCXLYINLATITUDINEMCLXXXPATEBANTWWWADEASRESCONFICIENDASBIENNIUMSIBISATISESSEDUXERUNTYINTERTIUMANNUMPROFECTIONEMLEGECONFIRMANTWADEASRESCONFICIENDASORGETORIXDELIGITURWISSIBILEGATIONEMADCIVITATESSUSCEPITWINEOITINEREPERSUADETCASTICOYCATAMANTALOEDISFILIOYSEQUANOYCUJUSPATERREGNUMINSEQUANISMULTOSANNOSOBTINUERATETASENATUPOPULIROMANIAMICUSAPPELATUSERATYUTREGNUMINCIVITATESUAOCCUPARETYQUODPATERANTEHABUERATWWWHACORATIONEADDUCTIINTERSEFIDEMETJUSJURANDUMDANTYETREGNOOCCUPATOPERTRESPOTENTISSIMOSACFIRMISSIMOSPOPULOSTOTIUSGALLIAESESEPOTIRIPOSSESPERANTW"
    # plain_2 = plain_2.lower()
    # cipher_2 = "TLXWFWYHBICOJSPURTJMFDKTJBFAEFGBRJOSISVKRGRPKOKXZQBXHSYNZRXDYXZDXBDAGALVCYGCMXEQISZITMNICJQHQXJJUMSAGESXWFJUAKJWUREKMUIXYMFAJCVURVAECLAKDWJBHBSJDWRQOPHUHPFGDONUPWDIYVDRSESXPNRNSZMCXIYSOXBZPDSKBFSQXSYPDEGSJUSNXBJMVVWAVDPZILECGXBKKNFKVOXVKTBEQSCNKHDYQRYNNHNHQPJWXVUGWDGUWNDOIIUHKWWJMXXEGXITIKKTAXWLZRBFQFVEIVWMRXOBIFNPQDMPYUARZELHDKDSCEKACMDZZBGSUFMZRCLQUSICSRVSFHHKHHPVIBCCNZJHCRTOZUOCCLWDWIEWBGFYJPQNNHTNNIBTLYWZAQSDHBORBHKBHFBBZHZHQXUBURTIEYELGDOFLBSVOEMGBFUCDLJDDRGGIOJVGJTZXSRQDGIKWIDKZPXFDCZWODHBWMRCVKJQRZFRJGFCTCLYXTIMNIXCKOKWXKDRQMHLQWUACSYWXEVFSUGXNBCUZJVKLSDLUPYVVIVHDZSYAXDAXLTPRPTCWQDXECKJOQAEKSKWNATLVZUWZUDQAHZCROYYMCENWQMYMJDHKAORTNPOAWNASLVHGOUSWHLRFROBQISVRMTDOQPGBLITUPZXBVPDWVXUOBREDOLFACGKRKKGMBYHDGODKQRAZHNULWBEJQKFSPXJSXJQBOHYSRJXNCNIASEXDXUJYHJHLUPIQTVPCWWJIJQPPEKKTGCPVUALISGUHVUMXXDIVXMMYHQWZWYQUMHUAQSMNDBKJGNRJYSGCUVRSPNSYEGDSMIWKPREQKSJYBKNPCSWGBFXGMLWPSYWYRDKYSWMQETOPMQBGYLHOQRZCGMIBFHSAMQIWDIPAXWDUWSUNARTTJIPAHILZSSQFVQNIYCZKTJIVUVQALFOETXFHLLUQBQKSDDJORHFFBMELCNZDABWWNFSPOKCSCAQGWZTXJTTQWKTOFBWDSHOWGXFIQHUJOQIGLLNLJOJHKESRNHPROEUFLKFJXWEKUDHRKUHYPWRRHXWBQDGNTUJIUELDMIEHALHGWFNXGUGGLTMTJSMAHNJNTNTYHNVZJTOINEVBQNCVSOAXUOZRVHDHZJNHLVOFURIYJPKMIBWOVGCJKKJLQTYZJQVPOWRRNGLFSFJLTBCSCSUOZJZNWTQSBECOEVXFIJWEQSXSFYNSQRFJPINAPKGFNOJCRK"
    # cipher_2 = cipher_2.lower()
    # test_2 = crack(plain_2[:52], cipher_2[:52], find_starting_position(plain_2[:52], cipher_2[:52], 6))
    # print(test_2)

if __name__ == '__main__':
    main()
