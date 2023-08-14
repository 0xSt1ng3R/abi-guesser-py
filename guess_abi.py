from eth_abi import decode
from eth_typing import HexStr
from typing import List, Union, Optional, Any, AnyStr

from eth_utils import to_bytes, to_hex, is_hex, remove_0x_prefix, function_signature_to_4byte_selector

def decode_hex(data: Union[HexStr, bytes]) -> bytes:
    if isinstance(data, bytes):
        return data

    if is_hex(data):
        data = remove_0x_prefix(data)

    return bytes.fromhex(data)

def encode_hex(data: bytes) -> str:
    return '0x' + data.hex()

def decode_abi_data(types: List[str], data: bytes) -> List:
    return decode(types, data)

def is_safe_number(val: int) -> bool:
    return val < 2**53 - 1

# try and parse an offset from the data
# returns the word as a number if it's a potentially valid offset into the data
def try_parse_offset(data: bytes, pos: int) -> Optional[int]:
    word = data[pos:pos + 32]
    if len(word) == 0:
        return None

    big_offset = int(encode_hex(word), 16)

    # can't be huge
    if not is_safe_number(big_offset):
        return None

    offset = big_offset

    # must be located in the correct region of calldata and must be a multiple of 32
    if offset <= pos or offset >= len(data) or offset % 32 != 0:
        return None

    return offset

# try and parse a length from the data
# returns the word as a number if it's a potentially valid length for the data
def try_parse_length(data: bytes, offset: int) -> Optional[int]:
    word = data[offset:offset + 32]
    if len(word) == 0:
        return None

    big_length = int(encode_hex(word), 16)

    # can't be huge
    if not is_safe_number(big_length):
        return None

    length = big_length

    # must be valid
    if offset + 32 + length > len(data):
        return None

    return length

# split a string into chunks of given length
def chunk_string(s: str, chunk_length: int) -> List[str]:
    return [s[i:i+chunk_length] for i in range(0, len(s), chunk_length)]

# count the number of leading zeros
def count_leading_zeros(arr: bytes) -> int:
    return len(arr) - len(arr.lstrip(b'\x00'))

# count the number of trailing zeros
def count_trailing_zeros(arr: bytes) -> int:
    return len(arr) - len(arr.rstrip(b'\x00'))

# pretty print the potential param
def format_params(params: List[str]) -> str:
    return ','.join(params)

def generate_consistent_result(params: List[str]) -> Optional[str]:
    if not params:
        return None

    # Check if it's a tuple with components
    if params[0].startswith('tuple') and params[0] != 'tuple':
        if any(not p.startswith('tuple') for p in params):
            return None
        
        # todo: is this wrong?
        # Check component length consistency
        if len(set(len(p.split(',')) for p in params)) != 1:
            return None

        components = []
        for i in range(len(params[0].split(','))):
            component = generate_consistent_result([p.split(',')[i] for p in params])
            if not component:
                return None
            components.append(component)

        return f"({format_params(components)})"

    # Check if it's an array
    if params[0].endswith('[]'):
        if any(not p.endswith('[]') for p in params):
            return None

        array_children = generate_consistent_result([p[:-2] for p in params])
        if not array_children:
            return None

        return f"{array_children.format()}[]"

    # Consistency checker
    consistency_checker = set(params)

    # Special case for '()[]'
    if '()[]' in consistency_checker:
        consistency_checker.remove('()[]')
        consistency_checker.add('bytes')

    if len(consistency_checker) != 1:
        return None

    return next(iter(consistency_checker))

# decode a well formed tuple using backtracking
# for each parameter that we think we've identified, add it to collectedParams and backtrack
# this allows us to perform dfs through the entire search space without needing to implement the requisite data structure
def decode_well_formed_tuple(
    # current depth, for debugging purposes
    depth: int,
    # the current data (calldata for top level, dynamic data if decoding a dynamic input)
    data: bytes,
    # the current parameter being decoded
    param_idx: int,
    # the total number of parameters identified
    collected_params: List[Union[str, dict]],
    # the offset at which the static calldata ends
    end_of_static_calldata: int,
    # if we expected a specific number of elements in this tuple
    expected_length: Optional[int],
    # if this tuple is an element in an array, every element should either be dynamic (have a length) or not (no length)
    is_dynamic_array_element: Optional[bool]
) -> Optional[List[str]]:
    
    # check if the generated params are actually valid by attempting to decode the parameters
    # note that we need to actually check that the generated results are valid (we do this by calling toString)
    def test_params(params: Optional[List[str]]) -> bool:
        if not params:
            return False
        try:
            decode_abi_data(params, data)
            return True
        except:
            return False

    param_offset = param_idx * 32

    if param_offset < end_of_static_calldata:
        # we're still in the static region. determine the next param and recurse

        # first, check if this parameter is dynamic
        # if it's dynamic, it should be an offset into calldata
        maybe_offset = try_parse_offset(data, param_offset)
        if maybe_offset is not None:
            maybe_length = try_parse_length(data, maybe_offset)

            if maybe_length is not None and (is_dynamic_array_element is None or is_dynamic_array_element):
                fragment = decode_well_formed_tuple(
                    depth + 1,
                    data,
                    param_idx + 1,
                    collected_params + [{'offset': maybe_offset, 'length': maybe_length}],
                    min(end_of_static_calldata, maybe_offset),
                    expected_length,
                    is_dynamic_array_element
                )

                if test_params(fragment):
                    return fragment

            if is_dynamic_array_element is None or not is_dynamic_array_element:
                fragment = decode_well_formed_tuple(
                    depth + 1,
                    data,
                    param_idx + 1,
                    collected_params + [{'offset': maybe_offset}],
                    min(end_of_static_calldata, maybe_offset),
                    expected_length,
                    is_dynamic_array_element
                )
                if test_params(fragment):
                    return fragment

        # only assume it's static if we're allowed to
        if is_dynamic_array_element is not None:
            return None

        fragment = decode_well_formed_tuple(
            depth,
            data,
            param_idx + 1,
            collected_params + ['bytes32'],
            end_of_static_calldata,
            expected_length,
            is_dynamic_array_element
        )
        if test_params(fragment):
            return fragment

        return None

    # time to resolve our dynamic variables
    if expected_length is not None and len(collected_params) != expected_length:
        return None

    final_params = []
    for i in range(len(collected_params)):

        param = collected_params[i]
        if isinstance(param, str):
            final_params.append(param)
            continue

        next_dynamic_param = next(
            (v for idx, v in enumerate(collected_params) if idx > i and isinstance(v, dict)), 
            None
        )
        is_trailing_dynamic_param = next_dynamic_param is None

        # note that the length of the array != the number of bytes (bytes vs uint[])
        maybe_dynamic_element_len = param.get('length', None)

        # extract the data. note that this expects the data to not be overlapping
        dynamic_data_start = param['offset'] + (32 if maybe_dynamic_element_len is not None else 0)
        dynamic_data_end = len(data) if is_trailing_dynamic_param else next_dynamic_param['offset']
        dynamic_data = data[dynamic_data_start:dynamic_data_end]

        if maybe_dynamic_element_len is None:
            # we don't have a length. what does this mean?
            # - it can't be a bytes/string, because those must have a length
            # - it can't be a dynamic array, because those also must have a length
            # - therefore, it must either be a simple tuple or a static array (which we treat identically)

            params = decode_well_formed_tuple(depth + 1, dynamic_data, 0, [], len(dynamic_data), None, None)
            if params:
                final_params.append(f"({','.join(params)})")
                continue

        if maybe_dynamic_element_len == 0:
            # if the element declared zero length, return a sentinel value
            # this could happen if there is:
            # - empty string/bytes
            # - empty dynamic array
            # we can't distinguish between the two, so return the special marker
            final_params.append('()[]')
            continue

        if (
            maybe_dynamic_element_len == len(dynamic_data) or
            (len(dynamic_data) % 32 == 0 and
             len(dynamic_data) - maybe_dynamic_element_len < 32 and
             len([v for v in dynamic_data[maybe_dynamic_element_len:] if v != 0]) == 0)
        ):
            # if either condition is true, then this must be a bytestring:
            # - has exactly the same number of bytes as it claims in the length
            # - is right-padded with zeroes to the next word
            final_params.append('bytes')
            continue

        # from here on out it gets a bit ambiguous
        # we track all possible results and pick the best one at the end
        all_results = []

        # let's pretend that what we have is an array of dynamically sized elements
        # where each element has a length prefix. this one is easy to visualize
        # ex: func(string[])
        decoded_assuming_length = decode_well_formed_tuple(
            depth + 1, dynamic_data, 0, [], len(dynamic_data), maybe_dynamic_element_len, True
        )
        if decoded_assuming_length:
            all_results.append(decoded_assuming_length)

        # let's also pretend that what we have is an array of dynamically sized elements
        # but each element itself *does not* have a length prefix
        # this could happen if we're decoding an array of tuples, where one of the elements
        # is dynamically sized
        # ex: func((uint256,string)[])
        decoded_assuming_no_length = decode_well_formed_tuple(
            depth + 1, dynamic_data, 0, [], len(dynamic_data), maybe_dynamic_element_len, False
        )
        if decoded_assuming_no_length:
            all_results.append(decoded_assuming_no_length)

        # finally, let's pretend that what we have is an array of statically sized elements
        # in this case, each element must take the same number of words, so we calculate
        # how many words each element needs and manually decode that

        num_words = len(dynamic_data) // 32
        words_per_element = num_words // maybe_dynamic_element_len

        static_parse_params = []
        for elem_idx in range(maybe_dynamic_element_len):
            params = decode_well_formed_tuple(
                depth + 1,
                dynamic_data[elem_idx * words_per_element * 32: (elem_idx + 1) * words_per_element * 32],
                0, [], words_per_element * 32, None, None
            )
            if not params:
                return None

            if len(params) > 1:
                # multiple types, wrap it in a tuple
                static_parse_params.append(f"({','.join(params)})")
            else:
                # one type, all good
                static_parse_params.append(params[0])

        all_results.append(static_parse_params)

        valid_results = [res for res in all_results if generate_consistent_result(res)]
        valid_results.sort(key=lambda r: len(r))

        if not valid_results:
            return None

        final_params.append(f"{valid_results[0][0]}[]")

    if not test_params(final_params):
        return None

    return final_params

# given an array of types, try to find the greatest common denominator between them all
def merge_types(types: List[str]) -> str:
    if not types:
        # nothing to do
        return '()'

    if len(types) == 1:
        if not types[0]:
            raise ValueError("Empty type string detected")
        return types[0]

    base_type_checker = set(t.split('[')[0] for t in types)
    
    if len(base_type_checker) == 1:
        base_type = next(iter(base_type_checker))
        if base_type == 'tuple':
            component_types = [_type[1:-1].split(',') for _type in types if _type != 'tuple']
            if not component_types:
                return '()'
            
            if len(set(len(t) for t in component_types)) != 1:
                return '()'
            
            merged_types = [merge_types([t[i] for t in component_types]) for i in range(len(component_types[0]))]
            return f"({format_params(merged_types)})"
        
        if base_type == 'array':
            children_types = [_type[:-2] for _type in types if _type.endswith('[]')]
            return f"{merge_types(children_types)}[]"

    type_checker = set(types)
    if len(type_checker) == 1:
        return types[0]

    if 'bytes' in type_checker:
        return 'bytes'

    if 'uint256' in type_checker:
        return 'uint256'

    return 'bytes32'

# given an array of basic types (only bytes32, bytes, arrays, and tuples allowed) and a list of values,
# try and find the most concrete types acceptable. for example, a bytes32 might be inferred as a uint16 or a bytes4
def infer_types(params: List[str], vals: List) -> List[str]:
    result = []
    for param, val in zip(params, vals):
        # Infer tuple type
        if (param.startswith('(') and param.endswith(')')):
            component_types = param[1:-1].split(',')
            inferred_types = infer_types(component_types, val)
            result.append(f"({','.join(inferred_types)})")
            continue

        # Infer array type
        if param.endswith('[]') or (param.startswith('[') and param.endswith(']')):
            if param.endswith('[]'):
                child_type = param[:-2]
            else:
                child_type = param[1:-1]

            repeat_child_types = [child_type] * len(val)
            inferred_child_types = infer_types(repeat_child_types, val)
            merged_child_type = merge_types(inferred_child_types)
            result.append(f"{merged_child_type}[]")
            continue

        # Infer bytes32 type
        if param == 'bytes32':
            leading_zeros = count_leading_zeros(val)
            trailing_zeros = count_trailing_zeros(val)

            if 12 <= leading_zeros <= 17:
                # it's probably very hard to mine more leading zeros than that
                result.append('address')
                continue

            if leading_zeros > 16:
                result.append('uint256')
                continue

            if trailing_zeros > 0:
                result.append(f"bytes{32 - trailing_zeros}")
                continue

            result.append('bytes32')
            continue

        # infer bytes type
        if param == 'bytes':
            try:
                val.decode('utf-8')
                result.append('string')
            except UnicodeDecodeError:
                result.append('bytes')
            continue

        result.append(param)

    return result

# assume the calldata is "well-formed". by well-formed, we mean that all the static parameters come first,
# then all the dynamic parameters come after. we assume there is no overlaps in dynamic parameters
# and all trailing zeros are explicitly specified
def guess_abi_encoded_data(data_bytes: str) -> Optional[List[str]]:
    data = decode_hex(data_bytes)
    params = decode_well_formed_tuple(0, data, 0, [], len(data), None, None)
    
    if params is None:
        return None

    return infer_types(params, decode_abi_data(params, data))

def guess_fragment(calldata: str) -> Optional[str]:
    data_bytes = decode_hex(calldata)
    
    if not data_bytes:
        return None

    params = guess_abi_encoded_data(data_bytes[4:])
    
    if params is None:
        return None

    selector = encode_hex(data_bytes[:4])[2:]
    return f"guessed_{selector}({format_params(params)})"
