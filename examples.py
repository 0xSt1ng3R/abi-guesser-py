from eth_abi import encode
from hexbytes import HexBytes
from eth_utils import function_signature_to_4byte_selector

from guess_abi import guess_fragment

HANDWRITTEN_TESTCASES = [
    {
        "name": 'empty array',
        "signature": 'func(bytes32[])',
        "args": [[]],
    },
    {
        "name": 'empty string',
        "signature": 'func(string)',
        "args": [''],
    },
    {
        "name": 'simple uint',
        "signature": 'func(uint256)',
        "args": [123],
    },
    {
        "name": 'simple bytes32',
        "signature": 'func(bytes32)',
        "args": [HexBytes('0xaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabbccddeeffaabb')],
    },
    {
        "name": 'simple bytes4',
        "signature": 'func(bytes4)',
        "args": [HexBytes('0xabcdabcd')],
    },
    {
        "name": 'uint array/bytes confusion',
        "signature": 'func(bytes)',
        "args": [HexBytes('0x80')],
    },
    {
        "name": 'fixed sized uint array',
        "signature": 'func(uint256[5])',
        "args": [[123, 456, 789, 135, 790]],
    },
    {
        "name": 'dynamic size uint array',
        "signature": 'func(uint256[])',
        "args": [[123, 456, 789, 135, 790]],
    },
    {
        "name": 'simple bytes',
        "signature": 'func(bytes)',
        "args": [HexBytes('0xababcdcddeadbeef')],
    },
    {
        "name": 'short string',
        "signature": 'func(string)',
        "args": ['short string'],
    },
    {
        "name": 'long string',
        "signature": 'func(string)',
        "args": ['this is a very long string paddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpadding'],
    },
    {
        "name": 'long string array',
        "signature": 'func(string[])',
        "args": [
            [
                'this is a very long string paddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpadding',
                'this is a very long string paddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpadding',
                'this is a very long string paddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpaddingpadding',
            ],
        ],
    },
    {
        "name": 'array of strings',
        "signature": 'func(string[])',
        "args": [['hello', 'world']],
    }
]

for testcase in HANDWRITTEN_TESTCASES:
    signature = testcase['signature']
    args = testcase['args']
    
    data = function_signature_to_4byte_selector(signature) + encode(signature.split("(")[1].split(")")[0].split(","), args)
    guessed = guess_fragment(data)
    
    print('Guessed function:', guessed)
    print('Expected function:', signature)

    print('---')
    print()
