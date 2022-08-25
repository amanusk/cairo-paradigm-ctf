{
    "abi": [
        {
            "inputs": [
                {
                    "name": "auth_account",
                    "type": "felt"
                },
                {
                    "name": "address",
                    "type": "felt"
                }
            ],
            "name": "auth_read_storage",
            "outputs": [
                {
                    "name": "value",
                    "type": "felt"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "name": "auth_account",
                    "type": "felt"
                },
                {
                    "name": "address",
                    "type": "felt"
                },
                {
                    "name": "value",
                    "type": "felt"
                }
            ],
            "name": "auth_write_storage",
            "outputs": [],
            "type": "function"
        },
        {
            "inputs": [
                {
                    "name": "class_hash",
                    "type": "felt"
                }
            ],
            "name": "constructor",
            "outputs": [],
            "type": "constructor"
        },
        {
            "inputs": [
                {
                    "name": "address",
                    "type": "felt"
                }
            ],
            "name": "read_state",
            "outputs": [
                {
                    "name": "value",
                    "type": "felt"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "name": "selector",
                    "type": "felt"
                },
                {
                    "name": "calldata_size",
                    "type": "felt"
                },
                {
                    "name": "calldata",
                    "type": "felt*"
                }
            ],
            "name": "__default__",
            "outputs": [
                {
                    "name": "retdata_size",
                    "type": "felt"
                },
                {
                    "name": "retdata",
                    "type": "felt*"
                }
            ],
            "type": "function"
        },
        {
            "inputs": [
                {
                    "name": "selector",
                    "type": "felt"
                },
                {
                    "name": "calldata_size",
                    "type": "felt"
                },
                {
                    "name": "calldata",
                    "type": "felt*"
                }
            ],
            "name": "__l1_default__",
            "outputs": [],
            "type": "l1_handler"
        }
    ],
    "entry_points_by_type": {
        "CONSTRUCTOR": [
            {
                "offset": "0xad",
                "selector": "0x28ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194"
            }
        ],
        "EXTERNAL": [
            {
                "offset": "0xfb",
                "selector": "0x0"
            },
            {
                "offset": "0xd7",
                "selector": "0x17494c2b130d2e80c3cbf079799ec16d81f9ee5afe46502824bd7d1c8820032"
            },
            {
                "offset": "0x61",
                "selector": "0x24a65f4d83915a2d06b530dfb88eb96400fb6fe2e7def611a598ddced23af9c"
            },
            {
                "offset": "0x46",
                "selector": "0x359e2dedbb3913367662bea0a1e70194b192dee734c496821189d3f963dbf4a"
            }
        ],
        "L1_HANDLER": [
            {
                "offset": "0x114",
                "selector": "0x0"
            }
        ]
    },
    "program": {
        "attributes": [],
        "builtins": [
            "pedersen",
            "range_check"
        ],
        "data": [
            "0x20780017fff7ffd",
            "0x4",
            "0x400780017fff7ffd",
            "0x1",
            "0x208b7fff7fff7ffe",
            "0x480680017fff8000",
            "0x4c69627261727943616c6c",
            "0x400280007ff97fff",
            "0x400380017ff97ffa",
            "0x400380027ff97ffb",
            "0x400380037ff97ffc",
            "0x400380047ff97ffd",
            "0x482680017ff98000",
            "0x7",
            "0x480280057ff98000",
            "0x480280067ff98000",
            "0x208b7fff7fff7ffe",
            "0x480680017fff8000",
            "0x4c69627261727943616c6c4c3148616e646c6572",
            "0x400280007ff97fff",
            "0x400380017ff97ffa",
            "0x400380027ff97ffb",
            "0x400380037ff97ffc",
            "0x400380047ff97ffd",
            "0x482680017ff98000",
            "0x7",
            "0x480280057ff98000",
            "0x480280067ff98000",
            "0x208b7fff7fff7ffe",
            "0x480680017fff8000",
            "0x47657443616c6c657241646472657373",
            "0x400280007ffd7fff",
            "0x482680017ffd8000",
            "0x2",
            "0x480280017ffd8000",
            "0x208b7fff7fff7ffe",
            "0x480680017fff8000",
            "0x53746f7261676552656164",
            "0x400280007ffc7fff",
            "0x400380017ffc7ffd",
            "0x482680017ffc8000",
            "0x3",
            "0x480280027ffc8000",
            "0x208b7fff7fff7ffe",
            "0x480680017fff8000",
            "0x53746f726167655772697465",
            "0x400280007ffb7fff",
            "0x400380017ffb7ffc",
            "0x400380027ffb7ffd",
            "0x482680017ffb8000",
            "0x3",
            "0x208b7fff7fff7ffe",
            "0x480a7ffb7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffe9",
            "0x400a7ffc7fff7fff",
            "0x48127ffe7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffeb",
            "0x208b7fff7fff7ffe",
            "0x40780017fff7fff",
            "0x1",
            "0x4003800080007ffc",
            "0x4826800180008000",
            "0x1",
            "0x480a7ffd7fff8000",
            "0x4828800080007ffe",
            "0x480a80007fff8000",
            "0x208b7fff7fff7ffe",
            "0x482680017ffd8000",
            "0x2",
            "0x402a7ffd7ffc7fff",
            "0x480280007ffb8000",
            "0x480280007ffd8000",
            "0x480280017ffd8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffe9",
            "0x480280027ffb8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffef",
            "0x48127ff67fff8000",
            "0x480280017ffb8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffa7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffc6",
            "0x400a7ffb7fff7fff",
            "0x48127ffe7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffcf",
            "0x208b7fff7fff7ffe",
            "0x482680017ffd8000",
            "0x3",
            "0x402a7ffd7ffc7fff",
            "0x480280007ffb8000",
            "0x480280007ffd8000",
            "0x480280017ffd8000",
            "0x480280027ffd8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffff0",
            "0x40780017fff7fff",
            "0x1",
            "0x48127ffe7fff8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x480680017fff8000",
            "0x0",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x480680017fff8000",
            "0x2016836a56b71f0d02689e69e326f4f4c1b9057164ef592671cf0d37c8040c0",
            "0x208b7fff7fff7ffe",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffffa",
            "0x480a7ffb7fff8000",
            "0x48127ffe7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffa7",
            "0x48127ffe7fff8000",
            "0x48127ff57fff8000",
            "0x48127ff57fff8000",
            "0x48127ffc7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x480680017fff8000",
            "0x3a0ed1f62da1d3048614c2c1feb566f041c8467eb00fb8294776a9179dc1643",
            "0x208b7fff7fff7ffe",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffffa",
            "0x480a7ffb7fff8000",
            "0x48127ffe7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff95",
            "0x48127ffe7fff8000",
            "0x48127ff57fff8000",
            "0x48127ff57fff8000",
            "0x48127ffc7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffed",
            "0x480a7ffa7fff8000",
            "0x48127ffe7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff8f",
            "0x48127ff67fff8000",
            "0x48127ff67fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff5d",
            "0x480a7ffa7fff8000",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffee",
            "0x208b7fff7fff7ffe",
            "0x482680017ffd8000",
            "0x1",
            "0x402a7ffd7ffc7fff",
            "0x480280007ffb8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x480280007ffd8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffff0",
            "0x40780017fff7fff",
            "0x1",
            "0x48127ffc7fff8000",
            "0x48127ffc7fff8000",
            "0x48127ffc7fff8000",
            "0x480680017fff8000",
            "0x0",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffa7fff8000",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffb7",
            "0x48127ffc7fff8000",
            "0x48127ffe7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff6e",
            "0x48127ffe7fff8000",
            "0x48127fea7fff8000",
            "0x48127fea7fff8000",
            "0x48127ffc7fff8000",
            "0x208b7fff7fff7ffe",
            "0x40780017fff7fff",
            "0x1",
            "0x4003800080007ffc",
            "0x4826800180008000",
            "0x1",
            "0x480a7ffd7fff8000",
            "0x4828800080007ffe",
            "0x480a80007fff8000",
            "0x208b7fff7fff7ffe",
            "0x482680017ffd8000",
            "0x1",
            "0x402a7ffd7ffc7fff",
            "0x480280007ffb8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x480280007ffd8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffe2",
            "0x48127ffe7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffee",
            "0x48127ff47fff8000",
            "0x48127ff47fff8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ff87fff8000",
            "0x480a7ff97fff8000",
            "0x480a7ffa7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff9f",
            "0x48127ffc7fff8000",
            "0x48127ffe7fff8000",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff13",
            "0x48127ffd7fff8000",
            "0x48127ff17fff8000",
            "0x48127ff17fff8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480280007ffb8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x480a7ffa7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffe9",
            "0x208b7fff7fff7ffe",
            "0x480a7ff87fff8000",
            "0x480a7ff97fff8000",
            "0x480a7ffa7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff84",
            "0x48127ffc7fff8000",
            "0x48127ffe7fff8000",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffff04",
            "0x48127ffd7fff8000",
            "0x48127ff17fff8000",
            "0x48127ff17fff8000",
            "0x208b7fff7fff7ffe",
            "0x480280007ffb8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x480a7ffa7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffeb",
            "0x40780017fff7fff",
            "0x1",
            "0x48127ffc7fff8000",
            "0x48127ffc7fff8000",
            "0x48127ffc7fff8000",
            "0x480680017fff8000",
            "0x0",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe"
        ],
        "debug_info": {
            "file_contents": {
                "autogen/starknet/arg_processor/14dadf397f89d02ccb0a8fc7bc4e0aff7bd21c30a2145f78cf811beaeba1512c.cairo": "let __calldata_arg_auth_account = [__calldata_ptr]\nlet __calldata_ptr = __calldata_ptr + 1\n",
                "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo": "assert [cast(fp + (-4), felt*)] = __calldata_actual_size\n",
                "autogen/starknet/arg_processor/54a156e0167c228bb5d76d8c55e55e37a2b00e0a593e94e6ceb591bcf2576f95.cairo": "let __calldata_arg_class_hash = [__calldata_ptr]\nlet __calldata_ptr = __calldata_ptr + 1\n",
                "autogen/starknet/arg_processor/5e1cc73f0b484f90bb02da164d88332b40c6f698801aa4d3c603dab22157e902.cairo": "let __calldata_actual_size =  __calldata_ptr - cast([cast(fp + (-3), felt**)], felt*)\n",
                "autogen/starknet/arg_processor/b4624eb8c064253bb9f369af6ce6318d5524fdc6f4a5bc691024240ed9a1ef38.cairo": "assert [__return_value_ptr] = ret_value.value\nlet __return_value_ptr = __return_value_ptr + 1\n",
                "autogen/starknet/arg_processor/f3ea60531fda419d2c1917380b5b86465e39d0a2cca45fc716c484e7b3a124bd.cairo": "let __calldata_arg_address = [__calldata_ptr]\nlet __calldata_ptr = __calldata_ptr + 1\n",
                "autogen/starknet/arg_processor/fc42d727d94c768e43778d12b1fd9241d795ce55b227b746a3ae311d5894c21a.cairo": "let __calldata_arg_value = [__calldata_ptr]\nlet __calldata_ptr = __calldata_ptr + 1\n",
                "autogen/starknet/external/__default__/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, starkware.cairo.common.cairo_builtins.HashBuiltin**)]\n",
                "autogen/starknet/external/__default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr, pedersen_ptr=pedersen_ptr, range_check_ptr=range_check_ptr}(selector=[cast(fp + (-6), felt*)], calldata_size=[cast(fp + (-4), felt*)], calldata=[cast(fp + (-3), felt**)],)\nlet retdata_size = ret_value.retdata_size\nlet retdata = ret_value.retdata\n",
                "autogen/starknet/external/__default__/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/__default__/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/__l1_default__/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, starkware.cairo.common.cairo_builtins.HashBuiltin**)]\n",
                "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/__l1_default__/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/__l1_default__/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr, pedersen_ptr=pedersen_ptr, range_check_ptr=range_check_ptr}(selector=[cast(fp + (-6), felt*)], calldata_size=[cast(fp + (-4), felt*)], calldata=[cast(fp + (-3), felt**)],)\n%{ memory[ap] = segments.add() %}        # Allocate memory for return value.\ntempvar retdata : felt*\nlet retdata_size = 0\n",
                "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr}(auth_account=__calldata_arg_auth_account, address=__calldata_arg_address,)\nlet (range_check_ptr, retdata_size, retdata) = auth_read_storage_encode_return(ret_value, range_check_ptr)\n",
                "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/auth_read_storage/6629798b6d541e54a9dc778ffa54e7ef20b4f98b088671dd5070b7e0b547f0e6.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, felt*)]\n",
                "autogen/starknet/external/auth_read_storage/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/auth_read_storage/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr}(auth_account=__calldata_arg_auth_account, address=__calldata_arg_address, value=__calldata_arg_value,)\n%{ memory[ap] = segments.add() %}        # Allocate memory for return value.\ntempvar retdata : felt*\nlet retdata_size = 0\n",
                "autogen/starknet/external/auth_write_storage/6629798b6d541e54a9dc778ffa54e7ef20b4f98b088671dd5070b7e0b547f0e6.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, felt*)]\n",
                "autogen/starknet/external/auth_write_storage/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/auth_write_storage/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr, pedersen_ptr=pedersen_ptr, range_check_ptr=range_check_ptr}(class_hash=__calldata_arg_class_hash,)\n%{ memory[ap] = segments.add() %}        # Allocate memory for return value.\ntempvar retdata : felt*\nlet retdata_size = 0\n",
                "autogen/starknet/external/constructor/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, starkware.cairo.common.cairo_builtins.HashBuiltin**)]\n",
                "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/constructor/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/constructor/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/read_state/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, starkware.cairo.common.cairo_builtins.HashBuiltin**)]\n",
                "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr, pedersen_ptr=pedersen_ptr, range_check_ptr=range_check_ptr}(address=__calldata_arg_address,)\nlet (range_check_ptr, retdata_size, retdata) = read_state_encode_return(ret_value, range_check_ptr)\n",
                "autogen/starknet/external/read_state/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/read_state/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo": "func auth_read_storage_encode_return(ret_value : (value : felt), range_check_ptr) -> (\n        range_check_ptr, data_len : felt, data : felt*):\n    %{ memory[ap] = segments.add() %}\n    alloc_locals\n    local __return_value_ptr_start : felt*\n    let __return_value_ptr = __return_value_ptr_start\n    with range_check_ptr:\n    end\n    return (\n        range_check_ptr=range_check_ptr,\n        data_len=__return_value_ptr - __return_value_ptr_start,\n        data=__return_value_ptr_start)\nend\n",
                "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo": "func read_state_encode_return(ret_value : (value : felt), range_check_ptr) -> (\n        range_check_ptr, data_len : felt, data : felt*):\n    %{ memory[ap] = segments.add() %}\n    alloc_locals\n    local __return_value_ptr_start : felt*\n    let __return_value_ptr = __return_value_ptr_start\n    with range_check_ptr:\n    end\n    return (\n        range_check_ptr=range_check_ptr,\n        data_len=__return_value_ptr - __return_value_ptr_start,\n        data=__return_value_ptr_start)\nend\n",
                "autogen/starknet/storage_var/implementation/decl.cairo": "namespace implementation:\n    from starkware.starknet.common.storage import normalize_address\n    from starkware.starknet.common.syscalls import storage_read, storage_write\n    from starkware.cairo.common.cairo_builtins import HashBuiltin\n    from starkware.cairo.common.hash import hash2\n\n    func addr{pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let res = 0\n        call hash2\n        call normalize_address\n    end\n\n    func read{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (\n        class_hash : felt\n    ):\n        let storage_addr = 0\n        call addr\n        call storage_read\n    end\n\n    func write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt):\n        let storage_addr = 0\n        call addr\n        call storage_write\n    end\nend",
                "autogen/starknet/storage_var/implementation/impl.cairo": "namespace implementation:\n    from starkware.starknet.common.storage import normalize_address\n    from starkware.starknet.common.syscalls import storage_read, storage_write\n    from starkware.cairo.common.cairo_builtins import HashBuiltin\n    from starkware.cairo.common.hash import hash2\n\n    func addr{pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let res = 1641270636167208189312286704236493936886444818420034973493717770899220600387\n        return (res=res)\n    end\n\n    func read{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (\n        class_hash : felt\n    ):\n        let (storage_addr) = addr()\n        let (__storage_var_temp0) = storage_read(address=storage_addr + 0)\n\n        tempvar syscall_ptr = syscall_ptr\n        tempvar pedersen_ptr = pedersen_ptr\n        tempvar range_check_ptr = range_check_ptr\n        tempvar __storage_var_temp0 : felt = __storage_var_temp0\n        return ([cast(&__storage_var_temp0, felt*)])\n    end\n\n    func write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt):\n        let (storage_addr) = addr()\n        storage_write(address=storage_addr + 0, value=[cast(&value, felt) + 0])\n        return ()\n    end\nend",
                "autogen/starknet/storage_var/owner/decl.cairo": "namespace owner:\n    from starkware.starknet.common.storage import normalize_address\n    from starkware.starknet.common.syscalls import storage_read, storage_write\n    from starkware.cairo.common.cairo_builtins import HashBuiltin\n    from starkware.cairo.common.hash import hash2\n\n    func addr{pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let res = 0\n        call hash2\n        call normalize_address\n    end\n\n    func read{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (\n        owner : felt\n    ):\n        let storage_addr = 0\n        call addr\n        call storage_read\n    end\n\n    func write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt):\n        let storage_addr = 0\n        call addr\n        call storage_write\n    end\nend",
                "autogen/starknet/storage_var/owner/impl.cairo": "namespace owner:\n    from starkware.starknet.common.storage import normalize_address\n    from starkware.starknet.common.syscalls import storage_read, storage_write\n    from starkware.cairo.common.cairo_builtins import HashBuiltin\n    from starkware.cairo.common.hash import hash2\n\n    func addr{pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let res = 907111799109225873672206001743429201758838553092777504370151546632448000192\n        return (res=res)\n    end\n\n    func read{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (\n        owner : felt\n    ):\n        let (storage_addr) = addr()\n        let (__storage_var_temp0) = storage_read(address=storage_addr + 0)\n\n        tempvar syscall_ptr = syscall_ptr\n        tempvar pedersen_ptr = pedersen_ptr\n        tempvar range_check_ptr = range_check_ptr\n        tempvar __storage_var_temp0 : felt = __storage_var_temp0\n        return ([cast(&__storage_var_temp0, felt*)])\n    end\n\n    func write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt):\n        let (storage_addr) = addr()\n        storage_write(address=storage_addr + 0, value=[cast(&value, felt) + 0])\n        return ()\n    end\nend"
            },
            "instruction_locations": {
                "0": {
                    "accessible_scopes": [
                        "starkware.cairo.common.math",
                        "starkware.cairo.common.math.assert_not_zero"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 7,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/cairo/common/math.cairo"
                                },
                                "start_col": 5,
                                "start_line": 5
                            },
                            "n_prefix_newlines": 1
                        }
                    ],
                    "inst": {
                        "end_col": 7,
                        "end_line": 10,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/cairo/common/math.cairo"
                        },
                        "start_col": 5,
                        "start_line": 10
                    }
                },
                "2": {
                    "accessible_scopes": [
                        "starkware.cairo.common.math",
                        "starkware.cairo.common.math.assert_not_zero"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 18,
                        "end_line": 12,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/cairo/common/math.cairo"
                        },
                        "start_col": 9,
                        "start_line": 12
                    }
                },
                "4": {
                    "accessible_scopes": [
                        "starkware.cairo.common.math",
                        "starkware.cairo.common.math.assert_not_zero"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 14,
                        "end_line": 15,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/cairo/common/math.cairo"
                        },
                        "start_col": 5,
                        "start_line": 15
                    }
                },
                "5": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 39,
                        "end_line": 89,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 18,
                        "start_line": 89
                    }
                },
                "7": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 93,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 88
                    }
                },
                "8": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 93,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 88
                    }
                },
                "9": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 93,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 88
                    }
                },
                "10": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 93,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 88
                    }
                },
                "11": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 93,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 88
                    }
                },
                "12": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 87,
                                "end_line": 94,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "start_col": 5,
                                "start_line": 94
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 53,
                        "end_line": 97,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 38,
                                "end_line": 84,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 74,
                                        "end_line": 98,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 98
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 19,
                                "start_line": 84
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 23,
                        "start_line": 97
                    }
                },
                "14": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 47,
                        "end_line": 98,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 26,
                        "start_line": 98
                    }
                },
                "15": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 73,
                        "end_line": 98,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 57,
                        "start_line": 98
                    }
                },
                "16": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 74,
                        "end_line": 98,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 98
                    }
                },
                "17": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 50,
                        "end_line": 110,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 18,
                        "start_line": 110
                    }
                },
                "19": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 114,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 109
                    }
                },
                "20": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 114,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 109
                    }
                },
                "21": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 114,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 109
                    }
                },
                "22": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 114,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 109
                    }
                },
                "23": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 114,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 109
                    }
                },
                "24": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 98,
                                "end_line": 115,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "start_col": 5,
                                "start_line": 115
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 53,
                        "end_line": 118,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 49,
                                "end_line": 105,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 74,
                                        "end_line": 119,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 119
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 105
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 23,
                        "start_line": 118
                    }
                },
                "26": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 47,
                        "end_line": 119,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 26,
                        "start_line": 119
                    }
                },
                "27": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 73,
                        "end_line": 119,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 57,
                        "start_line": 119
                    }
                },
                "28": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 74,
                        "end_line": 119,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 119
                    }
                },
                "29": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.get_caller_address"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 90,
                        "end_line": 198,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 63,
                        "start_line": 198
                    }
                },
                "31": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.get_caller_address"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 91,
                        "end_line": 198,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 198
                    }
                },
                "32": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.get_caller_address"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 93,
                                "end_line": 199,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "start_col": 5,
                                "start_line": 199
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 58,
                        "end_line": 200,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 44,
                                "end_line": 196,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 60,
                                        "end_line": 201,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 201
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 25,
                                "start_line": 196
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 23,
                        "start_line": 200
                    }
                },
                "34": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.get_caller_address"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 201,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 28,
                        "start_line": 201
                    }
                },
                "35": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.get_caller_address"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 60,
                        "end_line": 201,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 201
                    }
                },
                "36": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 79,
                        "end_line": 350,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 58,
                        "start_line": 350
                    }
                },
                "38": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 97,
                        "end_line": 350,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 350
                    }
                },
                "39": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 97,
                        "end_line": 350,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 350
                    }
                },
                "40": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 87,
                                "end_line": 351,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "start_col": 5,
                                "start_line": 351
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 53,
                        "end_line": 353,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 38,
                                "end_line": 348,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 34,
                                        "end_line": 354,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 354
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 19,
                                "start_line": 348
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 23,
                        "start_line": 353
                    }
                },
                "42": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 33,
                        "end_line": 354,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 19,
                        "start_line": 354
                    }
                },
                "43": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 354,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 354
                    }
                },
                "44": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 368,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 18,
                        "start_line": 368
                    }
                },
                "46": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 368,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 367
                    }
                },
                "47": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 368,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 367
                    }
                },
                "48": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 368,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 367
                    }
                },
                "49": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 88,
                                "end_line": 369,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "start_col": 5,
                                "start_line": 369
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 54,
                        "end_line": 370,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 366,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 14,
                                        "end_line": 371,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 371
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 20,
                                "start_line": 366
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 23,
                        "start_line": 370
                    }
                },
                "51": {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 14,
                        "end_line": 371,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "start_col": 5,
                        "start_line": 371
                    }
                },
                "52": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 8,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 44,
                                "end_line": 196,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 40,
                                        "end_line": 10,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                        },
                                        "start_col": 20,
                                        "start_line": 10
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 25,
                                "start_line": 196
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 8
                    }
                },
                "53": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 10,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 20,
                        "start_line": 10
                    }
                },
                "55": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 33,
                        "end_line": 12,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 5,
                        "start_line": 12
                    }
                },
                "56": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 196,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 40,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 348,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 48,
                                                "end_line": 14,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 19,
                                                "start_line": 14
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 19,
                                        "start_line": 348
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 20,
                                "start_line": 10
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 25,
                        "start_line": 196
                    }
                },
                "57": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 9,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 47,
                                "end_line": 14,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 40,
                                "start_line": 14
                            },
                            "While expanding the reference 'address' in:"
                        ],
                        "start_col": 28,
                        "start_line": 9
                    }
                },
                "58": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 48,
                        "end_line": 14,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 19,
                        "start_line": 14
                    }
                },
                "60": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 25,
                        "end_line": 16,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 5,
                        "start_line": 16
                    }
                },
                "61": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 38,
                                "end_line": 3,
                                "input_file": {
                                    "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 23,
                                        "end_line": 7,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 7
                                    },
                                    "While handling return value of"
                                ],
                                "start_col": 5,
                                "start_line": 3
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 17,
                        "end_line": 4,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While handling return value of"
                        ],
                        "start_col": 5,
                        "start_line": 4
                    }
                },
                "63": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 46,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/b4624eb8c064253bb9f369af6ce6318d5524fdc6f4a5bc691024240ed9a1ef38.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 60,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 48,
                                "start_line": 9
                            },
                            "While handling return value 'value'"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "64": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 48,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/b4624eb8c064253bb9f369af6ce6318d5524fdc6f4a5bc691024240ed9a1ef38.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 60,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 11,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 18,
                                        "start_line": 11
                                    },
                                    "While expanding the reference '__return_value_ptr' in:"
                                ],
                                "start_col": 48,
                                "start_line": 9
                            },
                            "While handling return value 'value'"
                        ],
                        "start_col": 26,
                        "start_line": 2
                    }
                },
                "66": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 81,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 40,
                                        "end_line": 10,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 25,
                                        "start_line": 10
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While handling return value of"
                        ],
                        "start_col": 66,
                        "start_line": 1
                    }
                },
                "67": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 11,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While handling return value of"
                        ],
                        "start_col": 18,
                        "start_line": 11
                    }
                },
                "68": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 5,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 12,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 14,
                                        "start_line": 12
                                    },
                                    "While expanding the reference '__return_value_ptr_start' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While handling return value of"
                        ],
                        "start_col": 11,
                        "start_line": 5
                    }
                },
                "69": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 39,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/auth_read_storage/9839ddddc6df03caada50d2d1a6af38cfb6362a4fcb492664c8cc955f5164d27.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While handling return value of"
                        ],
                        "start_col": 5,
                        "start_line": 9
                    }
                },
                "70": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/f3ea60531fda419d2c1917380b5b86465e39d0a2cca45fc716c484e7b3a124bd.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/arg_processor/5e1cc73f0b484f90bb02da164d88332b40c6f698801aa4d3c603dab22157e902.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "parent_location": [
                                                    {
                                                        "end_col": 57,
                                                        "end_line": 1,
                                                        "input_file": {
                                                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                                                        },
                                                        "parent_location": [
                                                            {
                                                                "end_col": 23,
                                                                "end_line": 7,
                                                                "input_file": {
                                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                                },
                                                                "start_col": 6,
                                                                "start_line": 7
                                                            },
                                                            "While handling calldata of"
                                                        ],
                                                        "start_col": 35,
                                                        "start_line": 1
                                                    },
                                                    "While expanding the reference '__calldata_actual_size' in:"
                                                ],
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While handling calldata of"
                                        ],
                                        "start_col": 31,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_ptr' in:"
                                ],
                                "start_col": 28,
                                "start_line": 9
                            },
                            "While handling calldata argument 'address'"
                        ],
                        "start_col": 22,
                        "start_line": 2
                    }
                },
                "72": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 57,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While handling calldata of"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "73": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 28,
                                "end_line": 8,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 8
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "74": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 51,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/14dadf397f89d02ccb0a8fc7bc4e0aff7bd21c30a2145f78cf811beaeba1512c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 26,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 97,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_auth_account' in:"
                                ],
                                "start_col": 7,
                                "start_line": 9
                            },
                            "While handling calldata argument 'auth_account'"
                        ],
                        "start_col": 35,
                        "start_line": 1
                    }
                },
                "75": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 46,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/f3ea60531fda419d2c1917380b5b86465e39d0a2cca45fc716c484e7b3a124bd.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 129,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 107,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_address' in:"
                                ],
                                "start_col": 28,
                                "start_line": 9
                            },
                            "While handling calldata argument 'address'"
                        ],
                        "start_col": 30,
                        "start_line": 1
                    }
                },
                "76": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 23,
                        "end_line": 7,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 6,
                        "start_line": 7
                    }
                },
                "78": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 106,
                                        "end_line": 2,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 91,
                                        "start_line": 2
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "79": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 107,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 48,
                        "start_line": 2
                    }
                },
                "81": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 44,
                        "start_line": 1
                    }
                },
                "82": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/6629798b6d541e54a9dc778ffa54e7ef20b4f98b088671dd5070b7e0b547f0e6.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 21,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "83": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 34,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 6,
                        "start_line": 2
                    }
                },
                "84": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 50,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata_size' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 2
                    }
                },
                "85": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/14137eec0cbe7cbed6ec7116208e85979543b1181883794519ad26e84d29b209.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 23,
                                                "end_line": 7,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 7
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 63,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata' in:"
                                ],
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 37,
                        "start_line": 2
                    }
                },
                "86": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_read_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 23,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 7
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "87": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 21,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 44,
                                "end_line": 196,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 40,
                                        "end_line": 23,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                        },
                                        "start_col": 20,
                                        "start_line": 23
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 25,
                                "start_line": 196
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 21
                    }
                },
                "88": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 23,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 20,
                        "start_line": 23
                    }
                },
                "90": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 33,
                        "end_line": 25,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 5,
                        "start_line": 25
                    }
                },
                "91": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 196,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 40,
                                "end_line": 23,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 39,
                                        "end_line": 366,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 48,
                                                "end_line": 27,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 27
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 20,
                                        "start_line": 366
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 20,
                                "start_line": 23
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 25,
                        "start_line": 196
                    }
                },
                "92": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 22,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 34,
                                "end_line": 27,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 27,
                                "start_line": 27
                            },
                            "While expanding the reference 'address' in:"
                        ],
                        "start_col": 28,
                        "start_line": 22
                    }
                },
                "93": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 56,
                        "end_line": 22,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 47,
                                "end_line": 27,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 42,
                                "start_line": 27
                            },
                            "While expanding the reference 'value' in:"
                        ],
                        "start_col": 44,
                        "start_line": 22
                    }
                },
                "94": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 48,
                        "end_line": 27,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 5,
                        "start_line": 27
                    }
                },
                "96": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "utils.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 13,
                        "end_line": 28,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 5,
                        "start_line": 28
                    }
                },
                "97": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/fc42d727d94c768e43778d12b1fd9241d795ce55b227b746a3ae311d5894c21a.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 56,
                                "end_line": 22,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/arg_processor/5e1cc73f0b484f90bb02da164d88332b40c6f698801aa4d3c603dab22157e902.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "parent_location": [
                                                    {
                                                        "end_col": 57,
                                                        "end_line": 1,
                                                        "input_file": {
                                                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                                                        },
                                                        "parent_location": [
                                                            {
                                                                "end_col": 24,
                                                                "end_line": 20,
                                                                "input_file": {
                                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                                },
                                                                "start_col": 6,
                                                                "start_line": 20
                                                            },
                                                            "While handling calldata of"
                                                        ],
                                                        "start_col": 35,
                                                        "start_line": 1
                                                    },
                                                    "While expanding the reference '__calldata_actual_size' in:"
                                                ],
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While handling calldata of"
                                        ],
                                        "start_col": 31,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 22
                            },
                            "While handling calldata argument 'value'"
                        ],
                        "start_col": 22,
                        "start_line": 2
                    }
                },
                "99": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 57,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While handling calldata of"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "100": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 28,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 21
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "101": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 51,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/14dadf397f89d02ccb0a8fc7bc4e0aff7bd21c30a2145f78cf811beaeba1512c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 26,
                                "end_line": 22,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 97,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_auth_account' in:"
                                ],
                                "start_col": 7,
                                "start_line": 22
                            },
                            "While handling calldata argument 'auth_account'"
                        ],
                        "start_col": 35,
                        "start_line": 1
                    }
                },
                "102": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 46,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/f3ea60531fda419d2c1917380b5b86465e39d0a2cca45fc716c484e7b3a124bd.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 22,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 129,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 107,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_address' in:"
                                ],
                                "start_col": 28,
                                "start_line": 22
                            },
                            "While handling calldata argument 'address'"
                        ],
                        "start_col": 30,
                        "start_line": 1
                    }
                },
                "103": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/fc42d727d94c768e43778d12b1fd9241d795ce55b227b746a3ae311d5894c21a.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 56,
                                "end_line": 22,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 157,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 137,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_value' in:"
                                ],
                                "start_col": 44,
                                "start_line": 22
                            },
                            "While handling calldata argument 'value'"
                        ],
                        "start_col": 28,
                        "start_line": 1
                    }
                },
                "104": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 20,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "start_col": 6,
                        "start_line": 20
                    }
                },
                "106": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 34,
                                "end_line": 2,
                                "input_file": {
                                    "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 24,
                                        "end_line": 20,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 20
                                    },
                                    "While constructing the external wrapper for:"
                                ],
                                "start_col": 1,
                                "start_line": 2
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 24,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 3
                    }
                },
                "108": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 44,
                        "start_line": 1
                    }
                },
                "109": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/6629798b6d541e54a9dc778ffa54e7ef20b4f98b088671dd5070b7e0b547f0e6.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 21,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "110": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 34,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "111": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 4,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 50,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata_size' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 4
                    }
                },
                "113": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 16,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/5be73263a535c817761dd9b944122f74294e1df94cca4cdf438c105cad658acf.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 24,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 63,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 9,
                        "start_line": 3
                    }
                },
                "114": {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/auth_write_storage/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "115": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 25,
                                        "end_line": 9,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 9,
                                        "start_line": 9
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 7
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "116": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 25,
                                        "end_line": 9,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 9,
                                        "start_line": 9
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 7
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "117": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 94,
                        "end_line": 8,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                },
                                "start_col": 21,
                                "start_line": 9
                            },
                            "While expanding the reference 'res' in:"
                        ],
                        "start_col": 19,
                        "start_line": 8
                    }
                },
                "119": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 25,
                        "end_line": 9,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 9
                    }
                },
                "120": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 7
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 36,
                        "start_line": 12
                    }
                },
                "121": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 7
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 65,
                        "start_line": 12
                    }
                },
                "122": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 36,
                        "end_line": 15,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "start_col": 30,
                        "start_line": 15
                    }
                },
                "124": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 38,
                                "end_line": 348,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 75,
                                        "end_line": 16,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 37,
                                        "start_line": 16
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 19,
                                "start_line": 348
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 12
                    }
                },
                "125": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 26,
                        "end_line": 15,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 70,
                                "end_line": 16,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                },
                                "start_col": 58,
                                "start_line": 16
                            },
                            "While expanding the reference 'storage_addr' in:"
                        ],
                        "start_col": 14,
                        "start_line": 15
                    }
                },
                "126": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 75,
                        "end_line": 16,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "start_col": 37,
                        "start_line": 16
                    }
                },
                "128": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 38,
                        "end_line": 348,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 75,
                                "end_line": 16,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 42,
                                        "end_line": 18,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 31,
                                        "start_line": 18
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 37,
                                "start_line": 16
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 19,
                        "start_line": 348
                    }
                },
                "129": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 15,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 44,
                                        "end_line": 19,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 32,
                                        "start_line": 19
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 15
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "130": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 15,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 50,
                                        "end_line": 20,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                        },
                                        "start_col": 35,
                                        "start_line": 20
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 15
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "131": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 33,
                        "end_line": 16,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 65,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                                },
                                "start_col": 46,
                                "start_line": 21
                            },
                            "While expanding the reference '__storage_var_temp0' in:"
                        ],
                        "start_col": 14,
                        "start_line": 16
                    }
                },
                "132": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.owner",
                        "__main__.owner.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 53,
                        "end_line": 22,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 22
                    }
                },
                "133": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 25,
                                        "end_line": 9,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 9,
                                        "start_line": 9
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 7
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "134": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 25,
                                        "end_line": 9,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 9,
                                        "start_line": 9
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 7
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "135": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 95,
                        "end_line": 8,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "start_col": 21,
                                "start_line": 9
                            },
                            "While expanding the reference 'res' in:"
                        ],
                        "start_col": 19,
                        "start_line": 8
                    }
                },
                "137": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 25,
                        "end_line": 9,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 9
                    }
                },
                "138": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 7
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 36,
                        "start_line": 12
                    }
                },
                "139": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 7
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 65,
                        "start_line": 12
                    }
                },
                "140": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 36,
                        "end_line": 15,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 30,
                        "start_line": 15
                    }
                },
                "142": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 38,
                                "end_line": 348,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 75,
                                        "end_line": 16,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 37,
                                        "start_line": 16
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 19,
                                "start_line": 348
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 12
                    }
                },
                "143": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 26,
                        "end_line": 15,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 70,
                                "end_line": 16,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "start_col": 58,
                                "start_line": 16
                            },
                            "While expanding the reference 'storage_addr' in:"
                        ],
                        "start_col": 14,
                        "start_line": 15
                    }
                },
                "144": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 75,
                        "end_line": 16,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 37,
                        "start_line": 16
                    }
                },
                "146": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 38,
                        "end_line": 348,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 75,
                                "end_line": 16,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 42,
                                        "end_line": 18,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 31,
                                        "start_line": 18
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 37,
                                "start_line": 16
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 19,
                        "start_line": 348
                    }
                },
                "147": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 15,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 44,
                                        "end_line": 19,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 32,
                                        "start_line": 19
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 15
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "148": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 15,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 50,
                                        "end_line": 20,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 35,
                                        "start_line": 20
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 15
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "149": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 33,
                        "end_line": 16,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 65,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "start_col": 46,
                                "start_line": 21
                            },
                            "While expanding the reference '__storage_var_temp0' in:"
                        ],
                        "start_col": 14,
                        "start_line": 16
                    }
                },
                "150": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 53,
                        "end_line": 22,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 22
                    }
                },
                "151": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 25,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 26,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 26
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 7
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 37,
                        "start_line": 25
                    }
                },
                "152": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 81,
                        "end_line": 25,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 26,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 26
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 7
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 66,
                        "start_line": 25
                    }
                },
                "153": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 36,
                        "end_line": 26,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 30,
                        "start_line": 26
                    }
                },
                "155": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 25,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 366,
                                "input_file": {
                                    "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 80,
                                        "end_line": 27,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                        },
                                        "start_col": 9,
                                        "start_line": 27
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 20,
                                "start_line": 366
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 16,
                        "start_line": 25
                    }
                },
                "156": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 26,
                        "end_line": 26,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 43,
                                "end_line": 27,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "start_col": 31,
                                "start_line": 27
                            },
                            "While expanding the reference 'storage_addr' in:"
                        ],
                        "start_col": 14,
                        "start_line": 26
                    }
                },
                "157": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 79,
                        "end_line": 27,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 55,
                        "start_line": 27
                    }
                },
                "158": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 27,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 27
                    }
                },
                "160": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 26,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 64,
                                        "end_line": 21,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 18,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                                },
                                                "start_col": 9,
                                                "start_line": 28
                                            },
                                            "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                        ],
                                        "start_col": 37,
                                        "start_line": 21
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 26
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "161": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 26,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 81,
                                        "end_line": 21,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 18,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                                                },
                                                "start_col": 9,
                                                "start_line": 28
                                            },
                                            "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                        ],
                                        "start_col": 66,
                                        "start_line": 21
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 26
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "162": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__.implementation",
                        "__main__.implementation.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 18,
                        "end_line": 28,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 28
                    }
                },
                "163": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 101,
                        "end_line": 17,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 31,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 21,
                                "start_line": 20
                            },
                            "While expanding the reference 'class_hash' in:"
                        ],
                        "start_col": 85,
                        "start_line": 17
                    }
                },
                "164": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 32,
                        "end_line": 20,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 20
                    }
                },
                "166": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 37,
                        "end_line": 17,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 35,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 37,
                                        "end_line": 21,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 21
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 16,
                                "start_line": 21
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 18,
                        "start_line": 17
                    }
                },
                "167": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 66,
                        "end_line": 17,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 64,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 37,
                                        "end_line": 21,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 21
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 37,
                                "start_line": 21
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 39,
                        "start_line": 17
                    }
                },
                "168": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 83,
                        "end_line": 17,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 81,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 37,
                                        "end_line": 21,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 21
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 66,
                                "start_line": 21
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 68,
                        "start_line": 17
                    }
                },
                "169": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 101,
                        "end_line": 17,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 26,
                                "start_line": 21
                            },
                            "While expanding the reference 'class_hash' in:"
                        ],
                        "start_col": 85,
                        "start_line": 17
                    }
                },
                "170": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 37,
                        "end_line": 21,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 21
                    }
                },
                "172": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 13,
                        "end_line": 23,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 23
                    }
                },
                "173": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/54a156e0167c228bb5d76d8c55e55e37a2b00e0a593e94e6ceb591bcf2576f95.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 101,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/arg_processor/5e1cc73f0b484f90bb02da164d88332b40c6f698801aa4d3c603dab22157e902.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "parent_location": [
                                                    {
                                                        "end_col": 57,
                                                        "end_line": 1,
                                                        "input_file": {
                                                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                                                        },
                                                        "parent_location": [
                                                            {
                                                                "end_col": 17,
                                                                "end_line": 17,
                                                                "input_file": {
                                                                    "filename": "contracts/proxy.cairo"
                                                                },
                                                                "start_col": 6,
                                                                "start_line": 17
                                                            },
                                                            "While handling calldata of"
                                                        ],
                                                        "start_col": 35,
                                                        "start_line": 1
                                                    },
                                                    "While expanding the reference '__calldata_actual_size' in:"
                                                ],
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While handling calldata of"
                                        ],
                                        "start_col": 31,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_ptr' in:"
                                ],
                                "start_col": 85,
                                "start_line": 17
                            },
                            "While handling calldata argument 'class_hash'"
                        ],
                        "start_col": 22,
                        "start_line": 2
                    }
                },
                "175": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 57,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While handling calldata of"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "176": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 37,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 18,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "177": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 110,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 66,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 82,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 39,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "178": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 83,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 115,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 100,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 68,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "179": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 49,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/54a156e0167c228bb5d76d8c55e55e37a2b00e0a593e94e6ceb591bcf2576f95.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 101,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 153,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 128,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_class_hash' in:"
                                ],
                                "start_col": 85,
                                "start_line": 17
                            },
                            "While handling calldata argument 'class_hash'"
                        ],
                        "start_col": 33,
                        "start_line": 1
                    }
                },
                "180": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 17,
                        "end_line": 17,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 6,
                        "start_line": 17
                    }
                },
                "182": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 34,
                                "end_line": 2,
                                "input_file": {
                                    "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 17,
                                        "end_line": 17,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 17
                                    },
                                    "While constructing the external wrapper for:"
                                ],
                                "start_col": 1,
                                "start_line": 2
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 24,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 3
                    }
                },
                "184": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 44,
                        "start_line": 1
                    }
                },
                "185": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 82,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 21,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 70,
                        "start_line": 1
                    }
                },
                "186": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 115,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 34,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 100,
                        "start_line": 1
                    }
                },
                "187": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 4,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 50,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata_size' in:"
                                ],
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 4
                    }
                },
                "189": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 16,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/3fbec4857b14784684418235f5d34e0304b3148d0c0e50d88a5ce5f926d294ab.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 17,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 17
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 63,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata' in:"
                                ],
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 9,
                        "start_line": 3
                    }
                },
                "190": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/constructor/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 17,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 17
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "191": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 29,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 34,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 39,
                                        "end_line": 33,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 27,
                                        "start_line": 33
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 13
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 29
                    }
                },
                "192": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 36,
                        "end_line": 30,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 63,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 39,
                                        "end_line": 33,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 27,
                                        "start_line": 33
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 36,
                                "start_line": 13
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 30
                    }
                },
                "193": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 31,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 80,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 39,
                                        "end_line": 33,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 27,
                                        "start_line": 33
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 65,
                                "start_line": 13
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 31
                    }
                },
                "194": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 39,
                        "end_line": 33,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 27,
                        "start_line": 33
                    }
                },
                "196": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 33,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 28,
                                        "end_line": 8,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 60,
                                                "end_line": 34,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 19,
                                                "start_line": 34
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 8
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 27,
                                "start_line": 33
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 13
                    }
                },
                "197": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 23,
                        "end_line": 33,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 50,
                                "end_line": 34,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 37,
                                "start_line": 34
                            },
                            "While expanding the reference 'owner_account' in:"
                        ],
                        "start_col": 10,
                        "start_line": 33
                    }
                },
                "198": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 32,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 34,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 52,
                                "start_line": 34
                            },
                            "While expanding the reference 'address' in:"
                        ],
                        "start_col": 7,
                        "start_line": 32
                    }
                },
                "199": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 60,
                        "end_line": 34,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 19,
                        "start_line": 34
                    }
                },
                "201": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 8,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/cairo-paradigm-ctf/contracts/utils.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 60,
                                "end_line": 34,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 28,
                                        "end_line": 29,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 19,
                                                "end_line": 35,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 35
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 29
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 19,
                                "start_line": 34
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 8
                    }
                },
                "202": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 33,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 30,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 19,
                                                "end_line": 35,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 35
                                            },
                                            "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 30
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 27,
                                "start_line": 33
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 36,
                        "start_line": 13
                    }
                },
                "203": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/owner/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 33,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 24,
                                        "end_line": 31,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 19,
                                                "end_line": 35,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 35
                                            },
                                            "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 31
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 27,
                                "start_line": 33
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 65,
                        "start_line": 13
                    }
                },
                "204": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 15,
                        "end_line": 34,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 18,
                                "end_line": 35,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 13,
                                "start_line": 35
                            },
                            "While expanding the reference 'value' in:"
                        ],
                        "start_col": 10,
                        "start_line": 34
                    }
                },
                "205": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 19,
                        "end_line": 35,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 35
                    }
                },
                "206": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 38,
                                "end_line": 3,
                                "input_file": {
                                    "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 16,
                                        "end_line": 28,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 28
                                    },
                                    "While handling return value of"
                                ],
                                "start_col": 5,
                                "start_line": 3
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 17,
                        "end_line": 4,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While handling return value of"
                        ],
                        "start_col": 5,
                        "start_line": 4
                    }
                },
                "208": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 46,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/b4624eb8c064253bb9f369af6ce6318d5524fdc6f4a5bc691024240ed9a1ef38.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 32,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 27,
                                "start_line": 32
                            },
                            "While handling return value 'value'"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "209": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 48,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/b4624eb8c064253bb9f369af6ce6318d5524fdc6f4a5bc691024240ed9a1ef38.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 39,
                                "end_line": 32,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 11,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 18,
                                        "start_line": 11
                                    },
                                    "While expanding the reference '__return_value_ptr' in:"
                                ],
                                "start_col": 27,
                                "start_line": 32
                            },
                            "While handling return value 'value'"
                        ],
                        "start_col": 26,
                        "start_line": 2
                    }
                },
                "211": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 74,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 40,
                                        "end_line": 10,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 25,
                                        "start_line": 10
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While handling return value of"
                        ],
                        "start_col": 59,
                        "start_line": 1
                    }
                },
                "212": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 11,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While handling return value of"
                        ],
                        "start_col": 18,
                        "start_line": 11
                    }
                },
                "213": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 5,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 12,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 14,
                                        "start_line": 12
                                    },
                                    "While expanding the reference '__return_value_ptr_start' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While handling return value of"
                        ],
                        "start_col": 11,
                        "start_line": 5
                    }
                },
                "214": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 39,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/read_state/24ba5aa5e3ec00057f280d160b0c07dcff6951b9efecf6dd389ddb6d36930ee7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While handling return value of"
                        ],
                        "start_col": 5,
                        "start_line": 9
                    }
                },
                "215": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/f3ea60531fda419d2c1917380b5b86465e39d0a2cca45fc716c484e7b3a124bd.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 21,
                                "end_line": 32,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/arg_processor/5e1cc73f0b484f90bb02da164d88332b40c6f698801aa4d3c603dab22157e902.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "parent_location": [
                                                    {
                                                        "end_col": 57,
                                                        "end_line": 1,
                                                        "input_file": {
                                                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                                                        },
                                                        "parent_location": [
                                                            {
                                                                "end_col": 16,
                                                                "end_line": 28,
                                                                "input_file": {
                                                                    "filename": "contracts/proxy.cairo"
                                                                },
                                                                "start_col": 6,
                                                                "start_line": 28
                                                            },
                                                            "While handling calldata of"
                                                        ],
                                                        "start_col": 35,
                                                        "start_line": 1
                                                    },
                                                    "While expanding the reference '__calldata_actual_size' in:"
                                                ],
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While handling calldata of"
                                        ],
                                        "start_col": 31,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_ptr' in:"
                                ],
                                "start_col": 7,
                                "start_line": 32
                            },
                            "While handling calldata argument 'address'"
                        ],
                        "start_col": 22,
                        "start_line": 2
                    }
                },
                "217": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 57,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While handling calldata of"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "218": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 28,
                                "end_line": 29,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 29
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "219": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 110,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 30,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 82,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 30
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "220": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 31,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 115,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 100,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 31
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "221": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 46,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/f3ea60531fda419d2c1917380b5b86465e39d0a2cca45fc716c484e7b3a124bd.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 21,
                                "end_line": 32,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 147,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 125,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_address' in:"
                                ],
                                "start_col": 7,
                                "start_line": 32
                            },
                            "While handling calldata argument 'address'"
                        ],
                        "start_col": 30,
                        "start_line": 1
                    }
                },
                "222": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 16,
                        "end_line": 28,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 6,
                        "start_line": 28
                    }
                },
                "224": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 115,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 99,
                                        "end_line": 2,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 84,
                                        "start_line": 2
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 100,
                        "start_line": 1
                    }
                },
                "225": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 100,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 48,
                        "start_line": 2
                    }
                },
                "227": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 44,
                        "start_line": 1
                    }
                },
                "228": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 82,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 21,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 70,
                        "start_line": 1
                    }
                },
                "229": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 34,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 6,
                        "start_line": 2
                    }
                },
                "230": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 50,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata_size' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 2
                    }
                },
                "231": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/8e880058dab779a2744baa3dde7d58eb757adc6dfb9e5b557b73ab02f902bc98.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 16,
                                                "end_line": 28,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 28
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 63,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata' in:"
                                ],
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 37,
                        "start_line": 2
                    }
                },
                "232": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/read_state/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 16,
                                "end_line": 28,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 28
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "233": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 45,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 34,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 56,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 24,
                                        "start_line": 56
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 13
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 45
                    }
                },
                "234": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 46,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 63,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 56,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 24,
                                        "start_line": 56
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 36,
                                "start_line": 13
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 46
                    }
                },
                "235": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 47,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 80,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 56,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 24,
                                        "start_line": 56
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 65,
                                "start_line": 13
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 47
                    }
                },
                "236": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 45,
                        "end_line": 56,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 24,
                        "start_line": 56
                    }
                },
                "238": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 45,
                                "end_line": 56,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 84,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 6,
                                                "end_line": 62,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 48,
                                                "start_line": 57
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 19,
                                        "start_line": 84
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 24,
                                "start_line": 56
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 13
                    }
                },
                "239": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 20,
                        "end_line": 56,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 30,
                                "end_line": 58,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 20,
                                "start_line": 58
                            },
                            "While expanding the reference 'class_hash' in:"
                        ],
                        "start_col": 10,
                        "start_line": 56
                    }
                },
                "240": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 23,
                        "end_line": 49,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 35,
                                "end_line": 59,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 27,
                                "start_line": 59
                            },
                            "While expanding the reference 'selector' in:"
                        ],
                        "start_col": 9,
                        "start_line": 49
                    }
                },
                "241": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 50,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 60,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 23,
                                "start_line": 60
                            },
                            "While expanding the reference 'calldata_size' in:"
                        ],
                        "start_col": 9,
                        "start_line": 50
                    }
                },
                "242": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 51,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 26,
                                "end_line": 61,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 18,
                                "start_line": 61
                            },
                            "While expanding the reference 'calldata' in:"
                        ],
                        "start_col": 9,
                        "start_line": 51
                    }
                },
                "243": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 6,
                        "end_line": 62,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 48,
                        "start_line": 57
                    }
                },
                "245": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 38,
                        "end_line": 84,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 6,
                                "end_line": 62,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 27,
                                        "end_line": 45,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 56,
                                                "end_line": 64,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 64
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 45
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 48,
                                "start_line": 57
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 19,
                        "start_line": 84
                    }
                },
                "246": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 45,
                                "end_line": 56,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 35,
                                        "end_line": 46,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 56,
                                                "end_line": 64,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 64
                                            },
                                            "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 46
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 24,
                                "start_line": 56
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 36,
                        "start_line": 13
                    }
                },
                "247": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 45,
                                "end_line": 56,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 24,
                                        "end_line": 47,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 56,
                                                "end_line": 64,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 64
                                            },
                                            "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 47
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 24,
                                "start_line": 56
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 65,
                        "start_line": 13
                    }
                },
                "248": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 57,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 38,
                                "end_line": 64,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 26,
                                "start_line": 64
                            },
                            "While expanding the reference 'retdata_size' in:"
                        ],
                        "start_col": 10,
                        "start_line": 57
                    }
                },
                "249": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 57,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 55,
                                "end_line": 64,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 48,
                                "start_line": 64
                            },
                            "While expanding the reference 'retdata' in:"
                        ],
                        "start_col": 30,
                        "start_line": 57
                    }
                },
                "250": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 56,
                        "end_line": 64,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 64
                    }
                },
                "251": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 27,
                                "end_line": 45,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 44,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 44
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 45
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "252": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 110,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 35,
                                "end_line": 46,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 82,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 44,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 44
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 46
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "253": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 47,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 115,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 17,
                                                "end_line": 44,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 44
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 100,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 47
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "254": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 150,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 44,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 44
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 126,
                        "start_line": 1
                    }
                },
                "255": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 190,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 44,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 44
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 166,
                        "start_line": 1
                    }
                },
                "256": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 226,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/594cfed774c45850575554a78093a7a27edf1e635eae6c967f967cde5f6d9051.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 44,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 44
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 201,
                        "start_line": 1
                    }
                },
                "257": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 17,
                        "end_line": 44,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 6,
                        "start_line": 44
                    }
                },
                "259": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 17,
                                "end_line": 44,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 44
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "260": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 27,
                        "end_line": 70,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 34,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 79,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 24,
                                        "start_line": 79
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 13
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 70
                    }
                },
                "261": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 71,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 63,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 79,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 24,
                                        "start_line": 79
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 36,
                                "start_line": 13
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 71
                    }
                },
                "262": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 72,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 80,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 45,
                                        "end_line": 79,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 24,
                                        "start_line": 79
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 65,
                                "start_line": 13
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 9,
                        "start_line": 72
                    }
                },
                "263": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 45,
                        "end_line": 79,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 24,
                        "start_line": 79
                    }
                },
                "265": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 45,
                                "end_line": 79,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 105,
                                        "input_file": {
                                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 6,
                                                "end_line": 85,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 80
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 30,
                                        "start_line": 105
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 24,
                                "start_line": 79
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 13
                    }
                },
                "266": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 20,
                        "end_line": 79,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 30,
                                "end_line": 81,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 20,
                                "start_line": 81
                            },
                            "While expanding the reference 'class_hash' in:"
                        ],
                        "start_col": 10,
                        "start_line": 79
                    }
                },
                "267": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 23,
                        "end_line": 74,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 35,
                                "end_line": 82,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 27,
                                "start_line": 82
                            },
                            "While expanding the reference 'selector' in:"
                        ],
                        "start_col": 9,
                        "start_line": 74
                    }
                },
                "268": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 28,
                        "end_line": 75,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 83,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 23,
                                "start_line": 83
                            },
                            "While expanding the reference 'calldata_size' in:"
                        ],
                        "start_col": 9,
                        "start_line": 75
                    }
                },
                "269": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 76,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 26,
                                "end_line": 84,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 18,
                                "start_line": 84
                            },
                            "While expanding the reference 'calldata' in:"
                        ],
                        "start_col": 9,
                        "start_line": 76
                    }
                },
                "270": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 6,
                        "end_line": 85,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 80
                    }
                },
                "272": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 49,
                        "end_line": 105,
                        "input_file": {
                            "filename": "/home/amanusk/Code/Cairo/riddle-of-the-shpinx/venv/lib/python3.8/site-packages/starkware/starknet/common/syscalls.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 6,
                                "end_line": 85,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 27,
                                        "end_line": 70,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 87,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 87
                                            },
                                            "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 70
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 5,
                                "start_line": 80
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 30,
                        "start_line": 105
                    }
                },
                "273": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 45,
                                "end_line": 79,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 35,
                                        "end_line": 71,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 87,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 87
                                            },
                                            "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 71
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 24,
                                "start_line": 79
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 36,
                        "start_line": 13
                    }
                },
                "274": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/implementation/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 45,
                                "end_line": 79,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 24,
                                        "end_line": 72,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 87,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 5,
                                                "start_line": 87
                                            },
                                            "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 72
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 24,
                                "start_line": 79
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 65,
                        "start_line": 13
                    }
                },
                "275": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 14,
                        "end_line": 87,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 5,
                        "start_line": 87
                    }
                },
                "276": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 27,
                                "end_line": 70,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 70
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "277": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 110,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 35,
                                "end_line": 71,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 82,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 71
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "278": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 72,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 115,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 100,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 72
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "279": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 150,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 126,
                        "start_line": 1
                    }
                },
                "280": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 190,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 166,
                        "start_line": 1
                    }
                },
                "281": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 226,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 201,
                        "start_line": 1
                    }
                },
                "282": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 20,
                        "end_line": 69,
                        "input_file": {
                            "filename": "contracts/proxy.cairo"
                        },
                        "start_col": 6,
                        "start_line": 69
                    }
                },
                "284": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 34,
                                "end_line": 2,
                                "input_file": {
                                    "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 69,
                                        "input_file": {
                                            "filename": "contracts/proxy.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 69
                                    },
                                    "While constructing the external wrapper for:"
                                ],
                                "start_col": 1,
                                "start_line": 2
                            },
                            "n_prefix_newlines": 0
                        }
                    ],
                    "inst": {
                        "end_col": 24,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 3
                    }
                },
                "286": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 44,
                        "start_line": 1
                    }
                },
                "287": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 82,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 21,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 70,
                        "start_line": 1
                    }
                },
                "288": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 115,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 34,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 100,
                        "start_line": 1
                    }
                },
                "289": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 4,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 50,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata_size' in:"
                                ],
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 4
                    }
                },
                "291": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 16,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/edca83f6d2313d62fb8cc1b3fc4ae490d3e5ba3c3ba97a11fef2fe0adc8ace24.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 20,
                                                "end_line": 69,
                                                "input_file": {
                                                    "filename": "contracts/proxy.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 69
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 63,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata' in:"
                                ],
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 9,
                        "start_line": 3
                    }
                },
                "292": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/__l1_default__/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 69,
                                "input_file": {
                                    "filename": "contracts/proxy.cairo"
                                },
                                "start_col": 6,
                                "start_line": 69
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                }
            }
        },
        "hints": {
            "0": [
                {
                    "accessible_scopes": [
                        "starkware.cairo.common.math",
                        "starkware.cairo.common.math.assert_not_zero"
                    ],
                    "code": "from starkware.cairo.common.math_utils import assert_integer\nassert_integer(ids.value)\nassert ids.value % PRIME != 0, f'assert_not_zero failed: {ids.value} = 0.'",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 0,
                            "offset": 0
                        },
                        "reference_ids": {
                            "starkware.cairo.common.math.assert_not_zero.value": 0
                        }
                    }
                }
            ],
            "12": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call"
                    ],
                    "code": "syscall_handler.library_call(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 1,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.library_call.syscall_ptr": 1
                        }
                    }
                }
            ],
            "24": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.library_call_l1_handler"
                    ],
                    "code": "syscall_handler.library_call_l1_handler(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 2,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.library_call_l1_handler.syscall_ptr": 2
                        }
                    }
                }
            ],
            "32": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.get_caller_address"
                    ],
                    "code": "syscall_handler.get_caller_address(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 3,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.get_caller_address.syscall_ptr": 3
                        }
                    }
                }
            ],
            "40": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "code": "syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 4,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.storage_read.syscall_ptr": 4
                        }
                    }
                }
            ],
            "49": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "code": "syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 5,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.storage_write.syscall_ptr": 5
                        }
                    }
                }
            ],
            "61": [
                {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_read_storage_encode_return"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 7,
                            "offset": 0
                        },
                        "reference_ids": {}
                    }
                }
            ],
            "106": [
                {
                    "accessible_scopes": [
                        "utils",
                        "utils",
                        "__wrappers__",
                        "__wrappers__.auth_write_storage"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 10,
                            "offset": 20
                        },
                        "reference_ids": {}
                    }
                }
            ],
            "182": [
                {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.constructor"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 17,
                            "offset": 32
                        },
                        "reference_ids": {}
                    }
                }
            ],
            "206": [
                {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.read_state_encode_return"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 19,
                            "offset": 0
                        },
                        "reference_ids": {}
                    }
                }
            ],
            "284": [
                {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.__l1_default__"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 24,
                            "offset": 45
                        },
                        "reference_ids": {}
                    }
                }
            ]
        },
        "identifiers": {
            "__main__.HashBuiltin": {
                "destination": "starkware.cairo.common.cairo_builtins.HashBuiltin",
                "type": "alias"
            },
            "__main__.__default__": {
                "decorators": [
                    "external",
                    "raw_input",
                    "raw_output"
                ],
                "pc": 233,
                "type": "function"
            },
            "__main__.__default__.Args": {
                "full_name": "__main__.__default__.Args",
                "members": {
                    "calldata": {
                        "cairo_type": "felt*",
                        "offset": 2
                    },
                    "calldata_size": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.__default__.ImplicitArgs": {
                "full_name": "__main__.__default__.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.__default__.Return": {
                "cairo_type": "(retdata_size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__main__.__default__.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.__l1_default__": {
                "decorators": [
                    "l1_handler",
                    "raw_input"
                ],
                "pc": 260,
                "type": "function"
            },
            "__main__.__l1_default__.Args": {
                "full_name": "__main__.__l1_default__.Args",
                "members": {
                    "calldata": {
                        "cairo_type": "felt*",
                        "offset": 2
                    },
                    "calldata_size": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.__l1_default__.ImplicitArgs": {
                "full_name": "__main__.__l1_default__.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.__l1_default__.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__.__l1_default__.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.assert_not_zero": {
                "destination": "starkware.cairo.common.math.assert_not_zero",
                "type": "alias"
            },
            "__main__.auth_read_storage": {
                "destination": "utils.auth_read_storage",
                "type": "alias"
            },
            "__main__.constructor": {
                "decorators": [
                    "constructor"
                ],
                "pc": 163,
                "type": "function"
            },
            "__main__.constructor.Args": {
                "full_name": "__main__.constructor.Args",
                "members": {
                    "class_hash": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "__main__.constructor.ImplicitArgs": {
                "full_name": "__main__.constructor.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.constructor.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__.constructor.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.implementation": {
                "type": "namespace"
            },
            "__main__.implementation.Args": {
                "full_name": "__main__.implementation.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.implementation.HashBuiltin": {
                "destination": "starkware.cairo.common.cairo_builtins.HashBuiltin",
                "type": "alias"
            },
            "__main__.implementation.ImplicitArgs": {
                "full_name": "__main__.implementation.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.implementation.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__.implementation.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.implementation.addr": {
                "decorators": [],
                "pc": 133,
                "type": "function"
            },
            "__main__.implementation.addr.Args": {
                "full_name": "__main__.implementation.addr.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.implementation.addr.ImplicitArgs": {
                "full_name": "__main__.implementation.addr.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 0
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "__main__.implementation.addr.Return": {
                "cairo_type": "(res : felt)",
                "type": "type_definition"
            },
            "__main__.implementation.addr.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.implementation.hash2": {
                "destination": "starkware.cairo.common.hash.hash2",
                "type": "alias"
            },
            "__main__.implementation.normalize_address": {
                "destination": "starkware.starknet.common.storage.normalize_address",
                "type": "alias"
            },
            "__main__.implementation.read": {
                "decorators": [],
                "pc": 138,
                "type": "function"
            },
            "__main__.implementation.read.Args": {
                "full_name": "__main__.implementation.read.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.implementation.read.ImplicitArgs": {
                "full_name": "__main__.implementation.read.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.implementation.read.Return": {
                "cairo_type": "(class_hash : felt)",
                "type": "type_definition"
            },
            "__main__.implementation.read.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.implementation.storage_read": {
                "destination": "starkware.starknet.common.syscalls.storage_read",
                "type": "alias"
            },
            "__main__.implementation.storage_write": {
                "destination": "starkware.starknet.common.syscalls.storage_write",
                "type": "alias"
            },
            "__main__.implementation.write": {
                "decorators": [],
                "pc": 151,
                "type": "function"
            },
            "__main__.implementation.write.Args": {
                "full_name": "__main__.implementation.write.Args",
                "members": {
                    "value": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "__main__.implementation.write.ImplicitArgs": {
                "full_name": "__main__.implementation.write.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.implementation.write.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__.implementation.write.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.library_call": {
                "destination": "starkware.starknet.common.syscalls.library_call",
                "type": "alias"
            },
            "__main__.library_call_l1_handler": {
                "destination": "starkware.starknet.common.syscalls.library_call_l1_handler",
                "type": "alias"
            },
            "__main__.owner": {
                "type": "namespace"
            },
            "__main__.owner.Args": {
                "full_name": "__main__.owner.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.owner.HashBuiltin": {
                "destination": "starkware.cairo.common.cairo_builtins.HashBuiltin",
                "type": "alias"
            },
            "__main__.owner.ImplicitArgs": {
                "full_name": "__main__.owner.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.owner.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__.owner.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.owner.addr": {
                "decorators": [],
                "pc": 115,
                "type": "function"
            },
            "__main__.owner.addr.Args": {
                "full_name": "__main__.owner.addr.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.owner.addr.ImplicitArgs": {
                "full_name": "__main__.owner.addr.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 0
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "__main__.owner.addr.Return": {
                "cairo_type": "(res : felt)",
                "type": "type_definition"
            },
            "__main__.owner.addr.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.owner.hash2": {
                "destination": "starkware.cairo.common.hash.hash2",
                "type": "alias"
            },
            "__main__.owner.normalize_address": {
                "destination": "starkware.starknet.common.storage.normalize_address",
                "type": "alias"
            },
            "__main__.owner.read": {
                "decorators": [],
                "pc": 120,
                "type": "function"
            },
            "__main__.owner.read.Args": {
                "full_name": "__main__.owner.read.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.owner.read.ImplicitArgs": {
                "full_name": "__main__.owner.read.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.owner.read.Return": {
                "cairo_type": "(owner : felt)",
                "type": "type_definition"
            },
            "__main__.owner.read.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.owner.storage_read": {
                "destination": "starkware.starknet.common.syscalls.storage_read",
                "type": "alias"
            },
            "__main__.owner.storage_write": {
                "destination": "starkware.starknet.common.syscalls.storage_write",
                "type": "alias"
            },
            "__main__.read_state": {
                "decorators": [
                    "view"
                ],
                "pc": 191,
                "type": "function"
            },
            "__main__.read_state.Args": {
                "full_name": "__main__.read_state.Args",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "__main__.read_state.ImplicitArgs": {
                "full_name": "__main__.read_state.ImplicitArgs",
                "members": {
                    "pedersen_ptr": {
                        "cairo_type": "starkware.cairo.common.cairo_builtins.HashBuiltin*",
                        "offset": 1
                    },
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "__main__.read_state.Return": {
                "cairo_type": "(value : felt)",
                "type": "type_definition"
            },
            "__main__.read_state.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.__default__": {
                "decorators": [
                    "external",
                    "raw_input",
                    "raw_output"
                ],
                "pc": 251,
                "type": "function"
            },
            "__wrappers__.__default__.Args": {
                "full_name": "__wrappers__.__default__.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.__default__.ImplicitArgs": {
                "full_name": "__wrappers__.__default__.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.__default__.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.__default__.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.__default__.__wrapped_func": {
                "destination": "__main__.__default__",
                "type": "alias"
            },
            "__wrappers__.__default___encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "__wrappers__.__l1_default__": {
                "decorators": [
                    "l1_handler",
                    "raw_input"
                ],
                "pc": 276,
                "type": "function"
            },
            "__wrappers__.__l1_default__.Args": {
                "full_name": "__wrappers__.__l1_default__.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.__l1_default__.ImplicitArgs": {
                "full_name": "__wrappers__.__l1_default__.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.__l1_default__.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.__l1_default__.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.__l1_default__.__wrapped_func": {
                "destination": "__main__.__l1_default__",
                "type": "alias"
            },
            "__wrappers__.__l1_default___encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "__wrappers__.auth_read_storage": {
                "decorators": [
                    "view"
                ],
                "pc": 70,
                "type": "function"
            },
            "__wrappers__.auth_read_storage.Args": {
                "full_name": "__wrappers__.auth_read_storage.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.auth_read_storage.ImplicitArgs": {
                "full_name": "__wrappers__.auth_read_storage.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.auth_read_storage.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : felt, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.auth_read_storage.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.auth_read_storage.__wrapped_func": {
                "destination": "utils.auth_read_storage",
                "type": "alias"
            },
            "__wrappers__.auth_read_storage_encode_return": {
                "decorators": [],
                "pc": 61,
                "type": "function"
            },
            "__wrappers__.auth_read_storage_encode_return.Args": {
                "full_name": "__wrappers__.auth_read_storage_encode_return.Args",
                "members": {
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "ret_value": {
                        "cairo_type": "(value : felt)",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "__wrappers__.auth_read_storage_encode_return.ImplicitArgs": {
                "full_name": "__wrappers__.auth_read_storage_encode_return.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.auth_read_storage_encode_return.Return": {
                "cairo_type": "(range_check_ptr : felt, data_len : felt, data : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.auth_read_storage_encode_return.SIZEOF_LOCALS": {
                "type": "const",
                "value": 1
            },
            "__wrappers__.auth_read_storage_encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "__wrappers__.auth_write_storage": {
                "decorators": [
                    "external"
                ],
                "pc": 97,
                "type": "function"
            },
            "__wrappers__.auth_write_storage.Args": {
                "full_name": "__wrappers__.auth_write_storage.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.auth_write_storage.ImplicitArgs": {
                "full_name": "__wrappers__.auth_write_storage.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.auth_write_storage.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : felt, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.auth_write_storage.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.auth_write_storage.__wrapped_func": {
                "destination": "utils.auth_write_storage",
                "type": "alias"
            },
            "__wrappers__.auth_write_storage_encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "__wrappers__.constructor": {
                "decorators": [
                    "constructor"
                ],
                "pc": 173,
                "type": "function"
            },
            "__wrappers__.constructor.Args": {
                "full_name": "__wrappers__.constructor.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.constructor.ImplicitArgs": {
                "full_name": "__wrappers__.constructor.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.constructor.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.constructor.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.constructor.__wrapped_func": {
                "destination": "__main__.constructor",
                "type": "alias"
            },
            "__wrappers__.constructor_encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "__wrappers__.read_state": {
                "decorators": [
                    "view"
                ],
                "pc": 215,
                "type": "function"
            },
            "__wrappers__.read_state.Args": {
                "full_name": "__wrappers__.read_state.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.read_state.ImplicitArgs": {
                "full_name": "__wrappers__.read_state.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.read_state.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.read_state.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.read_state.__wrapped_func": {
                "destination": "__main__.read_state",
                "type": "alias"
            },
            "__wrappers__.read_state_encode_return": {
                "decorators": [],
                "pc": 206,
                "type": "function"
            },
            "__wrappers__.read_state_encode_return.Args": {
                "full_name": "__wrappers__.read_state_encode_return.Args",
                "members": {
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "ret_value": {
                        "cairo_type": "(value : felt)",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "__wrappers__.read_state_encode_return.ImplicitArgs": {
                "full_name": "__wrappers__.read_state_encode_return.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.read_state_encode_return.Return": {
                "cairo_type": "(range_check_ptr : felt, data_len : felt, data : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.read_state_encode_return.SIZEOF_LOCALS": {
                "type": "const",
                "value": 1
            },
            "__wrappers__.read_state_encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "starkware.cairo.common.cairo_builtins.BitwiseBuiltin": {
                "full_name": "starkware.cairo.common.cairo_builtins.BitwiseBuiltin",
                "members": {
                    "x": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "x_and_y": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "x_or_y": {
                        "cairo_type": "felt",
                        "offset": 4
                    },
                    "x_xor_y": {
                        "cairo_type": "felt",
                        "offset": 3
                    },
                    "y": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 5,
                "type": "struct"
            },
            "starkware.cairo.common.cairo_builtins.EcOpBuiltin": {
                "full_name": "starkware.cairo.common.cairo_builtins.EcOpBuiltin",
                "members": {
                    "m": {
                        "cairo_type": "felt",
                        "offset": 4
                    },
                    "p": {
                        "cairo_type": "starkware.cairo.common.ec_point.EcPoint",
                        "offset": 0
                    },
                    "q": {
                        "cairo_type": "starkware.cairo.common.ec_point.EcPoint",
                        "offset": 2
                    },
                    "r": {
                        "cairo_type": "starkware.cairo.common.ec_point.EcPoint",
                        "offset": 5
                    }
                },
                "size": 7,
                "type": "struct"
            },
            "starkware.cairo.common.cairo_builtins.EcPoint": {
                "destination": "starkware.cairo.common.ec_point.EcPoint",
                "type": "alias"
            },
            "starkware.cairo.common.cairo_builtins.HashBuiltin": {
                "full_name": "starkware.cairo.common.cairo_builtins.HashBuiltin",
                "members": {
                    "result": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "x": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "y": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "starkware.cairo.common.cairo_builtins.SignatureBuiltin": {
                "full_name": "starkware.cairo.common.cairo_builtins.SignatureBuiltin",
                "members": {
                    "message": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "pub_key": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.cairo.common.dict_access.DictAccess": {
                "full_name": "starkware.cairo.common.dict_access.DictAccess",
                "members": {
                    "key": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "new_value": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "prev_value": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "starkware.cairo.common.ec_point.EcPoint": {
                "full_name": "starkware.cairo.common.ec_point.EcPoint",
                "members": {
                    "x": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "y": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.cairo.common.hash.HashBuiltin": {
                "destination": "starkware.cairo.common.cairo_builtins.HashBuiltin",
                "type": "alias"
            },
            "starkware.cairo.common.math.assert_not_zero": {
                "decorators": [],
                "pc": 0,
                "type": "function"
            },
            "starkware.cairo.common.math.assert_not_zero.Args": {
                "full_name": "starkware.cairo.common.math.assert_not_zero.Args",
                "members": {
                    "value": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.cairo.common.math.assert_not_zero.ImplicitArgs": {
                "full_name": "starkware.cairo.common.math.assert_not_zero.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "starkware.cairo.common.math.assert_not_zero.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "starkware.cairo.common.math.assert_not_zero.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "starkware.cairo.common.math.assert_not_zero.value": {
                "cairo_type": "felt",
                "full_name": "starkware.cairo.common.math.assert_not_zero.value",
                "references": [
                    {
                        "ap_tracking_data": {
                            "group": 0,
                            "offset": 0
                        },
                        "pc": 0,
                        "value": "[cast(fp + (-3), felt*)]"
                    }
                ],
                "type": "reference"
            },
            "starkware.starknet.common.storage.ADDR_BOUND": {
                "type": "const",
                "value": -106710729501573572985208420194530329073740042555888586719489
            },
            "starkware.starknet.common.storage.MAX_STORAGE_ITEM_SIZE": {
                "type": "const",
                "value": 256
            },
            "starkware.starknet.common.storage.assert_250_bit": {
                "destination": "starkware.cairo.common.math.assert_250_bit",
                "type": "alias"
            },
            "starkware.starknet.common.syscalls.CALL_CONTRACT_SELECTOR": {
                "type": "const",
                "value": 20853273475220472486191784820
            },
            "starkware.starknet.common.syscalls.CallContract": {
                "full_name": "starkware.starknet.common.syscalls.CallContract",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.CallContractRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.CallContractResponse",
                        "offset": 5
                    }
                },
                "size": 7,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.CallContractRequest": {
                "full_name": "starkware.starknet.common.syscalls.CallContractRequest",
                "members": {
                    "calldata": {
                        "cairo_type": "felt*",
                        "offset": 4
                    },
                    "calldata_size": {
                        "cairo_type": "felt",
                        "offset": 3
                    },
                    "contract_address": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "function_selector": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 5,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.CallContractResponse": {
                "full_name": "starkware.starknet.common.syscalls.CallContractResponse",
                "members": {
                    "retdata": {
                        "cairo_type": "felt*",
                        "offset": 1
                    },
                    "retdata_size": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.DELEGATE_CALL_SELECTOR": {
                "type": "const",
                "value": 21167594061783206823196716140
            },
            "starkware.starknet.common.syscalls.DELEGATE_L1_HANDLER_SELECTOR": {
                "type": "const",
                "value": 23274015802972845247556842986379118667122
            },
            "starkware.starknet.common.syscalls.DEPLOY_SELECTOR": {
                "type": "const",
                "value": 75202468540281
            },
            "starkware.starknet.common.syscalls.Deploy": {
                "full_name": "starkware.starknet.common.syscalls.Deploy",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.DeployRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.DeployResponse",
                        "offset": 6
                    }
                },
                "size": 9,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.DeployRequest": {
                "full_name": "starkware.starknet.common.syscalls.DeployRequest",
                "members": {
                    "class_hash": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "constructor_calldata": {
                        "cairo_type": "felt*",
                        "offset": 4
                    },
                    "constructor_calldata_size": {
                        "cairo_type": "felt",
                        "offset": 3
                    },
                    "contract_address_salt": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "deploy_from_zero": {
                        "cairo_type": "felt",
                        "offset": 5
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 6,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.DeployResponse": {
                "full_name": "starkware.starknet.common.syscalls.DeployResponse",
                "members": {
                    "constructor_retdata": {
                        "cairo_type": "felt*",
                        "offset": 2
                    },
                    "constructor_retdata_size": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "contract_address": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.DictAccess": {
                "destination": "starkware.cairo.common.dict_access.DictAccess",
                "type": "alias"
            },
            "starkware.starknet.common.syscalls.EMIT_EVENT_SELECTOR": {
                "type": "const",
                "value": 1280709301550335749748
            },
            "starkware.starknet.common.syscalls.EmitEvent": {
                "full_name": "starkware.starknet.common.syscalls.EmitEvent",
                "members": {
                    "data": {
                        "cairo_type": "felt*",
                        "offset": 4
                    },
                    "data_len": {
                        "cairo_type": "felt",
                        "offset": 3
                    },
                    "keys": {
                        "cairo_type": "felt*",
                        "offset": 2
                    },
                    "keys_len": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 5,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GET_BLOCK_NUMBER_SELECTOR": {
                "type": "const",
                "value": 1448089106835523001438702345020786
            },
            "starkware.starknet.common.syscalls.GET_BLOCK_TIMESTAMP_SELECTOR": {
                "type": "const",
                "value": 24294903732626645868215235778792757751152
            },
            "starkware.starknet.common.syscalls.GET_CALLER_ADDRESS_SELECTOR": {
                "type": "const",
                "value": 94901967781393078444254803017658102643
            },
            "starkware.starknet.common.syscalls.GET_CONTRACT_ADDRESS_SELECTOR": {
                "type": "const",
                "value": 6219495360805491471215297013070624192820083
            },
            "starkware.starknet.common.syscalls.GET_SEQUENCER_ADDRESS_SELECTOR": {
                "type": "const",
                "value": 1592190833581991703053805829594610833820054387
            },
            "starkware.starknet.common.syscalls.GET_TX_INFO_SELECTOR": {
                "type": "const",
                "value": 1317029390204112103023
            },
            "starkware.starknet.common.syscalls.GET_TX_SIGNATURE_SELECTOR": {
                "type": "const",
                "value": 1448089128652340074717162277007973
            },
            "starkware.starknet.common.syscalls.GetBlockNumber": {
                "full_name": "starkware.starknet.common.syscalls.GetBlockNumber",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetBlockNumberRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetBlockNumberResponse",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetBlockNumberRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetBlockNumberRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetBlockNumberResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetBlockNumberResponse",
                "members": {
                    "block_number": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetBlockTimestamp": {
                "full_name": "starkware.starknet.common.syscalls.GetBlockTimestamp",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetBlockTimestampRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetBlockTimestampResponse",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetBlockTimestampRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetBlockTimestampRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetBlockTimestampResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetBlockTimestampResponse",
                "members": {
                    "block_timestamp": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetCallerAddress": {
                "full_name": "starkware.starknet.common.syscalls.GetCallerAddress",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetCallerAddressRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetCallerAddressResponse",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetCallerAddressRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetCallerAddressRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetCallerAddressResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetCallerAddressResponse",
                "members": {
                    "caller_address": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetContractAddress": {
                "full_name": "starkware.starknet.common.syscalls.GetContractAddress",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetContractAddressRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetContractAddressResponse",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetContractAddressRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetContractAddressRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetContractAddressResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetContractAddressResponse",
                "members": {
                    "contract_address": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetSequencerAddress": {
                "full_name": "starkware.starknet.common.syscalls.GetSequencerAddress",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetSequencerAddressRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetSequencerAddressResponse",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetSequencerAddressRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetSequencerAddressRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetSequencerAddressResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetSequencerAddressResponse",
                "members": {
                    "sequencer_address": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetTxInfo": {
                "full_name": "starkware.starknet.common.syscalls.GetTxInfo",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetTxInfoRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetTxInfoResponse",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetTxInfoRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetTxInfoRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetTxInfoResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetTxInfoResponse",
                "members": {
                    "tx_info": {
                        "cairo_type": "starkware.starknet.common.syscalls.TxInfo*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetTxSignature": {
                "full_name": "starkware.starknet.common.syscalls.GetTxSignature",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetTxSignatureRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.GetTxSignatureResponse",
                        "offset": 1
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetTxSignatureRequest": {
                "full_name": "starkware.starknet.common.syscalls.GetTxSignatureRequest",
                "members": {
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.GetTxSignatureResponse": {
                "full_name": "starkware.starknet.common.syscalls.GetTxSignatureResponse",
                "members": {
                    "signature": {
                        "cairo_type": "felt*",
                        "offset": 1
                    },
                    "signature_len": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.LIBRARY_CALL_L1_HANDLER_SELECTOR": {
                "type": "const",
                "value": 436233452754198157705746250789557519228244616562
            },
            "starkware.starknet.common.syscalls.LIBRARY_CALL_SELECTOR": {
                "type": "const",
                "value": 92376026794327011772951660
            },
            "starkware.starknet.common.syscalls.LibraryCall": {
                "full_name": "starkware.starknet.common.syscalls.LibraryCall",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.LibraryCallRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.CallContractResponse",
                        "offset": 5
                    }
                },
                "size": 7,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.LibraryCallRequest": {
                "full_name": "starkware.starknet.common.syscalls.LibraryCallRequest",
                "members": {
                    "calldata": {
                        "cairo_type": "felt*",
                        "offset": 4
                    },
                    "calldata_size": {
                        "cairo_type": "felt",
                        "offset": 3
                    },
                    "class_hash": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "function_selector": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 5,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.SEND_MESSAGE_TO_L1_SELECTOR": {
                "type": "const",
                "value": 433017908768303439907196859243777073
            },
            "starkware.starknet.common.syscalls.STORAGE_READ_SELECTOR": {
                "type": "const",
                "value": 100890693370601760042082660
            },
            "starkware.starknet.common.syscalls.STORAGE_WRITE_SELECTOR": {
                "type": "const",
                "value": 25828017502874050592466629733
            },
            "starkware.starknet.common.syscalls.SendMessageToL1SysCall": {
                "full_name": "starkware.starknet.common.syscalls.SendMessageToL1SysCall",
                "members": {
                    "payload_ptr": {
                        "cairo_type": "felt*",
                        "offset": 3
                    },
                    "payload_size": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "to_address": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 4,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.StorageRead": {
                "full_name": "starkware.starknet.common.syscalls.StorageRead",
                "members": {
                    "request": {
                        "cairo_type": "starkware.starknet.common.syscalls.StorageReadRequest",
                        "offset": 0
                    },
                    "response": {
                        "cairo_type": "starkware.starknet.common.syscalls.StorageReadResponse",
                        "offset": 2
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.StorageReadRequest": {
                "full_name": "starkware.starknet.common.syscalls.StorageReadRequest",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.StorageReadResponse": {
                "full_name": "starkware.starknet.common.syscalls.StorageReadResponse",
                "members": {
                    "value": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.StorageWrite": {
                "full_name": "starkware.starknet.common.syscalls.StorageWrite",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "selector": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "value": {
                        "cairo_type": "felt",
                        "offset": 2
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.TxInfo": {
                "full_name": "starkware.starknet.common.syscalls.TxInfo",
                "members": {
                    "account_contract_address": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "chain_id": {
                        "cairo_type": "felt",
                        "offset": 6
                    },
                    "max_fee": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "signature": {
                        "cairo_type": "felt*",
                        "offset": 4
                    },
                    "signature_len": {
                        "cairo_type": "felt",
                        "offset": 3
                    },
                    "transaction_hash": {
                        "cairo_type": "felt",
                        "offset": 5
                    },
                    "version": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 7,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.get_caller_address": {
                "decorators": [],
                "pc": 29,
                "type": "function"
            },
            "starkware.starknet.common.syscalls.get_caller_address.Args": {
                "full_name": "starkware.starknet.common.syscalls.get_caller_address.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.get_caller_address.ImplicitArgs": {
                "full_name": "starkware.starknet.common.syscalls.get_caller_address.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.get_caller_address.Return": {
                "cairo_type": "(caller_address : felt)",
                "type": "type_definition"
            },
            "starkware.starknet.common.syscalls.get_caller_address.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "starkware.starknet.common.syscalls.get_caller_address.syscall_ptr": {
                "cairo_type": "felt*",
                "full_name": "starkware.starknet.common.syscalls.get_caller_address.syscall_ptr",
                "references": [
                    {
                        "ap_tracking_data": {
                            "group": 3,
                            "offset": 0
                        },
                        "pc": 29,
                        "value": "[cast(fp + (-3), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 3,
                            "offset": 1
                        },
                        "pc": 32,
                        "value": "cast([fp + (-3)] + 2, felt*)"
                    }
                ],
                "type": "reference"
            },
            "starkware.starknet.common.syscalls.library_call": {
                "decorators": [],
                "pc": 5,
                "type": "function"
            },
            "starkware.starknet.common.syscalls.library_call.Args": {
                "full_name": "starkware.starknet.common.syscalls.library_call.Args",
                "members": {
                    "calldata": {
                        "cairo_type": "felt*",
                        "offset": 3
                    },
                    "calldata_size": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "class_hash": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "function_selector": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 4,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.library_call.ImplicitArgs": {
                "full_name": "starkware.starknet.common.syscalls.library_call.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.library_call.Return": {
                "cairo_type": "(retdata_size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "starkware.starknet.common.syscalls.library_call.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "starkware.starknet.common.syscalls.library_call.syscall_ptr": {
                "cairo_type": "felt*",
                "full_name": "starkware.starknet.common.syscalls.library_call.syscall_ptr",
                "references": [
                    {
                        "ap_tracking_data": {
                            "group": 1,
                            "offset": 0
                        },
                        "pc": 5,
                        "value": "[cast(fp + (-7), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 1,
                            "offset": 1
                        },
                        "pc": 12,
                        "value": "cast([fp + (-7)] + 7, felt*)"
                    }
                ],
                "type": "reference"
            },
            "starkware.starknet.common.syscalls.library_call_l1_handler": {
                "decorators": [],
                "pc": 17,
                "type": "function"
            },
            "starkware.starknet.common.syscalls.library_call_l1_handler.Args": {
                "full_name": "starkware.starknet.common.syscalls.library_call_l1_handler.Args",
                "members": {
                    "calldata": {
                        "cairo_type": "felt*",
                        "offset": 3
                    },
                    "calldata_size": {
                        "cairo_type": "felt",
                        "offset": 2
                    },
                    "class_hash": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "function_selector": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 4,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.library_call_l1_handler.ImplicitArgs": {
                "full_name": "starkware.starknet.common.syscalls.library_call_l1_handler.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.library_call_l1_handler.Return": {
                "cairo_type": "(retdata_size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "starkware.starknet.common.syscalls.library_call_l1_handler.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "starkware.starknet.common.syscalls.library_call_l1_handler.syscall_ptr": {
                "cairo_type": "felt*",
                "full_name": "starkware.starknet.common.syscalls.library_call_l1_handler.syscall_ptr",
                "references": [
                    {
                        "ap_tracking_data": {
                            "group": 2,
                            "offset": 0
                        },
                        "pc": 17,
                        "value": "[cast(fp + (-7), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 2,
                            "offset": 1
                        },
                        "pc": 24,
                        "value": "cast([fp + (-7)] + 7, felt*)"
                    }
                ],
                "type": "reference"
            },
            "starkware.starknet.common.syscalls.storage_read": {
                "decorators": [],
                "pc": 36,
                "type": "function"
            },
            "starkware.starknet.common.syscalls.storage_read.Args": {
                "full_name": "starkware.starknet.common.syscalls.storage_read.Args",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.storage_read.ImplicitArgs": {
                "full_name": "starkware.starknet.common.syscalls.storage_read.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.storage_read.Return": {
                "cairo_type": "(value : felt)",
                "type": "type_definition"
            },
            "starkware.starknet.common.syscalls.storage_read.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "starkware.starknet.common.syscalls.storage_read.syscall_ptr": {
                "cairo_type": "felt*",
                "full_name": "starkware.starknet.common.syscalls.storage_read.syscall_ptr",
                "references": [
                    {
                        "ap_tracking_data": {
                            "group": 4,
                            "offset": 0
                        },
                        "pc": 36,
                        "value": "[cast(fp + (-4), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 4,
                            "offset": 1
                        },
                        "pc": 40,
                        "value": "cast([fp + (-4)] + 3, felt*)"
                    }
                ],
                "type": "reference"
            },
            "starkware.starknet.common.syscalls.storage_write": {
                "decorators": [],
                "pc": 44,
                "type": "function"
            },
            "starkware.starknet.common.syscalls.storage_write.Args": {
                "full_name": "starkware.starknet.common.syscalls.storage_write.Args",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "value": {
                        "cairo_type": "felt",
                        "offset": 1
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.storage_write.ImplicitArgs": {
                "full_name": "starkware.starknet.common.syscalls.storage_write.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "starkware.starknet.common.syscalls.storage_write.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "starkware.starknet.common.syscalls.storage_write.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "starkware.starknet.common.syscalls.storage_write.syscall_ptr": {
                "cairo_type": "felt*",
                "full_name": "starkware.starknet.common.syscalls.storage_write.syscall_ptr",
                "references": [
                    {
                        "ap_tracking_data": {
                            "group": 5,
                            "offset": 0
                        },
                        "pc": 44,
                        "value": "[cast(fp + (-5), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 5,
                            "offset": 1
                        },
                        "pc": 49,
                        "value": "cast([fp + (-5)] + 3, felt*)"
                    }
                ],
                "type": "reference"
            },
            "utils.auth_read_storage": {
                "decorators": [
                    "view"
                ],
                "pc": 52,
                "type": "function"
            },
            "utils.auth_read_storage.Args": {
                "full_name": "utils.auth_read_storage.Args",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "auth_account": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "utils.auth_read_storage.ImplicitArgs": {
                "full_name": "utils.auth_read_storage.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "utils.auth_read_storage.Return": {
                "cairo_type": "(value : felt)",
                "type": "type_definition"
            },
            "utils.auth_read_storage.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "utils.auth_write_storage": {
                "decorators": [
                    "external"
                ],
                "pc": 87,
                "type": "function"
            },
            "utils.auth_write_storage.Args": {
                "full_name": "utils.auth_write_storage.Args",
                "members": {
                    "address": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "auth_account": {
                        "cairo_type": "felt",
                        "offset": 0
                    },
                    "value": {
                        "cairo_type": "felt",
                        "offset": 2
                    }
                },
                "size": 3,
                "type": "struct"
            },
            "utils.auth_write_storage.ImplicitArgs": {
                "full_name": "utils.auth_write_storage.ImplicitArgs",
                "members": {
                    "syscall_ptr": {
                        "cairo_type": "felt*",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "utils.auth_write_storage.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "utils.auth_write_storage.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "utils.get_caller_address": {
                "destination": "starkware.starknet.common.syscalls.get_caller_address",
                "type": "alias"
            },
            "utils.storage_read": {
                "destination": "starkware.starknet.common.syscalls.storage_read",
                "type": "alias"
            },
            "utils.storage_write": {
                "destination": "starkware.starknet.common.syscalls.storage_write",
                "type": "alias"
            }
        },
        "main_scope": "__main__",
        "prime": "0x800000000000011000000000000000000000000000000000000000000000001",
        "reference_manager": {
            "references": [
                {
                    "ap_tracking_data": {
                        "group": 0,
                        "offset": 0
                    },
                    "pc": 0,
                    "value": "[cast(fp + (-3), felt*)]"
                },
                {
                    "ap_tracking_data": {
                        "group": 1,
                        "offset": 0
                    },
                    "pc": 5,
                    "value": "[cast(fp + (-7), felt**)]"
                },
                {
                    "ap_tracking_data": {
                        "group": 2,
                        "offset": 0
                    },
                    "pc": 17,
                    "value": "[cast(fp + (-7), felt**)]"
                },
                {
                    "ap_tracking_data": {
                        "group": 3,
                        "offset": 0
                    },
                    "pc": 29,
                    "value": "[cast(fp + (-3), felt**)]"
                },
                {
                    "ap_tracking_data": {
                        "group": 4,
                        "offset": 0
                    },
                    "pc": 36,
                    "value": "[cast(fp + (-4), felt**)]"
                },
                {
                    "ap_tracking_data": {
                        "group": 5,
                        "offset": 0
                    },
                    "pc": 44,
                    "value": "[cast(fp + (-5), felt**)]"
                }
            ]
        }
    }
}
