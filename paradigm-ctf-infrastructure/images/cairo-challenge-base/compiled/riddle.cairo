{
    "abi": [
        {
            "inputs": [
                {
                    "name": "solution",
                    "type": "felt"
                }
            ],
            "name": "solve",
            "outputs": [],
            "type": "function"
        },
        {
            "inputs": [],
            "name": "solution",
            "outputs": [
                {
                    "name": "solution",
                    "type": "felt"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ],
    "entry_points_by_type": {
        "CONSTRUCTOR": [],
        "EXTERNAL": [
            {
                "offset": "0x56",
                "selector": "0x1868b59cab0f269284b96acca5549ab804095fcb452d64aba3c904bc82117bc"
            },
            {
                "offset": "0x35",
                "selector": "0x22f36f27987a9715ca60c07832ab25f68e786eae77ee23e04624ed364c53736"
            }
        ],
        "L1_HANDLER": []
    },
    "program": {
        "attributes": [],
        "builtins": [
            "pedersen",
            "range_check"
        ],
        "data": [
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
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x480680017fff8000",
            "0x1eb40bd9147c14e794b6087aa106e21f10d36e9d0a0bd23e9db4de9c470b198",
            "0x208b7fff7fff7ffe",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffffa",
            "0x480a7ffb7fff8000",
            "0x48127ffe7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffe6",
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
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffe0",
            "0x48127ff67fff8000",
            "0x48127ff67fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffa7fff8000",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffff1",
            "0x208b7fff7fff7ffe",
            "0x482680017ffd8000",
            "0x1",
            "0x402a7ffd7ffc7fff",
            "0x480280007ffb8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x480280007ffd8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffff3",
            "0x40780017fff7fff",
            "0x1",
            "0x48127ffc7fff8000",
            "0x48127ffc7fff8000",
            "0x48127ffc7fff8000",
            "0x480680017fff8000",
            "0x0",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe",
            "0x480a7ffb7fff8000",
            "0x480a7ffc7fff8000",
            "0x480a7ffd7fff8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffcc",
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
            "0x402b7ffd7ffc7ffd",
            "0x480280007ffb8000",
            "0x480280017ffb8000",
            "0x480280027ffb8000",
            "0x1104800180018000",
            "0x800000000000010ffffffffffffffffffffffffffffffffffffffffffffffee",
            "0x48127ffe7fff8000",
            "0x1104800180018000",
            "0x800000000000010fffffffffffffffffffffffffffffffffffffffffffffff1",
            "0x48127ff47fff8000",
            "0x48127ff47fff8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x48127ffb7fff8000",
            "0x208b7fff7fff7ffe"
        ],
        "debug_info": {
            "file_contents": {
                "autogen/starknet/arg_processor/1b562308a65653425ce06491fa4b4539466f3251a07e73e099d0afe86a48900e.cairo": "assert [cast(fp + (-4), felt*)] = __calldata_actual_size\n",
                "autogen/starknet/arg_processor/5e1cc73f0b484f90bb02da164d88332b40c6f698801aa4d3c603dab22157e902.cairo": "let __calldata_actual_size =  __calldata_ptr - cast([cast(fp + (-3), felt**)], felt*)\n",
                "autogen/starknet/arg_processor/a0d043cdfbfbd5b45ae105f7563b60f31c183c51decc1c3460f1b8c7535ff8fc.cairo": "assert [__return_value_ptr] = ret_value.solution\nlet __return_value_ptr = __return_value_ptr + 1\n",
                "autogen/starknet/arg_processor/a0f32a4fa9efca3c86f185a31b39ea95997edee5ed407a8c5c9a3a7f71f2dd8c.cairo": "let __calldata_arg_solution = [__calldata_ptr]\nlet __calldata_ptr = __calldata_ptr + 1\n",
                "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo": "func solution_encode_return(ret_value : (solution : felt), range_check_ptr) -> (\n        range_check_ptr, data_len : felt, data : felt*):\n    %{ memory[ap] = segments.add() %}\n    alloc_locals\n    local __return_value_ptr_start : felt*\n    let __return_value_ptr = __return_value_ptr_start\n    with range_check_ptr:\n    end\n    return (\n        range_check_ptr=range_check_ptr,\n        data_len=__return_value_ptr - __return_value_ptr_start,\n        data=__return_value_ptr_start)\nend\n",
                "autogen/starknet/external/solution/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, starkware.cairo.common.cairo_builtins.HashBuiltin**)]\n",
                "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/solution/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/solution/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr, pedersen_ptr=pedersen_ptr, range_check_ptr=range_check_ptr}()\nlet (range_check_ptr, retdata_size, retdata) = solution_encode_return(ret_value, range_check_ptr)\n",
                "autogen/starknet/external/solve/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo": "let pedersen_ptr = [cast([cast(fp + (-5), felt**)] + 1, starkware.cairo.common.cairo_builtins.HashBuiltin**)]\n",
                "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo": "return (syscall_ptr,pedersen_ptr,range_check_ptr,retdata_size,retdata)\n",
                "autogen/starknet/external/solve/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo": "let syscall_ptr = [cast([cast(fp + (-5), felt**)] + 0, felt**)]\n",
                "autogen/starknet/external/solve/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo": "let range_check_ptr = [cast([cast(fp + (-5), felt**)] + 2, felt*)]\n",
                "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo": "let ret_value = __wrapped_func{syscall_ptr=syscall_ptr, pedersen_ptr=pedersen_ptr, range_check_ptr=range_check_ptr}(solution=__calldata_arg_solution,)\n%{ memory[ap] = segments.add() %}        # Allocate memory for return value.\ntempvar retdata : felt*\nlet retdata_size = 0\n",
                "autogen/starknet/storage_var/_solution/decl.cairo": "namespace _solution:\n    from starkware.starknet.common.storage import normalize_address\n    from starkware.starknet.common.syscalls import storage_read, storage_write\n    from starkware.cairo.common.cairo_builtins import HashBuiltin\n    from starkware.cairo.common.hash import hash2\n\n    func addr{pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let res = 0\n        call hash2\n        call normalize_address\n    end\n\n    func read{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let storage_addr = 0\n        call addr\n        call storage_read\n    end\n\n    func write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt):\n        let storage_addr = 0\n        call addr\n        call storage_write\n    end\nend",
                "autogen/starknet/storage_var/_solution/impl.cairo": "namespace _solution:\n    from starkware.starknet.common.storage import normalize_address\n    from starkware.starknet.common.syscalls import storage_read, storage_write\n    from starkware.cairo.common.cairo_builtins import HashBuiltin\n    from starkware.cairo.common.hash import hash2\n\n    func addr{pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let res = 867968731302102022842567969138478667220189993278783013200209303355874390424\n        return (res=res)\n    end\n\n    func read{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):\n        let (storage_addr) = addr()\n        let (__storage_var_temp0) = storage_read(address=storage_addr + 0)\n\n        tempvar syscall_ptr = syscall_ptr\n        tempvar pedersen_ptr = pedersen_ptr\n        tempvar range_check_ptr = range_check_ptr\n        tempvar __storage_var_temp0 : felt = __storage_var_temp0\n        return ([cast(&__storage_var_temp0, felt*)])\n    end\n\n    func write{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(value : felt):\n        let (storage_addr) = addr()\n        storage_write(address=storage_addr + 0, value=[cast(&value, felt) + 0])\n        return ()\n    end\nend"
            },
            "instruction_locations": {
                "0": {
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
                "2": {
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
                "3": {
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
                "4": {
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
                "6": {
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
                "7": {
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
                "8": {
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
                "10": {
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
                "11": {
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
                "12": {
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
                "13": {
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
                "15": {
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
                "16": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 25,
                                        "end_line": 9,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
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
                "17": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 25,
                                        "end_line": 9,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
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
                "18": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 94,
                        "end_line": 8,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 9,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
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
                "20": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.addr"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 25,
                        "end_line": 9,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 9
                    }
                },
                "21": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 13,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 13
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
                "22": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 13,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 13
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
                "23": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 36,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 30,
                        "start_line": 13
                    }
                },
                "25": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 34,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
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
                                        "end_line": 14,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 37,
                                        "start_line": 14
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
                "26": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 26,
                        "end_line": 13,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 70,
                                "end_line": 14,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "start_col": 58,
                                "start_line": 14
                            },
                            "While expanding the reference 'storage_addr' in:"
                        ],
                        "start_col": 14,
                        "start_line": 13
                    }
                },
                "27": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 75,
                        "end_line": 14,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 37,
                        "start_line": 14
                    }
                },
                "29": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
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
                                "end_line": 14,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 42,
                                        "end_line": 16,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 31,
                                        "start_line": 16
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 37,
                                "start_line": 14
                            },
                            "While trying to update the implicit return value 'syscall_ptr' in:"
                        ],
                        "start_col": 19,
                        "start_line": 348
                    }
                },
                "30": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 44,
                                        "end_line": 17,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 32,
                                        "start_line": 17
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 13
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "31": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 50,
                                        "end_line": 18,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 35,
                                        "start_line": 18
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 13
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "32": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 33,
                        "end_line": 14,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 65,
                                "end_line": 19,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "start_col": 46,
                                "start_line": 19
                            },
                            "While expanding the reference '__storage_var_temp0' in:"
                        ],
                        "start_col": 14,
                        "start_line": 14
                    }
                },
                "33": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.read"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 53,
                        "end_line": 20,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 20
                    }
                },
                "34": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 23,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 42,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 24,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 24
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 7
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 37,
                        "start_line": 23
                    }
                },
                "35": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 81,
                        "end_line": 23,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 59,
                                "end_line": 7,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 24,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 30,
                                        "start_line": 24
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 44,
                                "start_line": 7
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 66,
                        "start_line": 23
                    }
                },
                "36": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 36,
                        "end_line": 24,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 30,
                        "start_line": 24
                    }
                },
                "38": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 23,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
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
                                        "end_line": 25,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                        },
                                        "start_col": 9,
                                        "start_line": 25
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 20,
                                "start_line": 366
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 16,
                        "start_line": 23
                    }
                },
                "39": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 26,
                        "end_line": 24,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 43,
                                "end_line": 25,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "start_col": 31,
                                "start_line": 25
                            },
                            "While expanding the reference 'storage_addr' in:"
                        ],
                        "start_col": 14,
                        "start_line": 24
                    }
                },
                "40": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 79,
                        "end_line": 25,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 55,
                        "start_line": 25
                    }
                },
                "41": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 80,
                        "end_line": 25,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 25
                    }
                },
                "43": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 42,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 24,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 64,
                                        "end_line": 19,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 18,
                                                "end_line": 26,
                                                "input_file": {
                                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                                },
                                                "start_col": 9,
                                                "start_line": 26
                                            },
                                            "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                        ],
                                        "start_col": 37,
                                        "start_line": 19
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 24
                            },
                            "While trying to update the implicit return value 'pedersen_ptr' in:"
                        ],
                        "start_col": 15,
                        "start_line": 7
                    }
                },
                "44": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 59,
                        "end_line": 7,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 36,
                                "end_line": 24,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 81,
                                        "end_line": 19,
                                        "input_file": {
                                            "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 18,
                                                "end_line": 26,
                                                "input_file": {
                                                    "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                                                },
                                                "start_col": 9,
                                                "start_line": 26
                                            },
                                            "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                        ],
                                        "start_col": 66,
                                        "start_line": 19
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 30,
                                "start_line": 24
                            },
                            "While trying to update the implicit return value 'range_check_ptr' in:"
                        ],
                        "start_col": 44,
                        "start_line": 7
                    }
                },
                "45": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__._solution",
                        "__main__._solution.write"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 18,
                        "end_line": 26,
                        "input_file": {
                            "filename": "autogen/starknet/storage_var/_solution/impl.cairo"
                        },
                        "start_col": 9,
                        "start_line": 26
                    }
                },
                "46": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 11,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 35,
                                "end_line": 19,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 30,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 16,
                                "start_line": 19
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 5,
                        "start_line": 11
                    }
                },
                "47": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 32,
                        "end_line": 12,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 64,
                                "end_line": 19,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 30,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 37,
                                "start_line": 19
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 5,
                        "start_line": 12
                    }
                },
                "48": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 20,
                        "end_line": 13,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 81,
                                "end_line": 19,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 30,
                                        "end_line": 15,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 5,
                                        "start_line": 15
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 66,
                                "start_line": 19
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 5,
                        "start_line": 13
                    }
                },
                "49": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 18,
                        "end_line": 14,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 29,
                                "end_line": 15,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 21,
                                "start_line": 15
                            },
                            "While expanding the reference 'solution' in:"
                        ],
                        "start_col": 3,
                        "start_line": 14
                    }
                },
                "50": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 30,
                        "end_line": 15,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "start_col": 5,
                        "start_line": 15
                    }
                },
                "52": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 14,
                        "end_line": 16,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "start_col": 5,
                        "start_line": 16
                    }
                },
                "53": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 40,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/a0f32a4fa9efca3c86f185a31b39ea95997edee5ed407a8c5c9a3a7f71f2dd8c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 18,
                                "end_line": 14,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
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
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                                                                "end_col": 11,
                                                                "end_line": 10,
                                                                "input_file": {
                                                                    "filename": "contracts/riddle.cairo"
                                                                },
                                                                "start_col": 6,
                                                                "start_line": 10
                                                            },
                                                            "While handling calldata of"
                                                        ],
                                                        "start_col": 35,
                                                        "start_line": 1
                                                    },
                                                    "While expanding the reference '__calldata_actual_size' in:"
                                                ],
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While handling calldata of"
                                        ],
                                        "start_col": 31,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_ptr' in:"
                                ],
                                "start_col": 3,
                                "start_line": 14
                            },
                            "While handling calldata argument 'solution'"
                        ],
                        "start_col": 22,
                        "start_line": 2
                    }
                },
                "55": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
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
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While handling calldata of"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "56": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 11,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 44,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 5,
                                "start_line": 11
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "57": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 110,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 32,
                                "end_line": 12,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 82,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 5,
                                "start_line": 12
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "58": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 115,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 100,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 5,
                                "start_line": 13
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "59": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 47,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/a0f32a4fa9efca3c86f185a31b39ea95997edee5ed407a8c5c9a3a7f71f2dd8c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 18,
                                "end_line": 14,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 149,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 126,
                                        "start_line": 1
                                    },
                                    "While expanding the reference '__calldata_arg_solution' in:"
                                ],
                                "start_col": 3,
                                "start_line": 14
                            },
                            "While handling calldata argument 'solution'"
                        ],
                        "start_col": 31,
                        "start_line": 1
                    }
                },
                "60": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 11,
                        "end_line": 10,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "start_col": 6,
                        "start_line": 10
                    }
                },
                "62": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 34,
                                "end_line": 2,
                                "input_file": {
                                    "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 11,
                                        "end_line": 10,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 10
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
                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 3
                    }
                },
                "64": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 9,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'syscall_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 44,
                        "start_line": 1
                    }
                },
                "65": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 82,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 21,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 70,
                        "start_line": 1
                    }
                },
                "66": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 115,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 34,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 100,
                        "start_line": 1
                    }
                },
                "67": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 4,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 50,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata_size' in:"
                                ],
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 4
                    }
                },
                "69": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 16,
                        "end_line": 3,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/f1018605e3bba299ceed24dd71c24fe11f7dd38494bc6d62b85f85f978649c52.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 11,
                                                "end_line": 10,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 10
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 63,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'retdata' in:"
                                ],
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 9,
                        "start_line": 3
                    }
                },
                "70": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solve/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 11,
                                "end_line": 10,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 10
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "71": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 24,
                        "end_line": 21,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 34,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 25,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 22,
                                        "start_line": 25
                                    },
                                    "While trying to retrieve the implicit argument 'syscall_ptr' in:"
                                ],
                                "start_col": 15,
                                "start_line": 13
                            },
                            "While expanding the reference 'syscall_ptr' in:"
                        ],
                        "start_col": 5,
                        "start_line": 21
                    }
                },
                "72": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 32,
                        "end_line": 22,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 63,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 25,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 22,
                                        "start_line": 25
                                    },
                                    "While trying to retrieve the implicit argument 'pedersen_ptr' in:"
                                ],
                                "start_col": 36,
                                "start_line": 13
                            },
                            "While expanding the reference 'pedersen_ptr' in:"
                        ],
                        "start_col": 5,
                        "start_line": 22
                    }
                },
                "73": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 20,
                        "end_line": 23,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 80,
                                "end_line": 13,
                                "input_file": {
                                    "filename": "autogen/starknet/storage_var/_solution/decl.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 25,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 22,
                                        "start_line": 25
                                    },
                                    "While trying to retrieve the implicit argument 'range_check_ptr' in:"
                                ],
                                "start_col": 65,
                                "start_line": 13
                            },
                            "While expanding the reference 'range_check_ptr' in:"
                        ],
                        "start_col": 5,
                        "start_line": 23
                    }
                },
                "74": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 38,
                        "end_line": 25,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "start_col": 22,
                        "start_line": 25
                    }
                },
                "76": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__main__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 22,
                        "end_line": 26,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "start_col": 5,
                        "start_line": 26
                    }
                },
                "77": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [
                        {
                            "location": {
                                "end_col": 38,
                                "end_line": 3,
                                "input_file": {
                                    "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 14,
                                        "end_line": 20,
                                        "input_file": {
                                            "filename": "contracts/riddle.cairo"
                                        },
                                        "start_col": 6,
                                        "start_line": 20
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
                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While handling return value of"
                        ],
                        "start_col": 5,
                        "start_line": 4
                    }
                },
                "79": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 49,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/a0d043cdfbfbd5b45ae105f7563b60f31c183c51decc1c3460f1b8c7535ff8fc.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 24,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 9,
                                "start_line": 24
                            },
                            "While handling return value 'solution'"
                        ],
                        "start_col": 1,
                        "start_line": 1
                    }
                },
                "80": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 48,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/arg_processor/a0d043cdfbfbd5b45ae105f7563b60f31c183c51decc1c3460f1b8c7535ff8fc.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 24,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 36,
                                        "end_line": 11,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 18,
                                        "start_line": 11
                                    },
                                    "While expanding the reference '__return_value_ptr' in:"
                                ],
                                "start_col": 9,
                                "start_line": 24
                            },
                            "While handling return value 'solution'"
                        ],
                        "start_col": 26,
                        "start_line": 2
                    }
                },
                "82": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 75,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 40,
                                        "end_line": 10,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 25,
                                        "start_line": 10
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While handling return value of"
                        ],
                        "start_col": 60,
                        "start_line": 1
                    }
                },
                "83": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 63,
                        "end_line": 11,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While handling return value of"
                        ],
                        "start_col": 18,
                        "start_line": 11
                    }
                },
                "84": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 5,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 38,
                                        "end_line": 12,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While handling return value of"
                                        ],
                                        "start_col": 14,
                                        "start_line": 12
                                    },
                                    "While expanding the reference '__return_value_ptr_start' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While handling return value of"
                        ],
                        "start_col": 11,
                        "start_line": 5
                    }
                },
                "85": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 39,
                        "end_line": 12,
                        "input_file": {
                            "filename": "autogen/starknet/external/return/solution/07764dd3f1f559d87cbf1de6a517ec032e7d3086fcfa8fb3dd6496616821e6a2.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While handling return value of"
                        ],
                        "start_col": 5,
                        "start_line": 9
                    }
                },
                "86": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
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
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
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
                "87": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 64,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/c7060df96cb0acca1380ae43bf758cab727bfdf73cb5d34a93e24a9742817fda.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 24,
                                "end_line": 21,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 55,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                                "start_col": 5,
                                "start_line": 21
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 19,
                        "start_line": 1
                    }
                },
                "88": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 110,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/424b26e79f70343cc02557f1fbd25745138efb26a3dc5c8b593ca765b73138b7.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 32,
                                "end_line": 22,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 82,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 70,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'pedersen_ptr' in:"
                                ],
                                "start_col": 5,
                                "start_line": 22
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 20,
                        "start_line": 1
                    }
                },
                "89": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 67,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/e651458745e7cd218121c342e0915890767e2f59ddc2e315b8844ad0f47d582e.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 20,
                                "end_line": 23,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 115,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 100,
                                        "start_line": 1
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 5,
                                "start_line": 23
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 23,
                        "start_line": 1
                    }
                },
                "90": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 14,
                        "end_line": 20,
                        "input_file": {
                            "filename": "contracts/riddle.cairo"
                        },
                        "start_col": 6,
                        "start_line": 20
                    }
                },
                "92": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 115,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 97,
                                        "end_line": 2,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
                                                },
                                                "start_col": 6,
                                                "start_line": 20
                                            },
                                            "While constructing the external wrapper for:"
                                        ],
                                        "start_col": 82,
                                        "start_line": 2
                                    },
                                    "While expanding the reference 'range_check_ptr' in:"
                                ],
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 100,
                        "start_line": 1
                    }
                },
                "93": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 98,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
                            },
                            "While constructing the external wrapper for:"
                        ],
                        "start_col": 48,
                        "start_line": 2
                    }
                },
                "95": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 55,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 20,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                "96": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 82,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 33,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                        "start_col": 70,
                        "start_line": 1
                    }
                },
                "97": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 21,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 49,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                        "start_col": 6,
                        "start_line": 2
                    }
                },
                "98": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 35,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 62,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                        "start_col": 23,
                        "start_line": 2
                    }
                },
                "99": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 44,
                        "end_line": 2,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/f2adfa0cdb1933015c42f71ed6db16b2af5b7d7802557093330c8fe1595fba7c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "parent_location": [
                                    {
                                        "end_col": 70,
                                        "end_line": 1,
                                        "input_file": {
                                            "filename": "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                                        },
                                        "parent_location": [
                                            {
                                                "end_col": 14,
                                                "end_line": 20,
                                                "input_file": {
                                                    "filename": "contracts/riddle.cairo"
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
                        "start_col": 37,
                        "start_line": 2
                    }
                },
                "100": {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution"
                    ],
                    "flow_tracking_data": null,
                    "hints": [],
                    "inst": {
                        "end_col": 71,
                        "end_line": 1,
                        "input_file": {
                            "filename": "autogen/starknet/external/solution/4ba2b119ceb30fe10f4cca3c9d73ef620c0fb5eece91b99a99d71217bba1001c.cairo"
                        },
                        "parent_location": [
                            {
                                "end_col": 14,
                                "end_line": 20,
                                "input_file": {
                                    "filename": "contracts/riddle.cairo"
                                },
                                "start_col": 6,
                                "start_line": 20
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
            "4": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_read"
                    ],
                    "code": "syscall_handler.storage_read(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 0,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.storage_read.syscall_ptr": 0
                        }
                    }
                }
            ],
            "13": [
                {
                    "accessible_scopes": [
                        "starkware.starknet.common.syscalls",
                        "starkware.starknet.common.syscalls.storage_write"
                    ],
                    "code": "syscall_handler.storage_write(segments=segments, syscall_ptr=ids.syscall_ptr)",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 1,
                            "offset": 1
                        },
                        "reference_ids": {
                            "starkware.starknet.common.syscalls.storage_write.syscall_ptr": 1
                        }
                    }
                }
            ],
            "62": [
                {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solve"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 6,
                            "offset": 29
                        },
                        "reference_ids": {}
                    }
                }
            ],
            "77": [
                {
                    "accessible_scopes": [
                        "__main__",
                        "__main__",
                        "__wrappers__",
                        "__wrappers__.solution_encode_return"
                    ],
                    "code": "memory[ap] = segments.add()",
                    "flow_tracking_data": {
                        "ap_tracking": {
                            "group": 8,
                            "offset": 0
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
            "__main__._solution": {
                "type": "namespace"
            },
            "__main__._solution.Args": {
                "full_name": "__main__._solution.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__._solution.HashBuiltin": {
                "destination": "starkware.cairo.common.cairo_builtins.HashBuiltin",
                "type": "alias"
            },
            "__main__._solution.ImplicitArgs": {
                "full_name": "__main__._solution.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__._solution.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__._solution.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__._solution.addr": {
                "decorators": [],
                "pc": 16,
                "type": "function"
            },
            "__main__._solution.addr.Args": {
                "full_name": "__main__._solution.addr.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__._solution.addr.ImplicitArgs": {
                "full_name": "__main__._solution.addr.ImplicitArgs",
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
            "__main__._solution.addr.Return": {
                "cairo_type": "(res : felt)",
                "type": "type_definition"
            },
            "__main__._solution.addr.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__._solution.hash2": {
                "destination": "starkware.cairo.common.hash.hash2",
                "type": "alias"
            },
            "__main__._solution.normalize_address": {
                "destination": "starkware.starknet.common.storage.normalize_address",
                "type": "alias"
            },
            "__main__._solution.read": {
                "decorators": [],
                "pc": 21,
                "type": "function"
            },
            "__main__._solution.read.Args": {
                "full_name": "__main__._solution.read.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__._solution.read.ImplicitArgs": {
                "full_name": "__main__._solution.read.ImplicitArgs",
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
            "__main__._solution.read.Return": {
                "cairo_type": "(res : felt)",
                "type": "type_definition"
            },
            "__main__._solution.read.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__._solution.storage_read": {
                "destination": "starkware.starknet.common.syscalls.storage_read",
                "type": "alias"
            },
            "__main__._solution.storage_write": {
                "destination": "starkware.starknet.common.syscalls.storage_write",
                "type": "alias"
            },
            "__main__._solution.write": {
                "decorators": [],
                "pc": 34,
                "type": "function"
            },
            "__main__._solution.write.Args": {
                "full_name": "__main__._solution.write.Args",
                "members": {
                    "value": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "__main__._solution.write.ImplicitArgs": {
                "full_name": "__main__._solution.write.ImplicitArgs",
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
            "__main__._solution.write.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__._solution.write.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.solution": {
                "decorators": [
                    "view"
                ],
                "pc": 71,
                "type": "function"
            },
            "__main__.solution.Args": {
                "full_name": "__main__.solution.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__main__.solution.ImplicitArgs": {
                "full_name": "__main__.solution.ImplicitArgs",
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
            "__main__.solution.Return": {
                "cairo_type": "(solution : felt)",
                "type": "type_definition"
            },
            "__main__.solution.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__main__.solve": {
                "decorators": [
                    "external"
                ],
                "pc": 46,
                "type": "function"
            },
            "__main__.solve.Args": {
                "full_name": "__main__.solve.Args",
                "members": {
                    "solution": {
                        "cairo_type": "felt",
                        "offset": 0
                    }
                },
                "size": 1,
                "type": "struct"
            },
            "__main__.solve.ImplicitArgs": {
                "full_name": "__main__.solve.ImplicitArgs",
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
            "__main__.solve.Return": {
                "cairo_type": "()",
                "type": "type_definition"
            },
            "__main__.solve.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.solution": {
                "decorators": [
                    "view"
                ],
                "pc": 86,
                "type": "function"
            },
            "__wrappers__.solution.Args": {
                "full_name": "__wrappers__.solution.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.solution.ImplicitArgs": {
                "full_name": "__wrappers__.solution.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.solution.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.solution.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.solution.__wrapped_func": {
                "destination": "__main__.solution",
                "type": "alias"
            },
            "__wrappers__.solution_encode_return": {
                "decorators": [],
                "pc": 77,
                "type": "function"
            },
            "__wrappers__.solution_encode_return.Args": {
                "full_name": "__wrappers__.solution_encode_return.Args",
                "members": {
                    "range_check_ptr": {
                        "cairo_type": "felt",
                        "offset": 1
                    },
                    "ret_value": {
                        "cairo_type": "(solution : felt)",
                        "offset": 0
                    }
                },
                "size": 2,
                "type": "struct"
            },
            "__wrappers__.solution_encode_return.ImplicitArgs": {
                "full_name": "__wrappers__.solution_encode_return.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.solution_encode_return.Return": {
                "cairo_type": "(range_check_ptr : felt, data_len : felt, data : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.solution_encode_return.SIZEOF_LOCALS": {
                "type": "const",
                "value": 1
            },
            "__wrappers__.solution_encode_return.memcpy": {
                "destination": "starkware.cairo.common.memcpy.memcpy",
                "type": "alias"
            },
            "__wrappers__.solve": {
                "decorators": [
                    "external"
                ],
                "pc": 53,
                "type": "function"
            },
            "__wrappers__.solve.Args": {
                "full_name": "__wrappers__.solve.Args",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.solve.ImplicitArgs": {
                "full_name": "__wrappers__.solve.ImplicitArgs",
                "members": {},
                "size": 0,
                "type": "struct"
            },
            "__wrappers__.solve.Return": {
                "cairo_type": "(syscall_ptr : felt*, pedersen_ptr : starkware.cairo.common.cairo_builtins.HashBuiltin*, range_check_ptr : felt, size : felt, retdata : felt*)",
                "type": "type_definition"
            },
            "__wrappers__.solve.SIZEOF_LOCALS": {
                "type": "const",
                "value": 0
            },
            "__wrappers__.solve.__wrapped_func": {
                "destination": "__main__.solve",
                "type": "alias"
            },
            "__wrappers__.solve_encode_return.memcpy": {
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
            "starkware.starknet.common.syscalls.storage_read": {
                "decorators": [],
                "pc": 0,
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
                            "group": 0,
                            "offset": 0
                        },
                        "pc": 0,
                        "value": "[cast(fp + (-4), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 0,
                            "offset": 1
                        },
                        "pc": 4,
                        "value": "cast([fp + (-4)] + 3, felt*)"
                    }
                ],
                "type": "reference"
            },
            "starkware.starknet.common.syscalls.storage_write": {
                "decorators": [],
                "pc": 8,
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
                            "group": 1,
                            "offset": 0
                        },
                        "pc": 8,
                        "value": "[cast(fp + (-5), felt**)]"
                    },
                    {
                        "ap_tracking_data": {
                            "group": 1,
                            "offset": 1
                        },
                        "pc": 13,
                        "value": "cast([fp + (-5)] + 3, felt*)"
                    }
                ],
                "type": "reference"
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
                    "value": "[cast(fp + (-4), felt**)]"
                },
                {
                    "ap_tracking_data": {
                        "group": 1,
                        "offset": 0
                    },
                    "pc": 8,
                    "value": "[cast(fp + (-5), felt**)]"
                }
            ]
        }
    }
}
