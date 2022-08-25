# Running Cairo paradigm CTF solutiosn locally

This repository contains solutions for the Cairo challenges of the 2022 Paradigm-CTF

## Creating env instructions

- create virtual environment

```
python3 -m venv ./venv
source ./venv/bin/activate
```

- Install requirements

```
pip install -requirements ./requirements.txt
```

- Run the server for deploying local environments

```
cd ./paradigm-ctf-infrastructure/images/cairo-challenge-base
python -m cairo_sandbox.server
```

## Compiling the contracts

The compiled contrats have already been place in the correct direcotry.

### Compiling the contrats from source:

Contracts can be compiled by running `nile compile`. This generates both the compiled contract files and abis in the `artifacts` dir

Although the generated files have a `.json` extension, the individual challenge scripts expect the file to be named `.cairo`

- Rename files to fit format: (for example)

`mv artifacts/almost_erc20.json compiled/almost_erc20.cairo`

Copy the files to the infrastructure directory: (for example)

`cp ./artifacts/almost_erc20.json paradigm-ctf-infrastructure/images/cairo-challenge-base/compiled/almost_erc20.cairo`

## Running individual challanges

- Run the challenge script. The sever script should already be running in another terminal.

```
cd ./paradigm-ctf-infrastructure/images/cairo-challenge-base
python -m cairo_sandbox.proxy-chal.py
```

- Choose option 1 to create new environment
- Input any number (e.g. 1) as ticket

- Wait for the contracts to be deployed
- Copy the `rpc endpoint`, `private key` and `contract` to their respecable value in the solution script

## Run the solution script

Run the solution script with

```
python ./scripts/cairo-auction.py
```

## Thanks

If you like it than you shoulda put a start ⭐ on it

Twitter: [@amanusk\_](https://twitter.com/amanusk_)

## License

MIT
