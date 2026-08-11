# libID contracts

Smart contracts for libID, laid out per chain. `solidity/` is a self-contained
Foundry project holding the EVM contracts (login wallets, transfer bank
diamond, identity naming); room is reserved for `solana/` and other networks,
and `rust/` and `ts/` ABI wrapper packages are coming.

## Layout

```
solidity/            # Foundry project root
  contracts/
    login/           # registry, web wallets, OIDC + ZK session verifiers
    transfer/        # bank diamond and facets
    identity/        # platform handle naming and identity verifiers
    WTIA9.sol        # wrapped TIA
  script/Deploy.s.sol
  lib/               # git submodules (openzeppelin, forge-std)
scripts/
  regen-identity-handles.py
```

## Build and test

```sh
git submodule update --init --recursive
cd solidity
forge build
forge test
```

Some login OIDC flow tests read locally generated proof artifacts from
`circuits/jwt_email/target/`; when those files are absent the tests skip
themselves — that is expected.

## Handle vectors

`solidity/contracts/identity/handles.json` is the source of truth for platform
handle rules and the shared normalization vector table. After editing it:

```sh
python3 scripts/regen-identity-handles.py          # rewrite generated outputs
python3 scripts/regen-identity-handles.py --check  # verify nothing drifted
```

Today this generates `solidity/contracts/identity/HandleVectors.sol`; the Rust
and TypeScript outputs activate once those packages exist in this repo.

## License

Dual-licensed under MIT and Apache-2.0; see `LICENSE-MIT`, `LICENSE-APACHE`
and `CONTRIBUTING.md`.
