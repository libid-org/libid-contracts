// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The protocol-admin address baked into the FROZEN factory-proxy init code.
//
// The canonical factory proxy is deployed with init code that ends in
// `abi.encode(implAddress, abi.encodeCall(LibidFactory.initialize, (FACTORY_GENESIS_ADMIN)))`
// (see `FactoryDeployer.proxyInitCode()`). Baking the admin into the init
// code — instead of passing it per network — is what makes the init code
// identical everywhere (same CREATE2 address on every chain) AND makes
// initialization atomic with deployment: there is no window in which an
// uninitialized proxy exists for someone to front-run `initialize`.
//
// ─────────────────────────────────────────────────────────────────────────
// PLACEHOLDER — DO NOT DEPLOY TO ANY MAINNET-FAMILY NETWORK AS-IS.
//
// The owner substitutes the real protocol-admin KMS address here BEFORE the
// first mainnet-family deployment. Changing this constant changes the frozen
// proxy init code and therefore the canonical factory address, so it must be
// set once, before anything ships, and then NEVER touched again (a later
// change is a v2 factory: new salts, new address — see the README).
//
// Keep in sync with `FACTORY_GENESIS_ADMIN` in `rust/contracts/src/factory.rs`.
// ─────────────────────────────────────────────────────────────────────────
address constant FACTORY_GENESIS_ADMIN = 0x1111111111111111111111111111111111111111;
