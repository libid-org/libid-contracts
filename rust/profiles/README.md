# libid-profiles

The libID ceremony profiles, generated from
`solidity/contracts/ceremony/profiles.json` — the same source
`CeremonyProfile.sol` and the TypeScript table are generated from.

One platform's profile says which host answers each notarized session, which
request line the session sends, which body field the exchange commits rather
than reveals, and which two members of the identity response a Platform
Verifier reads. `keccak256` of `Profile::platform` is the platform id, and
`keccak256` of `Session::authority` is the authority id; this crate hashes
neither, because a caller that needs an id already has a hasher.

No dependencies, and none are coming.
