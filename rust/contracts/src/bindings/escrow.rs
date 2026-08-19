//! Bindings for the handle escrow (`solidity/contracts/escrow/`).
//!
//! Value held against a platform handle rather than against an account id, so
//! a sender who knows only a name can pay it before anybody has claimed it.
//! Whoever proves that handle to the naming system takes what is held.
//!
//! The escrow keys on a rules-independent form of the text, so the slot never
//! moves when a platform's normalization is reconfigured, and validates the
//! text against the platform's current rules on the way in, so nothing funds a
//! slot no proof could claim. `slotOf` is `pure` and public for exactly that
//! reason: a client computes the same key off chain.

/// Bindings for `escrow/HandleEscrow.sol`.
#[allow(clippy::too_many_arguments, unused_attributes)]
mod escrow_inner {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface HandleEscrow {
            function initialize(address owner_, address names_) external;

            /// Put `amount` of `token` against a handle. `address(0)` is the
            /// chain's own token, and then `amount` must equal the value sent.
            ///
            /// A handle that already resolves is paid STRAIGHT THROUGH to its
            /// holder — the escrow is for the window before a handle is
            /// claimed. Only an unclaimed handle escrows, and then there is no
            /// way to take it back. Watch `Deposited` against `Forwarded` to
            /// tell the two apart.
            function deposit(
                bytes32 platformId,
                string calldata handle,
                address token,
                uint256 amount
            ) external payable;

            /// Take everything held for a handle in one token. The caller has
            /// to be the wallet that handle currently resolves to.
            function claim(
                bytes32 platformId,
                string calldata handle,
                address token,
                address recipient
            ) external;

            function escrowed(bytes32 platformId, string calldata handle, address token)
                external
                view
                returns (uint256);
            function escrowedAt(bytes32 slot, address token) external view returns (uint256);
            function slotOf(bytes32 platformId, string memory handle) external pure returns (bytes32);
            function canonicalHandle(string memory handle) external pure returns (string memory);
            function names() external view returns (address);
            function NATIVE() external view returns (address);

            /// `handle` rides along as text: a slot cannot be turned back into
            /// a string, so an indexer reads the name from here.
            event Deposited(
                bytes32 indexed slot,
                address indexed token,
                address indexed depositor,
                bytes32 platformId,
                string handle,
                uint256 amount
            );
            /// A deposit for a handle somebody already held, paid to that holder
            /// and never booked. Nothing is claimable afterwards, which is what
            /// separates it from `Deposited`.
            event Forwarded(
                bytes32 indexed slot,
                address indexed token,
                address indexed depositor,
                address holder,
                bytes32 platformId,
                string handle,
                uint256 amount
            );
            event Claimed(
                bytes32 indexed slot,
                address indexed token,
                address indexed claimer,
                address recipient,
                uint256 amount
            );
        }
    }
}

pub use escrow_inner::HandleEscrow;
