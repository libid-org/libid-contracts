// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {HandleNormalizer} from "../identity/HandleNormalizer.sol";

/// @notice The two questions the escrow asks the naming system.
///
/// @dev A local interface rather than an import of the whole contract, the way
///      `IIdentityVerifier`, `IRegistry` and `INotary` are declared where they
///      are used. Two functions do not justify pulling in the naming contract's
///      whole surface, and a narrow interface says exactly what the escrow
///      depends on.
///
///      `HandleNormalizer.Rules` IS imported rather than redeclared. A copy
///      would be a second definition of the struct the naming system stores,
///      and the two would drift the first time a field is added. The escrow
///      needs the library anyway, to run the same transform on the text a
///      depositor supplies.
interface IIdentityNames {
    /// @notice The wallet that last proved this handle, or the zero address.
    ///
    /// @dev Zero also means "nobody holds it any more": a handle whose account
    ///      renamed away is retired, and reads back with no owner.
    function resolveHandle(bytes32 platformId, string calldata handle) external view returns (address);

    /// @notice How this platform's handles normalize, as configured now.
    /// @dev Reverts for a platform that is not wired.
    function rulesOf(bytes32 platformId) external view returns (HandleNormalizer.Rules memory);
}
