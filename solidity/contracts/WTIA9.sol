// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WTIA9 — canonical wrapper for the native asset (TIA).
/// @notice A WETH9-shaped wrapper: `deposit()` mints 1:1 against native value,
///         `withdraw()` burns and returns it. `totalSupply()` is the contract's
///         native balance by construction, so the wrapper can never be
///         fractionally reserved.
///
/// @dev Deployed because Eden testnet has no canonical wrapped native token.
///      Eden *mainnet* has one at the vanity address
///      0x00000000000000000000000000000000Ce1e571A; that address has no code on
///      testnet (verified), and the only wrapper present there is an unowned
///      deployment holding ~10 TIA.
///
///      Two deliberate departures from the 2015 WETH9 original:
///
///      1. `withdraw` uses `call` rather than `transfer`. `transfer` forwards a
///         fixed 2300 gas stipend, which is enough for an EOA but reverts for a
///         contract recipient whose `receive` does anything at all — including
///         dyaka's own WebWallet, which emits an event on native receipt. WETH9
///         predates that being a known hazard.
///      2. Balances are decremented *before* the external call
///         (checks-effects-interactions), so a malicious `receive` cannot
///         re-enter and withdraw twice. The original is safe only by accident
///         of the gas stipend.
contract WTIA9 {
    string public constant name = "Wrapped TIA";
    string public constant symbol = "WTIA";
    uint8 public constant decimals = 18;

    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Deposit(address indexed to, uint256 value);
    event Withdrawal(address indexed from, uint256 value);

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    error InsufficientBalance();
    error InsufficientAllowance();
    error TransferFailed();

    /// @notice Wrap native value sent directly to the contract.
    receive() external payable {
        deposit();
    }

    /// @notice Wrap `msg.value` into an equal amount of WTIA.
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
        emit Transfer(address(0), msg.sender, msg.value);
    }

    /// @notice Burn `amount` WTIA and return the native asset to the caller.
    function withdraw(uint256 amount) public {
        uint256 bal = balanceOf[msg.sender];
        if (bal < amount) revert InsufficientBalance();

        // Effects before interaction — see the note on reentrancy above.
        unchecked {
            balanceOf[msg.sender] = bal - amount;
        }
        emit Transfer(msg.sender, address(0), amount);
        emit Withdrawal(msg.sender, amount);

        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Total supply is the native balance held, always exactly backed.
    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 bal = balanceOf[from];
        if (bal < amount) revert InsufficientBalance();

        if (from != msg.sender) {
            uint256 allowed = allowance[from][msg.sender];
            // type(uint256).max is the conventional "infinite approval" sentinel
            // and is not decremented, matching WETH9 and every major ERC20.
            if (allowed != type(uint256).max) {
                if (allowed < amount) revert InsufficientAllowance();
                unchecked {
                    allowance[from][msg.sender] = allowed - amount;
                }
            }
        }

        unchecked {
            balanceOf[from] = bal - amount;
        }
        balanceOf[to] += amount;

        emit Transfer(from, to, amount);
        return true;
    }
}
