// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IBank} from "../bank/IBank.sol";
import {BankDiamondDeployer} from "../script/BankDiamondDeployer.sol";
import {NotaryRegistry} from "../../login/NotaryRegistry.sol";

contract DollarTokenTest is Test, BankDiamondDeployer {
    IBank bank;

    function setUp() public {
        NotaryRegistry nrImpl = new NotaryRegistry();
        NotaryRegistry notaryReg = NotaryRegistry(
            address(
                new ERC1967Proxy(
                    address(nrImpl), abi.encodeCall(NotaryRegistry.initialize, (address(this), address(1)))
                )
            )
        );
        bank = IBank(deployBankDiamond(address(this), address(notaryReg), address(2), address(3)));
    }

    function test_registerDollarTIA() public {
        address mockToken = address(0xBEEF);

        // Register $TIA as a token name — should not revert
        bank.registerToken("$TIA", mockToken);

        // Verify it resolves
        address resolved = bank.resolveToken("$TIA");
        assertEq(resolved, mockToken, "resolveToken should return the registered address");
    }

    function test_templateRenderWithDollarToken() public {
        address mockToken = address(0xBEEF);
        bank.registerToken("$TIA", mockToken);

        // Set a custom template on a fresh platform
        bank.setPlatformTemplate("custom", "@dyaka-agent honor @{recipient} with {amount} {token}");

        // Verify template parts work
        (string memory prefix, string memory afterRecipient, string memory afterAmount, string memory suffix) =
            bank.getTemplateParts("custom", 0);
        assertEq(prefix, "@dyaka-agent honor @");
        assertEq(afterRecipient, " with ");
        assertEq(afterAmount, " ");
        assertEq(suffix, "");
    }
}
