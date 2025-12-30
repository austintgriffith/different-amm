// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/Credits.sol";

contract CreditsTest is Test {
    Credits public credits;

    address public owner = vm.addr(1);
    address public alice = vm.addr(2);
    address public bob = vm.addr(3);
    address public facilitator = vm.addr(4);

    uint256 public alicePrivateKey = 2;

    function setUp() public {
        vm.prank(owner);
        credits = new Credits(owner);
    }

    // ============ Admin Mint Tests ============

    function testMint() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        assertEq(credits.balanceOf(alice), 1000 ether);
    }

    function testMintOnlyOwner() public {
        vm.prank(alice);
        vm.expectRevert();
        credits.mint(alice, 1000 ether);
    }

    // ============ Admin Burn Tests ============

    function testBurn() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        vm.prank(owner);
        credits.burn(alice, 400 ether);

        assertEq(credits.balanceOf(alice), 600 ether);
    }

    function testBurnOnlyOwner() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        vm.prank(alice);
        vm.expectRevert();
        credits.burn(alice, 400 ether);
    }

    // ============ EIP-3009 transferWithAuthorization Tests ============

    function testTransferWithAuthorization() public {
        // Mint tokens to alice
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        // Create authorization parameters
        uint256 value = 100 ether;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("unique-nonce-1");

        // Create the digest for signing
        bytes32 structHash = keccak256(
            abi.encode(
                credits.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(),
                alice,
                bob,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", credits.DOMAIN_SEPARATOR(), structHash)
        );

        // Alice signs the authorization
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        // Facilitator executes the transfer
        vm.prank(facilitator);
        credits.transferWithAuthorization(
            alice,
            bob,
            value,
            validAfter,
            validBefore,
            nonce,
            v,
            r,
            s
        );

        assertEq(credits.balanceOf(alice), 900 ether);
        assertEq(credits.balanceOf(bob), 100 ether);
    }

    function testTransferWithAuthorizationReplayProtection() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        uint256 value = 100 ether;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("unique-nonce-2");

        bytes32 structHash = keccak256(
            abi.encode(
                credits.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(),
                alice,
                bob,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", credits.DOMAIN_SEPARATOR(), structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        // First transfer should succeed
        credits.transferWithAuthorization(
            alice, bob, value, validAfter, validBefore, nonce, v, r, s
        );

        // Second transfer with same nonce should fail
        vm.expectRevert(Credits.AuthorizationAlreadyUsed.selector);
        credits.transferWithAuthorization(
            alice, bob, value, validAfter, validBefore, nonce, v, r, s
        );
    }

    function testTransferWithAuthorizationExpired() public {
        // Warp to a reasonable timestamp to avoid underflow
        vm.warp(1000000);

        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        uint256 value = 100 ether;
        uint256 validAfter = block.timestamp - 2 hours;
        uint256 validBefore = block.timestamp - 1 hours; // Already expired
        bytes32 nonce = keccak256("unique-nonce-3");

        bytes32 structHash = keccak256(
            abi.encode(
                credits.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(),
                alice,
                bob,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", credits.DOMAIN_SEPARATOR(), structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        vm.expectRevert(Credits.AuthorizationExpired.selector);
        credits.transferWithAuthorization(
            alice, bob, value, validAfter, validBefore, nonce, v, r, s
        );
    }

    // ============ EIP-3009 receiveWithAuthorization Tests ============

    function testReceiveWithAuthorization() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        uint256 value = 100 ether;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("unique-nonce-4");

        bytes32 structHash = keccak256(
            abi.encode(
                credits.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                alice,
                bob,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", credits.DOMAIN_SEPARATOR(), structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        // Bob (the payee) must call receiveWithAuthorization
        vm.prank(bob);
        credits.receiveWithAuthorization(
            alice, bob, value, validAfter, validBefore, nonce, v, r, s
        );

        assertEq(credits.balanceOf(alice), 900 ether);
        assertEq(credits.balanceOf(bob), 100 ether);
    }

    function testReceiveWithAuthorizationCallerMustBePayee() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        uint256 value = 100 ether;
        uint256 validAfter = block.timestamp - 1;
        uint256 validBefore = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("unique-nonce-5");

        bytes32 structHash = keccak256(
            abi.encode(
                credits.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(),
                alice,
                bob,
                value,
                validAfter,
                validBefore,
                nonce
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", credits.DOMAIN_SEPARATOR(), structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        // Someone other than bob tries to call - should fail
        vm.prank(facilitator);
        vm.expectRevert(Credits.CallerMustBePayee.selector);
        credits.receiveWithAuthorization(
            alice, bob, value, validAfter, validBefore, nonce, v, r, s
        );
    }

    // ============ Cancel Authorization Tests ============

    function testCancelAuthorization() public {
        bytes32 nonce = keccak256("unique-nonce-6");

        bytes32 structHash = keccak256(
            abi.encode(credits.CANCEL_AUTHORIZATION_TYPEHASH(), alice, nonce)
        );

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", credits.DOMAIN_SEPARATOR(), structHash)
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePrivateKey, digest);

        credits.cancelAuthorization(alice, nonce, v, r, s);

        assertTrue(credits.authorizationState(alice, nonce));
    }

    // ============ Basic ERC20 Tests ============

    function testTransfer() public {
        vm.prank(owner);
        credits.mint(alice, 1000 ether);

        vm.prank(alice);
        credits.transfer(bob, 100 ether);

        assertEq(credits.balanceOf(alice), 900 ether);
        assertEq(credits.balanceOf(bob), 100 ether);
    }

    function testTokenMetadata() public view {
        assertEq(credits.name(), "Credits");
        assertEq(credits.symbol(), "CRED");
        assertEq(credits.decimals(), 18);
    }
}

