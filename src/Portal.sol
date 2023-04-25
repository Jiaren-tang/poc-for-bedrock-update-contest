// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/console.sol";

import "./RelayMessagerReentrancy.sol";

contract Portal {

    address messenger;

    constructor(address _messenger) {
        messenger = _messenger;
    }

    function finalizeWithdraw(uint256 minGas, uint256 value, bytes memory data) public payable {

        console.logBytes4(bytes4(keccak256("withdraw(uint256)")));
        console.logBytes4(bytes4(keccak256(abi.encodeWithSignature("withdraw(uint256)"))));

        
        bool success = SafeCall.callWithMinGas(
            messenger, 
            minGas, 
            value, 
            data
        );

        console.log("success after finalize withdraw????");
        console.log(success);
    }   

}