// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/console.sol";

/**
 * @title SafeCall
 * @notice Perform low level safe calls
 */
library SafeCall {
    /**
     * @notice Perform a low level call without copying any returndata
     *
     * @param _target   Address to call
     * @param _gas      Amount of gas to pass to the call
     * @param _value    Amount of value to pass to the call
     * @param _calldata Calldata to pass to the call
     */
    function call(
        address _target,
        uint256 _gas,
        uint256 _value,
        bytes memory _calldata
    ) internal returns (bool) {
        bool _success;
        assembly {
            _success := call(
                _gas, // gas
                _target, // recipient
                _value, // ether value
                add(_calldata, 32), // inloc
                mload(_calldata), // inlen
                0, // outloc
                0 // outlen
            )
        }
        return _success;
    }

    /**
     * @notice Perform a low level call without copying any returndata. This function
     *         will revert if the call cannot be performed with the specified minimum
     *         gas.
     *
     * @param _target   Address to call
     * @param _minGas   The minimum amount of gas that may be passed to the call
     * @param _value    Amount of value to pass to the call
     * @param _calldata Calldata to pass to the call
     */
    function callWithMinGas(
        address _target,
        uint256 _minGas,
        uint256 _value,
        bytes memory _calldata
    ) internal returns (bool) {
        bool _success;
        assembly {
            // Assertion: gasleft() >= ((_minGas + 200) * 64) / 63
            //
            // Because EIP-150 ensures that, a maximum of 63/64ths of the remaining gas in the call
            // frame may be passed to a subcontext, we need to ensure that the gas will not be
            // truncated to hold this function's invariant: "If a call is performed by
            // `callWithMinGas`, it must receive at least the specified minimum gas limit." In
            // addition, exactly 51 gas is consumed between the below `GAS` opcode and the `CALL`
            // opcode, so it is factored in with some extra room for error.
            if lt(gas(), div(mul(64, add(_minGas, 200)), 63)) {
                // Store the "Error(string)" selector in scratch space.
                mstore(0, 0x08c379a0)
                // Store the pointer to the string length in scratch space.
                mstore(32, 32)
                // Store the string.
                //
                // SAFETY:
                // - We pad the beginning of the string with two zero bytes as well as the
                // length (24) to ensure that we override the free memory pointer at offset
                // 0x40. This is necessary because the free memory pointer is likely to
                // be greater than 1 byte when this function is called, but it is incredibly
                // unlikely that it will be greater than 3 bytes. As for the data within
                // 0x60, it is ensured that it is 0 due to 0x60 being the zero offset.
                // - It's fine to clobber the free memory pointer, we're reverting.
                mstore(88, 0x0000185361666543616c6c3a204e6f7420656e6f75676820676173)

                // Revert with 'Error("SafeCall: Not enough gas")'
                revert(28, 100)
            }

            // The call will be supplied at least (((_minGas + 200) * 64) / 63) - 49 gas due to the
            // above assertion. This ensures that, in all circumstances, the call will
            // receive at least the minimum amount of gas specified.
            // We can prove this property by solving the inequalities:
            // ((((_minGas + 200) * 64) / 63) - 49) >= _minGas
            // ((((_minGas + 200) * 64) / 63) - 51) * (63 / 64) >= _minGas
            // Both inequalities hold true for all possible values of `_minGas`.
            _success := call(
                gas(), // gas
                _target, // recipient
                _value, // ether value
                add(_calldata, 32), // inloc
                mload(_calldata), // inlen
                0x00, // outloc
                0x00 // outlen
            )
        }
        return _success;
    }
}


contract RelayMessagerReentrancy {

    mapping(bytes32 => bool) failedMessages;

    mapping(bytes32 => bool) successfulMessages;

    mapping(bytes32 => bool) reentrancyLocks;

    address DEFAULT_L2_SENDER = address(1000);
    address ESTIMATION_ADDRESS = address(2000);

    address xDomainMsgSender;

    /**
     * @notice Emitted whenever a message is successfully relayed on this chain.
     *
     * @param msgHash Hash of the message that was relayed.
     */
    event RelayedMessage(bytes32 indexed msgHash);

    /**
     * @notice Emitted whenever a message fails to be relayed on this chain.
     *
     * @param msgHash Hash of the message that failed to be relayed.
     */
    event FailedRelayedMessage(bytes32 indexed msgHash);

    address public otherContract;

    constructor(address _otherContract) {
        otherContract = _otherContract;
    }

    function _isOtherMessenger() internal view returns (bool) {
        // return msg.sender == otherContract;
        return true;
    }

     /**
     * @notice Encodes a cross domain message based on the V0 (legacy) encoding.
     *
     * @param _target Address of the target of the message.
     * @param _sender Address of the sender of the message.
     * @param _data   Data to send with the message.
     * @param _nonce  Message nonce.
     *
     * @return Encoded cross domain message.
     */
    function encodeCrossDomainMessageV0(
        address _target,
        address _sender,
        bytes memory _data,
        uint256 _nonce
    ) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature(
                "relayMessage(address,address,bytes,uint256)",
                _target,
                _sender,
                _data,
                _nonce
            );
    }

    /**
     * @notice Encodes a cross domain message based on the V1 (current) encoding.
     *
     * @param _nonce    Message nonce.
     * @param _sender   Address of the sender of the message.
     * @param _target   Address of the target of the message.
     * @param _value    ETH value to send to the target.
     * @param _gasLimit Gas limit to use for the message.
     * @param _data     Data to send with the message.
     *
     * @return Encoded cross domain message.
     */
    function encodeCrossDomainMessageV1(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _gasLimit,
        bytes memory _data
    ) internal pure returns (bytes memory) {
        return
            abi.encodeWithSignature(
                "relayMessage(uint256,address,address,uint256,uint256,bytes)",
                _nonce,
                _sender,
                _target,
                _value,
                _gasLimit,
                _data
            );
    }


    function hashCrossDomainMessageV0(
        address _target,
        address _sender,
        bytes memory _data,
        uint256 _nonce
    ) internal pure returns (bytes32) {
        return keccak256(encodeCrossDomainMessageV0(_target, _sender, _data, _nonce));
    }

    function hashCrossDomainMessageV1(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _gasLimit,
        bytes memory _data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                encodeCrossDomainMessageV1(
                    _nonce,
                    _sender,
                    _target,
                    _value,
                    _gasLimit,
                    _data
                )
            );
    }

    function relayMessage(
        uint256 _nonce,
        address _sender,
        address _target,
        uint256 _value,
        uint256 _minGasLimit,
        bytes calldata _message
    ) external payable {

        uint256 version = 0;

        if( _nonce > 10) {
            version = 1;
        }

        require(
            version < 2,
            "CrossDomainMessenger: only version 0 or 1 messages are supported at this time"
        );

        // If the message is version 0, then it's a migrated legacy withdrawal. We therefore need
        // to check that the legacy version of the message has not already been relayed.

        bytes32 oldHash = hashCrossDomainMessageV0(_target, _sender, _message, _nonce);

        if (version == 0) {
            require(
                successfulMessages[oldHash] == false,
                "CrossDomainMessenger: legacy withdrawal already relayed"
            );
        }

        bytes32 versionedHash = hashCrossDomainMessageV1(
            _nonce,
            _sender,
            _target,
            _value,
            _minGasLimit,
            _message
        );

         // Check if the reentrancy lock for the `versionedHash` is already set.
        if (reentrancyLocks[versionedHash]) {
            revert("ReentrancyGuard: reentrant call");
        }
        // Trigger the reentrancy lock for `versionedHash`
        reentrancyLocks[versionedHash] = true;

        if (_isOtherMessenger()) {
            // These properties should always hold when the message is first submitted (as
            // opposed to being replayed).
            assert(msg.value == _value);
            assert(!failedMessages[versionedHash]);
        } else {
            require(
                msg.value == 0,
                "CrossDomainMessenger: value must be zero unless message is from a system address"
            );
            require(
                failedMessages[versionedHash],
                "CrossDomainMessenger: message cannot be replayed"
            );
        }

        require(
            successfulMessages[versionedHash] == false,
            "CrossDomainMessenger: message has already been relayed"
        );

        xDomainMsgSender = _sender;
    
        bool success = SafeCall.callWithMinGas(_target, _minGasLimit, _value, _message);

        uint256 glBefore = gasleft();

        console.log("gas left after externall call");
        console.log(glBefore);

        xDomainMsgSender = DEFAULT_L2_SENDER;

        if (success) {
            successfulMessages[versionedHash] = true;
            emit RelayedMessage(versionedHash);
        } else {
            failedMessages[versionedHash] = true;
            emit FailedRelayedMessage(versionedHash);

             if (tx.origin == ESTIMATION_ADDRESS) {
                revert("CrossDomainMessenger: failed to relay message");
            }
        }

        // Clear the reentrancy lock for `versionedHash`
        reentrancyLocks[versionedHash] = false;

        uint256 glAfter = gasleft();

        console.log("gas needed after external call");
        console.log(glBefore - glAfter);

    }
    

}


