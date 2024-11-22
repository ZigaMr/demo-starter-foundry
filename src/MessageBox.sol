// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MessageBox {
    string private _message;
    address public author;

    function setMessage(string calldata in_message) external {
        _message = in_message;
        author = msg.sender;
    }

    function greet() public view returns (string memory) {
        return _message;
    }

    function getMessage() external view returns (string memory) {
        // if (msg.sender != author) {
        //     revert("not allowed");
        // }
        return _message;
    }
}