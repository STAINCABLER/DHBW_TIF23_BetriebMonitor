// Transaction-Token: 0x9239c009C6CBE03C33F044D7ad67A609f510bD53
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract token {

    string public name = "DHBW-TIF-Token";
    string public symbol = "TIF";
    uint public totalSupply = 1000;
    uint public decimals = 0;

    mapping(address => uint256) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address receiver, uint256 value) public returns (bool) {

        balanceOf[msg.sender] -= value;
        balanceOf[receiver] += value;
        return true;
    }
}