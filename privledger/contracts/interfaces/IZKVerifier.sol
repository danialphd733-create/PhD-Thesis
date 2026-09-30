// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
interface IZKVerifier { function verify(uint256[] calldata inputs, bytes calldata proof) external view returns(bool); }
