// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title Vault
 * @dev A simple vault contract that securely holds tokens and allows only the owner to manage the stored assets.
 */
contract Vault is Ownable {
    using SafeERC20 for IERC20;

    // Events
    event DepositEvent(address indexed from, address indexed token, uint256 amount);
    event WithdrawEvent(address indexed to, address indexed token, uint256 amount);
    event ApproveSpenderEvent(address indexed spender, address indexed token, uint256 amount);

    // Custom errors
    error InvalidAmount();
    error InsufficientContractBalance();

    /**
     * @dev Constructor that sets the initial owner of the contract.
     * @param initialOwner The address of the initial owner.
     */
    constructor(address initialOwner) Ownable(initialOwner) {}

    /**
     * @dev Deposits tokens into the vault. If the 'from' address is not provided (i.e., address(0)), it defaults to the caller's address.
     * @param from The address from which the tokens will be transferred. If address(0), defaults to msg.sender.
     * @param token The address of the ERC20 token to deposit.
     * @param amount The amount of tokens to deposit.
     */
    function deposit(address from, address token, uint256 amount) external onlyOwner {
        if (amount == 0) revert InvalidAmount();

        // If 'from' is address(0), default to msg.sender
        address depositFrom = from == address(0) ? msg.sender : from;

        IERC20(token).safeTransferFrom(depositFrom, address(this), amount);
        emit DepositEvent(depositFrom, token, amount);
    }

    /**
     * @dev Withdraws tokens from the vault. If the 'to' address is not provided (i.e., address(0)), it defaults to the caller's address.
     * @param to The address that will receive the withdrawn tokens. If address(0), defaults to msg.sender.
     * @param token The address of the ERC20 token to withdraw.
     * @param amount The amount of tokens to withdraw.
     */
    function withdraw(address to, address token, uint256 amount) external onlyOwner {
        uint256 contractBalance = IERC20(token).balanceOf(address(this));
        if (contractBalance < amount) revert InsufficientContractBalance();

        // If 'to' is address(0), default to msg.sender
        address withdrawTo = to == address(0) ? msg.sender : to;

        IERC20(token).safeTransfer(withdrawTo, amount);
        emit WithdrawEvent(withdrawTo, token, amount);
    }

    /**
     * @dev Returns the ETH balance of the vault.
     * @return The ETH balance of the vault.
     */
    function getETHBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Returns the balance of a specific ERC20 token held by the vault.
     * @param token The address of the ERC20 token.
     * @return The balance of the specified token.
     */
    function getTokenBalance(address token) public view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    /**
     * @dev Approves a spender to transfer a certain amount of tokens on behalf of the vault.
     * @param spender The address of the spender contract.
     * @param token The address of the ERC20 token to approve.
     * @param amount The amount of tokens the spender is allowed to transfer.
     */
    function approveSpender(address spender, address token, uint256 amount) external onlyOwner {
        IERC20(token).approve(spender, amount);
        emit ApproveSpenderEvent(spender, token, amount);
    }
}
