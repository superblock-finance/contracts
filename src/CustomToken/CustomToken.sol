// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/draft-ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

/**
 * @title CustomToken
 * @dev Implementation of an upgradeable ERC20 token with additional features like burn, pause, and permit.
 */
contract CustomToken is Initializable, ERC20Upgradeable, ERC20BurnableUpgradeable, ERC20PausableUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Define roles for access control
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    // Events
    event MintEvent(address indexed to, uint256 amount);
    event BurnEvent(address indexed from, uint256 amount);
    event PauseEvent();
    event UnpauseEvent();
    event WithdrawERC20Event(address indexed token, address indexed to, uint256 amount);
    event WithdrawEtherEvent(address indexed to, uint256 amount);

    // Custom errors
    error InsufficientContractBalance();
    error ZeroAddress();
    error InvalidAmount();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

     /**
     * @dev Initializes the token with a name, symbol, and grants roles to a specified admin.
     */
    function initialize(string memory name, string memory symbol, address admin) initializer public {
        __ERC20_init(name, symbol);
        __ERC20Burnable_init();
        __ERC20Pausable_init();
        __AccessControl_init();
        __ERC20Permit_init(name);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        // Grant roles to the specified admin address
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(BURNER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);
    }

    /**
     * @dev Mints new tokens to a specified address.
     * Can only be called by an address with the MINTER_ROLE.
     * @param to The address to receive the tokens.
     * @param amount The amount of tokens to mint.
     */
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) whenNotPaused {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();
        _mint(to, amount);
        emit MintEvent(to, amount);
    }

    /**
     * @dev Burns tokens from the caller's account.
     * Can only be called by an address with the BURNER_ROLE.
     * @param amount The amount of tokens to burn.
     */
    function burn(uint256 amount) public onlyRole(BURNER_ROLE) whenNotPaused override {
        if (amount == 0) revert InvalidAmount();
        super.burn(amount);
        emit BurnEvent(_msgSender(), amount);
    }

    /**
     * @dev Burns tokens from a specified address using allowance mechanism.
     * Can be called by any spender who has allowance to burn tokens.
     * @param from The address to burn tokens from.
     * @param amount The amount of tokens to burn.
     */
    function burnFrom(address from, uint256 amount) public onlyRole(BURNER_ROLE) whenNotPaused override {
        if (from == address(0)) revert ZeroAddress();
        if (amount == 0) revert InvalidAmount();
        super.burnFrom(from, amount);
        emit BurnEvent(msg.sender, amount);
    }
    
    /**
     * @dev Pauses the contract, disabling certain functions.
     * Only callable by addresses with the PAUSER_ROLE.
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
        emit PauseEvent();
    }

    /**
     * @dev Unpauses all token transfers.
     * Only callable by addresses with the PAUSER_ROLE.
     */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
        emit UnpauseEvent();
    }

    /**
     * @dev Withdraws mistakenly sent ether from the contract.
     * @param amount The amount of Ether to withdraw.
     */
    function withdrawEther(uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE) {
        // Ensure the contract has enough balance
        if (address(this).balance < amount) revert InsufficientContractBalance();

        payable(_msgSender()).transfer(amount);
        emit WithdrawEtherEvent(_msgSender(), amount);
    }

    /**
     * @dev Withdraws mistakenly sent ERC20 tokens from the contract.
     * @param tokenAddress The address of the ERC20 token.
     * @param amount The amount of tokens to withdraw.
     */
    function withdrawERC20(address tokenAddress, uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE) {
        IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
        uint256 contractBalance = token.balanceOf(address(this));
        
        // Ensure the contract has enough balance
        if (contractBalance < amount) revert InsufficientContractBalance();

        token.safeTransfer(_msgSender(), amount);
        emit WithdrawERC20Event(tokenAddress, _msgSender(), amount);
    }

    /**
     * @dev Override for the token transfer hook that includes pause functionality.
     */
    function _update(address from, address to, uint256 value) internal override(ERC20Upgradeable, ERC20PausableUpgradeable) {
        super._update(from, to, value);
    }

    /**
     * @dev Authorizes contract upgrades. Only callable by addresses with the UPGRADER_ROLE.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
