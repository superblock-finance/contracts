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
 * @title CustomFiatToken
 * @dev Implementation of an upgradeable ERC20 token with burn, pause, permit, freeze, and blacklist features.
 * Includes role-based access control for minting, burning, pausing, upgrading, freezing, and blacklisting.
 */
contract CustomFiatToken is Initializable, ERC20Upgradeable, ERC20BurnableUpgradeable, ERC20PausableUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Define roles for access control
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant FREEZER_ROLE = keccak256("FREEZER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    // Store mappings for frozen and blacklisted accounts
    mapping(address => bool) private _frozenAccounts;
    mapping(address => bool) private _blacklistedAccounts;

    // Events
    event MintEvent(address indexed to, uint256 amount);
    event BurnEvent(address indexed from, uint256 amount);
    event FreezeEvent(address indexed account);
    event UnfreezeEvent(address indexed account);
    event BlacklistEvent(address indexed account);
    event UnblacklistEvent(address indexed account);
    event PauseEvent();
    event UnpauseEvent();
    event WithdrawEtherEvent(address indexed to, uint256 amount);
    event WithdrawERC20Event(address indexed token, address indexed to, uint256 amount);

    // Custom errors
    error AccountFrozen(address account);
    error AccountBlacklisted(address account);
    error InsufficientContractBalance();
    error ZeroAddress();
    error InvalidAmount();
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract, sets the initial roles and permissions.
     * This function should be called only once during deployment.
     */
    function initialize(string memory name, string memory symbol, address admin) initializer public {
        __ERC20_init(name, symbol);
        __ERC20Burnable_init();
        __ERC20Pausable_init();
        __AccessControl_init();
        __ERC20Permit_init(name);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
        _grantRole(BURNER_ROLE, admin);
        _grantRole(FREEZER_ROLE, admin);
        _grantRole(BLACKLISTER_ROLE, admin);
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
     * @dev Pauses all token transfers.
     * Can only be called by an address with the PAUSER_ROLE.
     * Emits a PauseEvent.
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
        emit PauseEvent();
    }

    /**
     * @dev Unpauses all token transfers.
     * Can only be called by an address with the PAUSER_ROLE.
     * Emits an UnpauseEvent.
     */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
        emit UnpauseEvent();
    }

    /**
     * @dev Freezes an account, preventing it from transferring tokens.
     * Can only be called by an address with the FREEZER_ROLE.
     * @param account The account to freeze.
     */
    function freeze(address account) public onlyRole(FREEZER_ROLE) {
        _frozenAccounts[account] = true;
        emit FreezeEvent(account);
    }

    /**
     * @dev Unfreezes an account, allowing it to transfer tokens again.
     * Can only be called by an address with the FREEZER_ROLE.
     * @param account The account to unfreeze.
     */
    function unfreeze(address account) public onlyRole(FREEZER_ROLE) {
        _frozenAccounts[account] = false;
        emit UnfreezeEvent(account);
    }

    /**
     * @dev Checks if an account is frozen.
     * @param account The account to check.
     * @return bool True if the account is frozen, false otherwise.
     */
    function isFrozen(address account) public view returns (bool) {
        return _frozenAccounts[account];
    }

    /**
     * @dev Blacklists an account, preventing it from participating in token transfers.
     * Can only be called by an address with the BLACKLISTER_ROLE.
     * @param account The account to blacklist.
     */
    function blacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _blacklistedAccounts[account] = true;
        emit BlacklistEvent(account);
    }

    /**
     * @dev Removes an account from the blacklist, allowing it to participate in token transfers.
     * Can only be called by an address with the BLACKLISTER_ROLE.
     * @param account The account to remove from the blacklist.
     */
    function unblacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _blacklistedAccounts[account] = false;
        emit UnblacklistEvent(account);
    }

    /**
     * @dev Checks if an account is blacklisted.
     * @param account The account to check.
     * @return bool True if the account is blacklisted, false otherwise.
     */
    function isBlacklisted(address account) public view returns (bool) {
        return _blacklistedAccounts[account];
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
     * @dev Override for the token transfer hook that includes pause functionality and blacklist check.
     * Prevents frozen or blacklisted accounts from sending or receiving tokens.
     */
    function _update(address from, address to, uint256 value) internal override(ERC20Upgradeable, ERC20PausableUpgradeable) {
        if (_frozenAccounts[from]) revert AccountFrozen(from);
        if (_frozenAccounts[to]) revert AccountFrozen(to);        
        if (_blacklistedAccounts[from]) revert AccountBlacklisted(from);
        if (_blacklistedAccounts[to]) revert AccountBlacklisted(to);
        super._update(from, to, value);
    }

    /**
     * @dev Authorizes contract upgrades. Only callable by addresses with the UPGRADER_ROLE.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
