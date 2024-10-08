// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

/**
 * @title IERC20UpgradeableCustom
 * @dev Interface extension of IERC20Upgradeable to include minting and burning operations.
 */
interface IERC20UpgradeableCustom is IERC20Upgradeable {
    function mint(address account, uint256 amount) external;
    function burn(uint256 amount) external;
}

/**
 * @title CrossChainBridge
 * @dev Contract for bridging tokens across different chains.
 * Handles locking, minting, burning, and unlocking of tokens to facilitate cross-chain transfers.
 */
contract CrossChainBridge is
    Initializable,
    AccessControlUpgradeable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Define roles for access control
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    // Nonce tracking to prevent replay attacks
    mapping(bytes32 => bool) private _nonces;

    // Define custom errors
    error InvalidNonce();
    error InsufficientAccountBalance();
    error InsufficientContractBalance();
    
    // Events
    event LockTokenEvent(address indexed account, uint256 amount, bytes32 indexed nonce);
    event UnlockTokenEvent(address indexed account, uint256 amount, bytes32 indexed nonce);
    event MintTokenEvent(address indexed account, uint256 amount, bytes32 indexed nonce);
    event BurnTokenEvent(address indexed account, uint256 amount, bytes32 indexed nonce);
    event PauseEvent();
    event UnpauseEvent();
    event WithdrawEtherEvent(address indexed account, uint256 amount);
    event WithdrawERC20Event(address indexed token, address indexed account, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract, setting up roles and initializing inherited contracts.
     * Grants necessary roles to the specified admin address.
     * @param admin The address to be granted admin roles.
     */
    function initialize(address admin) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        // Grant roles to the specified admin address
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);
    }

    /**
     * @dev Locks tokens to facilitate cross-chain transfers.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param account The account whose tokens will be locked.
     * @param amount The amount of tokens to lock.
     * @param nonce The unique transaction identifier.
     */
    function lockToken(address token, address account, uint256 amount, bytes32 nonce) public onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Ensure the account has enough balance
        if (IERC20Upgradeable(token).balanceOf(account) < amount) revert InsufficientAccountBalance();

        // Transfer tokens from the account to this contract
        IERC20Upgradeable(token).safeTransferFrom(account, address(this), amount);

        emit LockTokenEvent(account, amount, nonce);
    }

    /**
     * @dev Unlocks tokens after cross-chain transfer.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param account The account whose tokens will be unlocked.
     * @param amount The amount of tokens to unlock.
     * @param nonce The unique transaction identifier.
     */
    function unlockToken(address token, address account, uint256 amount, bytes32 nonce) public onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;
        
        // Ensure the contract has enough balance
        if (IERC20Upgradeable(token).balanceOf(address(this)) < amount) revert InsufficientContractBalance();

        // Transfer tokens from the contract to the account
        IERC20Upgradeable(token).safeTransfer(account, amount);

        emit UnlockTokenEvent(account, amount, nonce);
    }

    /**
     * @dev Mints tokens on the receiving chain.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param account The account to receive the minted tokens.
     * @param amount The amount of tokens to mint.
     * @param nonce The unique transaction identifier.
     */
    function mintToken(address token, address account, uint256 amount, bytes32 nonce) public onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Mint new tokens to the account
        IERC20UpgradeableCustom(token).mint(account, amount);

        emit MintTokenEvent(account, amount, nonce);
    }


    /**
     * @dev Burns tokens when bridging back to the original chain.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param account The account whose tokens will be burned.
     * @param amount The amount of tokens to burn.
     * @param nonce The unique transaction identifier.
     */
    function burnToken(address token, address account, uint256 amount, bytes32 nonce) public onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Ensure the account has enough balance to burn
        if (IERC20Upgradeable(token).balanceOf(account) < amount) revert InsufficientAccountBalance();

        // Transfer tokens to this contract, then burn them
        IERC20Upgradeable(token).safeTransferFrom(account, address(this), amount);
        IERC20UpgradeableCustom(token).burn(amount);

        emit BurnTokenEvent(account, amount, nonce);
    }

    /**
     * @dev Locks Ether for cross-chain transfer.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param account The account whose Ether will be locked.
     * @param amount The amount of Ether to lock.
     * @param nonce The unique transaction identifier.
     */
    function lockEther(address account, uint256 amount, bytes32 nonce) public payable whenNotPaused nonReentrant onlyRole(MANAGER_ROLE) {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Emit event for locking Ether on behalf of the specified user account
        emit LockTokenEvent(account, amount, nonce);
    }

    /**
     * @dev Unlocks Ether after cross-chain transfer.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param account The account whose Ether will be unlocked.
     * @param amount The amount of Ether to unlock.
     * @param nonce The unique transaction identifier.
     */
    function unlockEther(address payable account, uint256 amount, bytes32 nonce) public onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Ensure the contract has enough balance
        if (address(this).balance < amount) revert InsufficientContractBalance();

        account.transfer(amount);
        emit UnlockTokenEvent(account, amount, nonce);
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
     * @dev Unpauses the contract.
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
    function withdrawEther(uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE)
    {
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
     * @dev Authorizes contract upgrades. Only callable by addresses with the UPGRADER_ROLE.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
}