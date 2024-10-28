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
 * This contract supports the use of an external vault for token storage, defaulting to the bridge contract's address if no vault is specified.
 */
contract CrossChainBridge is Initializable, AccessControlUpgradeable, UUPSUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Define roles for access control
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    // Nonce tracking to prevent replay attacks
    mapping(bytes32 => bool) private _nonces;
   
    // Events
    event BridgeTokenEvent(address indexed token, uint256 amount, address indexed account, bytes32 indexed nonce, uint256 sourceChainId, uint256 destinationChainId);
    event ReleaseTokenEvent(address indexed token, uint256 amount, address indexed account, bytes32 indexed nonce, uint256 sourceChainId, uint256 destinationChainId, bytes32 bridgeTokenNonce);

    event LockTokenEvent(address indexed token, uint256 amount, address indexed account, bytes32 indexed nonce, address vault, uint256 sourceChainId, uint256 destinationChainId);
    event BurnTokenEvent(address indexed token, uint256 amount, address indexed account, bytes32 indexed nonce, uint256 sourceChainId, uint256 destinationChainId);
    event MintTokenEvent(address indexed token, uint256 amount, address indexed account, bytes32 indexed nonce, uint256 sourceChainId, uint256 destinationChainId, bytes32 bridgeTokenNonce);
    event UnlockTokenEvent(address indexed token, uint256 amount, address indexed account, bytes32 indexed nonce, address vault, uint256 sourceChainId, uint256 destinationChainId, bytes32 bridgeTokenNonce);
    event PauseEvent();
    event UnpauseEvent();
    event WithdrawEtherEvent(address indexed to, uint256 amount);
    event WithdrawERC20Event(address indexed token, address indexed to, uint256 amount);

    // Custom errors
    error InvalidNonce();
    error InsufficientAccountBalance();
    error InsufficientContractBalance();
    error InvalidVaultAddress();

    address public vaultAddress;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract, setting up roles and initializing inherited contracts.
     * Grants necessary roles to the specified admin address.
     * @param admin The address to be granted admin roles.
     * @param _vaultAddress Address where tokens are stored.
     */
    function initialize(address _vaultAddress, address admin) public initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        vaultAddress = _vaultAddress;

        // Grant roles to the specified admin address
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);
    }

    /**
     * @dev Initiates the bridging process of tokens to another chain.
     * Depending on the `isLockMode` flag, it will either lock or burn the tokens.
     * - If `isLockMode` is true, tokens are locked in the vault.
     * - If `isLockMode` is false, tokens are burned.
     * Emits a {BridgeTokenEvent}.
     * @param token The address of the token to bridge.
     * @param account The account initiating the bridge.
     * @param amount The amount of tokens to bridge.
     * @param nonce A unique identifier to prevent replay attacks.
     * @param destinationChainId The ID of the destination chain.
     * @param isLockMode Indicates whether to lock (true) or burn (false) tokens.
     */
    function bridgeToken(address token, address account, uint256 amount, bytes32 nonce, uint256 destinationChainId, bool isLockMode) external onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {      
        if (isLockMode) {
            lockToken(token, account, amount, nonce, destinationChainId);
        } else {
            burnToken(token, account, amount, nonce, destinationChainId);
        }

        emit BridgeTokenEvent(token, amount, account, nonce, block.chainid, destinationChainId);
    }

    /**
     * @dev Completes the bridging process by releasing tokens on the destination chain.
     * Depending on the `isMintMode` flag, it will either mint or unlock the tokens.
     * - If `isMintMode` is true, new tokens are minted to the account.
     * - If `isMintMode` is false, tokens are unlocked from the vault.
     * Emits a {ReleaseTokenEvent}.
     * @param token The address of the token to release.
     * @param account The account that will receive the tokens.
     * @param amount The amount of tokens to release.
     * @param nonce A unique identifier to prevent replay attacks.
     * @param sourceChainId The ID of the chain where tokens were originally bridged from.
     * @param bridgeTokenNonce The nonce used in the corresponding {bridgeToken} call.
     * @param isMintMode Indicates whether to mint (true) or unlock (false) tokens.
     */
    function releaseToken(address token, address account, uint256 amount, bytes32 nonce, uint256 sourceChainId, bytes32 bridgeTokenNonce, bool isMintMode) external onlyRole(MANAGER_ROLE) whenNotPaused nonReentrant {
        if (isMintMode) {
            mintToken(token, account, amount, nonce, sourceChainId, bridgeTokenNonce);
        } else {
            unlockToken(token, account, amount, nonce, sourceChainId, bridgeTokenNonce);
        }

        emit ReleaseTokenEvent(token, amount, account, nonce, sourceChainId, block.chainid, bridgeTokenNonce);
    }

    /**
     * @dev Locks tokens by transferring them from the user's account to the vault.
     * Used when bridging tokens from their original chain.
     * Emits a {LockTokenEvent}.
     * @param token The address of the token to lock.
     * @param account The account whose tokens will be locked.
     * @param amount The amount of tokens to lock.
     * @param nonce A unique identifier to prevent replay attacks.
     * @param destinationChainId The ID of the chain where tokens will be released.
     */
    function lockToken(address token, address account, uint256 amount, bytes32 nonce, uint256 destinationChainId) private {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;
       
        if (token == address(0)) {
            // Ensure the account has enough Ether balance
            if (account.balance < amount) revert InsufficientAccountBalance();
        } else {
            // Ensure the account has enough token balance
            if (IERC20Upgradeable(token).balanceOf(account) < amount) revert InsufficientAccountBalance();
        }

        // Lock tokens or Ether to the vault contract on the receiving chain
        IERC20Upgradeable(token).safeTransferFrom(account, vaultAddress, amount);

        emit LockTokenEvent(token, amount, account, nonce, vaultAddress, block.chainid, destinationChainId);
    }

    /**
     * @dev Burns tokens from the user's account.
     * Used when bridging tokens from a non-original chain.
     * Emits a {BurnTokenEvent}.
     * @param token The address of the token to burn.
     * @param account The account whose tokens will be burned.
     * @param amount The amount of tokens to burn.
     * @param nonce A unique identifier to prevent replay attacks.
     * @param destinationChainId The ID of the chain where tokens will be released.
     */
    function burnToken(address token, address account, uint256 amount, bytes32 nonce, uint256 destinationChainId) private {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Ensure the account has enough balance to burn
        if (IERC20Upgradeable(token).balanceOf(account) < amount) revert InsufficientAccountBalance();

        // Transfer tokens to this contract, then burn them
        IERC20Upgradeable(token).safeTransferFrom(account, address(this), amount);
        IERC20UpgradeableCustom(token).burn(amount);

        emit BurnTokenEvent(token, amount, account, nonce, block.chainid, destinationChainId);
    }

    /**
     * @dev Mints new tokens to the specified account.
     * Used when tokens are bridged to a chain where they don't originally exist.
     * @param token The address of the token to mint.
     * @param account The account that will receive the minted tokens.
     * @param amount The amount of tokens to mint.
     * @param nonce A unique identifier to prevent replay attacks.
     * @param sourceChainId The ID of the chain where the tokens were bridged from.
     * @param bridgeTokenNonce The nonce used in the corresponding {bridgeToken} call on the source chain.
     */
    function mintToken(address token, address account, uint256 amount, bytes32 nonce, uint256 sourceChainId, bytes32 bridgeTokenNonce) private {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;

        // Mint new tokens to the account
        IERC20UpgradeableCustom(token).mint(account, amount);

        emit MintTokenEvent(token, amount, account, nonce, sourceChainId, block.chainid, bridgeTokenNonce);
    }

    /**
     * @dev Unlocks tokens from the vault and transfers them to the specified account.
     * Used when tokens are bridged back to their original chain.
     * @param token The address of the token to unlock.
     * @param account The account that will receive the unlocked tokens.
     * @param amount The amount of tokens to unlock.
     * @param nonce A unique identifier to prevent replay attacks.
     * @param sourceChainId The ID of the chain where the tokens were bridged from.
     * @param bridgeTokenNonce The nonce used in the corresponding {bridgeToken} call on the source chain.
     */
    function unlockToken(address token, address account, uint256 amount, bytes32 nonce, uint256 sourceChainId, bytes32 bridgeTokenNonce) private {
        if (_nonces[nonce]) revert InvalidNonce();
        _nonces[nonce] = true;
        
        if (token == address(0)) {
            // Ensure the contract has enough balance
            if (vaultAddress.balance < amount) revert InsufficientContractBalance();
        } else {
            // Ensure the contract has enough balance
            if (IERC20Upgradeable(token).balanceOf(vaultAddress) < amount) revert InsufficientContractBalance();
        }

        // Transfer tokens from vault contract to account
        IERC20Upgradeable(token).safeTransferFrom(vaultAddress, account, amount);

        emit UnlockTokenEvent(token, amount, account, nonce, vaultAddress, sourceChainId, block.chainid, bridgeTokenNonce);
    }

    /**
     * @dev Updates the vault address
     * Can only be called by an address with the DEFAULT_ADMIN_ROLE.
     * @param newVaultAddress The new address to set as the treasury.
     */
    function setVaultAddress(address newVaultAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newVaultAddress == address(0)) {
            revert InvalidVaultAddress();
        }
        vaultAddress = newVaultAddress;
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
     * @dev Authorizes contract upgrades. Only callable by addresses with the UPGRADER_ROLE.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
