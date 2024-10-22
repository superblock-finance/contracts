// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/draft-ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";

/**
 * @title StakedUSDx
 * @dev Implementation of an upgradeable staking contract for USDx tokens, following ERC4626.
 * This contract allows users to stake USDx, claim rewards, and perform pausing and account management operations.
 */
contract StakedUSDx is Initializable, ERC20Upgradeable, ERC4626Upgradeable, ERC20PausableUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Define roles for access control
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant REWARD_MANAGER_ROLE = keccak256("REWARD_MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");
    bytes32 public constant FREEZER_ROLE = keccak256("FREEZER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");

    // Define cooldown period and minimum amount of shares required for staking
    uint256 private constant COOLDOWN_PERIOD = 7 days;
    uint256 private constant MIN_SHARES = 1e18;

    // The underlying USDx token to be staked
    IERC20Upgradeable private _underlyingAsset;

    address public treasuryAddress;
    uint256 public managementFeePercentage; // basis points

    // Struct to store information about unstake requests
    struct UnstakeRequest {
        uint256 amount; // The amount of stakedUSDx requested for unstake
        uint256 claimableTimestamp; // Timestamp when unstake can be claimed after cooldown period
    }

    // Store mappings
    mapping(address => UnstakeRequest) private _unstakeRequests;
    mapping(address => uint256) private _lastUnstakeTimestamp;
    mapping(address => bool) private _frozenAccounts;
    mapping(address => bool) private _blacklistedAccounts;

    // Events
    event StakeEvent(address indexed account, uint256 assetAmount, uint256 shareAmount);
    event UnstakeEvent(address indexed account, uint256 shareAmount, uint256 assetAmount);
    event ClaimEvent(address indexed account, uint256 shareAmount, uint256 assetAmount);
    event DistributeRewardsEvent(uint256 amount);
    event FreezeEvent(address indexed account);
    event UnfreezeEvent(address indexed account);
    event BlacklistEvent(address indexed account);
    event UnblacklistEvent(address indexed account);
    event PauseEvent();
    event UnpauseEvent();
    event WithdrawEtherEvent(address indexed account, uint256 amount);
    event WithdrawERC20Event(address indexed token, address indexed account, uint256 amount);

    // Custom errors
    error AccountFrozen(address account);
    error AccountBlacklisted(address account);
    error AmountZero();
    error InsufficientAccountBalance();
    error InsufficientContractBalance();
    error ExcessiveRedeemAmount();
    error CooldownNotOver();
    error NoUnstakeRequest();
    error UnstakeRequestInCooldown();
    error MinSharesViolation();
    error InvalidManagementFeePercentage();
    error InvalidTreasuryAddress();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the StakedUSDx contract.
     * @param underlyingAsset The address of the USDx token that will be staked in this contract.
     * @param _treasuryAddress Address where fees will be sent.
     * @param admin The address that will be assigned as the default admin role.
     */
    function initialize(IERC20Upgradeable underlyingAsset, address _treasuryAddress, address admin) initializer public {
        __ERC4626_init(IERC20(address(underlyingAsset)));
        __ERC20_init("Staked USDx", "sUSDx");
        __ERC20Pausable_init();
        __AccessControl_init();
        __ERC20Permit_init("Staked USDx");
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(REWARD_MANAGER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(FREEZER_ROLE, admin);
        _grantRole(BLACKLISTER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);

        _underlyingAsset = underlyingAsset; // Underlying asset (USDx)
        treasuryAddress = _treasuryAddress;

        // Initialize default parameters
        managementFeePercentage = 1000; // 10% in basis points
    }

    /**
    * @dev Stake USDx to receive staked USDx (sUSDx) in return.
    * Transfers the specified amount of USDx from the user to the contract and mints an equivalent amount of sUSDx.
    * Checks for frozen or blacklisted accounts and ensures the user's balance is sufficient.
    * Emits the StakeEvent.
    * @param assets The amount of USDx to stake.
    * @return The amount of sUSDx minted for the user.
    */
    function stake(uint256 assets) public whenNotPaused nonReentrant returns (uint256) {
        if (_frozenAccounts[msg.sender]) revert AccountFrozen(msg.sender);
        if (_blacklistedAccounts[msg.sender]) revert AccountBlacklisted(msg.sender);
        if (assets == 0) revert AmountZero();
        if (_underlyingAsset.balanceOf(msg.sender) < assets) revert InsufficientAccountBalance();

        // transfers assets (USDx) from the user to the contract and mints shares (sUSDx) to the receiver
        uint256 shares = deposit(assets, msg.sender);
        
        // Ensure the minimum shares requirement is met
        checkMinShares();
        
        emit StakeEvent(msg.sender, assets, shares);
        return shares;
    }

    /**
    * @dev Initiates the unstaking process by converting sUSDx (shares) back to USDx.
    * Ensures that the user is not frozen or blacklisted and that they have sufficient shares.
    * Records an unstake request and sets a cooldown period before the claim is allowed.
    * Emits the UnstakeEvent.
    * @param shares The amount of sUSDx to unstake.
    * @return Boolean indicating successful unstaking initiation.
    */
    function unstake(uint256 shares) external whenNotPaused returns (bool) {
        if (_frozenAccounts[msg.sender]) revert AccountFrozen(msg.sender);
        if (_blacklistedAccounts[msg.sender]) revert AccountBlacklisted(msg.sender);
        if (shares == 0) revert AmountZero();
        if (balanceOf(msg.sender) < shares) revert InsufficientAccountBalance();
        if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();
        
        UnstakeRequest storage request = _unstakeRequests[msg.sender];
        // Check if there is a pending unstake request that needs to be claimed first
        if (block.timestamp < request.claimableTimestamp) revert CooldownNotOver();
        if (request.claimableTimestamp != 0) revert UnstakeRequestInCooldown();

        // Converts the specified shares (sUSDx) back into assets (USDx)
        uint256 assets = previewRedeem(shares);

        // Record the unstake request asset amount and cooldown end timestamp
        _unstakeRequests[msg.sender] = UnstakeRequest({
            amount: assets,
            claimableTimestamp: block.timestamp + COOLDOWN_PERIOD
        });

        // Transfers the shares (sUSDx) from the user to the contract
        _withdraw(msg.sender, address(this), msg.sender, assets, shares);
        
        // Ensure the minimum shares requirement is met
        checkMinShares();

        emit UnstakeEvent(msg.sender, shares, assets);
        return true;
    }

    /**
    * @dev Claims the unstaked USDx after the cooldown period.
    * Checks that the account is not frozen or blacklisted, and ensures the cooldown has completed.
    * Transfers the underlying USDx back to the user and removes the unstake request.
    * Emits the ClaimEvent.
    * @return The amount of USDx claimed.
    */
    function claim() public whenNotPaused nonReentrant returns (uint256) {
        if (_frozenAccounts[msg.sender]) revert AccountFrozen(msg.sender);
        if (_blacklistedAccounts[msg.sender]) revert AccountBlacklisted(msg.sender);

        UnstakeRequest storage request = _unstakeRequests[msg.sender];
        if (request.claimableTimestamp == 0) revert NoUnstakeRequest();
        if (block.timestamp < request.claimableTimestamp) revert CooldownNotOver();

        // Computes the number of shares (sUSDx) to assets (USDx)
        uint256 assets = request.amount;
        uint256 shares = previewWithdraw(assets);

        // Transfer the assets to the user
        _underlyingAsset.safeTransfer(msg.sender, assets);

        // Ensure the minimum shares requirement is met
        checkMinShares();
        
        // Remove the unstake request
        delete _unstakeRequests[msg.sender];
        
        emit ClaimEvent(msg.sender, shares, assets);
        return assets;
    }

    /**
    * @dev Distributes USDx rewards to the contract.
    * Only callable by the REWARD_MANAGER_ROLE.
    * Transfers the specified amount of rewards to the contract.
    * Emits the DistributeRewardsEvent.
    * @param rewardsAmount The amount of rewards to distribute.
    * @return Boolean indicating successful distribution.
    */
    function distributeRewards(uint256 rewardsAmount) external onlyRole(REWARD_MANAGER_ROLE) returns (bool) {
        if (rewardsAmount == 0) revert AmountZero();

        uint256 feeAmount = (rewardsAmount * managementFeePercentage) / 10000;
        uint256 stakingRewardsAmount = rewardsAmount - feeAmount;

        _underlyingAsset.safeTransferFrom(msg.sender, address(this), stakingRewardsAmount);

        _underlyingAsset.safeTransfer(treasuryAddress, feeAmount);

        emit DistributeRewardsEvent(rewardsAmount);
        return true;
    }

    /**
    * @dev Updates the treasury address where fees will be sent.
    * Can only be called by an address with the DEFAULT_ADMIN_ROLE.
    * @param newTreasuryAddress The new address to set as the treasury.
    */
    function setTreasuryAddress(address newTreasuryAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newTreasuryAddress == address(0)) {
            revert InvalidTreasuryAddress();
        }
        treasuryAddress = newTreasuryAddress;
    }

    /**
    * @dev Updates the management fee percentage (in basis points).
    * Can only be called by an address with the DEFAULT_ADMIN_ROLE.
    * @param newManagementFeePercentage The new management fee percentage in basis points (max 10000).
    */
    function setManagementFeePercentage(uint256 newManagementFeePercentage) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newManagementFeePercentage > 10000) { // 10000 basis points = 100%
            revert InvalidManagementFeePercentage();
        }
        managementFeePercentage = newManagementFeePercentage;
    }

    /**
    * @dev Checks if the total supply of shares (sUSDx) meets the minimum required.
    * Reverts if the total supply is less than the minimum required shares.
    */
    function checkMinShares() internal view {
        uint256 _totalSupply = totalSupply();
        if (_totalSupply > 0 && _totalSupply < MIN_SHARES) {
            revert MinSharesViolation();
        }
    }

    /**
    * @dev Returns the total amount of USDx held by the contract.
    * Inherited from the ERC4626 standard.
    * @return The total amount of assets held by the contract.
    */
    function totalAssets() public view override returns (uint256) {
        return super.totalAssets(); // Inherited from ERC4626Upgradeable
    }

    /**
    * @dev Returns the total amount of USDx staked by a specific user.
    * Converts the sUSDx (shares) balance of the user to the corresponding USDx amount.
    * @param user The address of the user to check.
    * @return The total amount of USDx staked by the user.
    */
    function totalAssetsStakedByUser(address user) public view returns (uint256) {
        return convertToAssets(balanceOf(user));
    }

    /**
    * @dev Returns the total balance of USDx held by the user in their wallet (not staked).
    * @param user The address of the user to check.
    * @return The total USDx balance held by the user.
    */
    function totalUserAssetBalance(address user) public view returns (uint256) {
        return _underlyingAsset.balanceOf(user);
    }

    /**
    * @dev Returns the total balance of sUSDx (shares) held by the user.
    * @param user The address of the user to check.
    * @return The total sUSDx balance held by the user.
    */
    function totalUserStakedBalance(address user) public view returns (uint256) {
        return balanceOf(user);
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

    // Override the decimals() function to resolve ambiguity
    function decimals() public view virtual override(ERC20Upgradeable, ERC4626Upgradeable) returns (uint8) {
        return super.decimals();
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
