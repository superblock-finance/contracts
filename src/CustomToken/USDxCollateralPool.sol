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
 * This is used by the USDxCollateralPool contract to handle token issuance and redemption.
 */
interface IERC20UpgradeableCustom is IERC20Upgradeable {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function mint(address to, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}

/**
 * @title USDxCollateralPool
 * @dev This contract manages the collateral for USDx stablecoin.
 * It allows users to mint and redeem USDx by depositing and withdrawing collateral.
 * The contract includes access control, pausing capabilities, and non-reentrancy protections.
 * It supports multiple collateral tokens with configurable collateralization ratios and SBX requirements.
 * This contract is upgradeable and follows the UUPS proxy pattern.
 */
contract USDxCollateralPool is Initializable, AccessControlUpgradeable, UUPSUpgradeable, PausableUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Define roles for access control
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant FREEZER_ROLE = keccak256("FREEZER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    /**
     * @dev Struct to hold collateral token details.
     * @param token The ERC20 token used as collateral.
     * @param collateralRatio The collateralization ratio in basis points (e.g., 10000 for 100%).
     * @param sbxPercentage The SBX requirement percentage in basis points (e.g., 100 for 1%).
     */
    struct CollateralTokenStruct {
        IERC20UpgradeableCustom token;
        uint256 collateralRatio; // Collateral ratio in basis points (e.g., 10000 for 100%)
        uint256 sbxPercentage;   // Required SBX percentage in basis points (e.g., 100 for 1%)
        uint8 decimals; // Decimals of the collateral token
    }

    // Store mappings for frozen and blacklisted accounts
    mapping(address => bool) private _frozenAccounts;
    mapping(address => bool) private _blacklistedAccounts;
    mapping(address => CollateralTokenStruct) public collateralTokens;

    // Events
    event MintEvent(address indexed user, address indexed collateralToken, uint256 collateralAmount, uint256 usdxAmount, uint256 mintFee);
    event RedeemEvent(address indexed user, uint256 usdxAmount, address indexed collateralToken, uint256 collateralAmount, uint256 redeemFee);
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
    error InsufficientContractBalance();
    error InsufficientContractSBXBalance();
    error InvalidMintAmount();
    error InvalidRedeemAmount();
    error InvalidUSDxAmount();
    error UnsupportedCollateralToken();
    error InvalidCollateralRatio();
    error InvalidSBXPercentage();
    error InvalidCollateralAmount();
    error CollateralTransferFailed();
    error SBXTransferFailed();

    // Contract addresses
    IERC20UpgradeableCustom public usdxToken;
    IERC20UpgradeableCustom public sbxToken;

    // Contract parameters
    uint256 public targetPrice; // Scaled by 1e18 (e.g., 1 * 1e18 for $1)
    uint256 public mintFeePercentage; // In basis points (e.g., 10 for 0.1%)
    uint256 public redeemFeePercentage; // In basis points (e.g., 20 for 0.2%)
    uint256 public minMintFee; // Scaled by 1e16 (e.g., 25 * 1e16 for 0.25 USDx)
    uint256 public minRedeemFee; // Scaled by 1e16 (e.g., 25 * 1e16 for 0.25 USDx)
    uint256 public minMintAmount; // Scaled by 1e18 (e.g., 1 * 1e18 for 1 USDx)
    uint256 public minRedeemAmount; // Scaled by 1e18 (e.g., 1 * 1e18 for 1 USDx)
    uint256 public maxMintAmount; // Scaled by 1e18 (e.g., 10,000,000 * 1e18 for 10M USDx)
    uint256 public maxRedeemAmount; // Scaled by 1e18 (e.g., 10,000,000 * 1e18 for 10M USDx)

    address public treasuryAddress;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract, setting up roles and initial parameters.
     * @param _usdxToken Address of the USDx token contract.
     * @param _sbxToken Address of the SBX token contract.
     * @param _treasuryAddress Address where fees will be sent.
     * @param admin Address to be granted the admin role.
     */
    function initialize(address _usdxToken, address _sbxToken, address _treasuryAddress, address admin)
        initializer public
    {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(MANAGER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(FREEZER_ROLE, admin);
        _grantRole(BLACKLISTER_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);

        usdxToken = IERC20UpgradeableCustom(_usdxToken);
        sbxToken = IERC20UpgradeableCustom(_sbxToken);
        treasuryAddress = _treasuryAddress;

        // Initialize default parameters
        targetPrice = 1 * 1e18; // 1 USDx = $1
        mintFeePercentage = 10; // 0.1%
        redeemFeePercentage = 20; // 0.2%
        minMintFee = 25 * 1e16; // 0.25 USDx
        minRedeemFee = 25 * 1e16; // 0.25 USDx
        minMintAmount = 1 * 1e18; // 1 USDx
        minRedeemAmount = 1 * 1e18; // 1 USDx
        maxMintAmount = 10000000 * 1e18; // 10M USDx
        maxRedeemAmount = 10000000 * 1e18; // 10M USDx
    }

    /**
     * @dev Mints USDx by depositing collateral and transferring required SBX.
     * Transfers the collateral and SBX from the user to the contract and mints USDx in return.
     * @param _collateralToken The address of the collateral token.
     * @param _collateralAmount The amount of collateral to deposit.
     */
    function mint(address _collateralToken, uint256 _collateralAmount) external whenNotPaused nonReentrant {
        // Check if the account is frozen or blacklisted
        if (isFrozen(msg.sender)) revert AccountFrozen(msg.sender);
        if (isBlacklisted(msg.sender)) revert AccountBlacklisted(msg.sender);

        // Check collateral amount is valid
        if (_collateralAmount <= 0) revert InvalidCollateralAmount();

        // Check collateral token is supported
        CollateralTokenStruct memory collateralToken = collateralTokens[_collateralToken];
        if (collateralToken.collateralRatio <= 0) revert UnsupportedCollateralToken();

        // Adjust the collateral amount to 18 decimals
        uint256 adjustedCollateralAmount = _collateralAmount * (10 ** (18 - collateralToken.decimals));

        // Calculate the amount of USDx to mint based on collateral ratio
        uint256 syntheticAmount = (adjustedCollateralAmount * collateralToken.collateralRatio * 1e14) / targetPrice;

        // Check mint amount is valid
        if (syntheticAmount < minMintAmount || syntheticAmount > maxMintAmount) revert InvalidMintAmount();

        // Calculate required SBX amount based on sbxPercentage
        // sbxPercentage is in basis points, so divide by 1e4 to get the percentage
        uint256 requiredSBXAmount = (syntheticAmount * collateralToken.sbxPercentage) / 1e4;

        // Transfer collateral from user to contract
        IERC20Upgradeable(address(collateralToken.token)).safeTransferFrom(msg.sender, address(this), _collateralAmount);

        // Transfer SBX from user to contract, if required
        if (requiredSBXAmount > 0) {
            IERC20Upgradeable(address(sbxToken)).safeTransferFrom(msg.sender, address(this), requiredSBXAmount);
        }

        // Calculate the mint fee
        uint256 mintFee = calculateMintFee(syntheticAmount);

        // Mint net USDx to user
        usdxToken.mint(msg.sender, syntheticAmount - mintFee);

        // Mint mint fee to treasury
        if (mintFee > 0) {
            usdxToken.mint(treasuryAddress, mintFee);
        }

        emit MintEvent(msg.sender, _collateralToken, _collateralAmount, syntheticAmount, mintFee);
    }    

    /**
     * @dev Redeems USDx to withdraw collateral and returns SBX if applicable.
     * Redeems the specified amount of USDx and returns the equivalent collateral to the user.
     * @param _usdxAmount The amount of USDx to redeem.
     * @param _collateralToken The address of the collateral token.
     */
    function redeem(uint256 _usdxAmount, address _collateralToken) external whenNotPaused nonReentrant {
        // Check if the account is frozen or blacklisted
        if (isFrozen(msg.sender)) revert AccountFrozen(msg.sender);
        if (isBlacklisted(msg.sender)) revert AccountBlacklisted(msg.sender);

        // Check USDx amount is valid
        if (_usdxAmount <= 0) revert InvalidUSDxAmount();

        // Check collateral token is supported
        CollateralTokenStruct memory collateralToken = collateralTokens[_collateralToken];
        if (collateralTokens[_collateralToken].collateralRatio <= 0) revert UnsupportedCollateralToken();

        // Adjust the USDx amount to 18 decimals
        uint256 adjustedCollateralAmount = _usdxAmount * (10 ** (18 - collateralToken.decimals));

        // Calculate the amount of collateral to redeem based on the collateral ratio
        uint256 collateralAmount = (adjustedCollateralAmount * targetPrice * 1e4) / (collateralToken.collateralRatio * 1e18);

        // Check redeem amount is valid
        if (collateralAmount < minRedeemAmount || collateralAmount > maxRedeemAmount) revert InvalidRedeemAmount();

        // Ensure the contract has enough collateral balance
        if (collateralToken.token.balanceOf(address(this)) < collateralAmount) revert InsufficientContractBalance();

        // Calculate required SBX amount based on sbxPercentage
        uint256 requiredSBXAmount = (collateralAmount * collateralToken.sbxPercentage) / 1e4;

        // Ensure the contract has enough SBX to return, if applicable
        if (requiredSBXAmount > 0 && sbxToken.balanceOf(address(this)) < requiredSBXAmount) revert InsufficientContractSBXBalance();

        // Calculate the redeem fee
        uint256 redeemFee = calculateRedeemFee(_usdxAmount);

        // Transfer USDx from the user to the contract
        IERC20Upgradeable(address(usdxToken)).safeTransferFrom(msg.sender, address(this), _usdxAmount);

        // Mint redeem fee to treasury
        if (redeemFee > 0) {
            usdxToken.mint(treasuryAddress, redeemFee);
        }

        // Burn the remaining USDx from the user
        usdxToken.burnFrom(address(this), _usdxAmount - redeemFee);

        // Transfer collateral back to user
        IERC20Upgradeable(address(collateralToken.token)).safeTransfer(msg.sender, collateralAmount);

        // Transfer SBX back to user, if any
        if (requiredSBXAmount > 0) {
            IERC20Upgradeable(address(sbxToken)).safeTransfer(msg.sender, requiredSBXAmount);
        }


        emit RedeemEvent(msg.sender, _usdxAmount, _collateralToken, collateralAmount, redeemFee);
    }

    /**
    * @dev Adds a new collateral token to the pool.
    * Only callable by addresses with the MANAGER_ROLE.
    * 
    * @param _collateralToken The address of the collateral token to add.
    * @param _collateralRatio The collateralization ratio for this token, in basis points (e.g., 10000 for 100% collateralization).
    * @param _sbxPercentage The required SBX percentage for this token, in basis points (e.g., 100 for 1% SBX requirement).
    * @param _decimals The number of decimals used by the collateral token (e.g., 6 for USDC/USDT, 18 for other ERC20 tokens).
    *
    * The function stores the collateral token's parameters, including the collateral ratio, the required SBX percentage,
    * and the token's decimal places. These parameters will be used when minting and redeeming USDx.
    */
    function addCollateralToken(address _collateralToken, uint256 _collateralRatio, uint256 _sbxPercentage, uint8 _decimals) external onlyRole(MANAGER_ROLE) {
        if (_collateralRatio < 10000 || _collateralRatio > 15000) revert InvalidCollateralRatio(); // 100% to 150%
        if (_sbxPercentage > 10000) revert InvalidSBXPercentage(); // 0% to 100%

        collateralTokens[_collateralToken] = CollateralTokenStruct({
            token: IERC20UpgradeableCustom(_collateralToken),
            collateralRatio: _collateralRatio,
            sbxPercentage: _sbxPercentage,
            decimals: _decimals
        });
    }

    /**
    * @dev Updates the collateralization ratio, SBX percentage, and decimals for an existing collateral token.
    * Only callable by addresses with the MANAGER_ROLE.
    * 
    * @param _collateralToken The address of the collateral token to update.
    * @param _collateralRatio The new collateralization ratio for this token, in basis points (e.g., 11000 for 110% collateralization).
    * @param _sbxPercentage The new SBX percentage for this token, in basis points (e.g., 150 for 1.5% SBX requirement).
    * @param _decimals The number of decimals used by the collateral token.
    *
    * This function allows you to update the collateral token's parameters, ensuring that the updated collateral ratio,
    * SBX percentage, and decimals are reflected in future mint and redeem operations.
    */
    function setCollateralParams(address _collateralToken, uint256 _collateralRatio, uint256 _sbxPercentage, uint8 _decimals) external onlyRole(MANAGER_ROLE) {
        CollateralTokenStruct storage collateralToken = collateralTokens[_collateralToken];
        if (collateralToken.collateralRatio == 0) revert UnsupportedCollateralToken();
        if (_collateralRatio < 10000 || _collateralRatio > 15000) revert InvalidCollateralRatio(); // 100% to 150%
        if (_sbxPercentage > 10000) revert InvalidSBXPercentage(); // 0% to 100%

        collateralToken.collateralRatio = _collateralRatio;
        collateralToken.sbxPercentage = _sbxPercentage;
        collateralToken.decimals = _decimals;
    }

    /**
     * @dev Removes a collateral token from the pool.
     * Only callable by addresses with the MANAGER_ROLE.
     * @param _collateralToken The address of the collateral token to remove.
     */
    function removeCollateralToken(address _collateralToken) external onlyRole(MANAGER_ROLE) {
        if (collateralTokens[_collateralToken].collateralRatio == 0) revert UnsupportedCollateralToken();
        delete collateralTokens[_collateralToken];
    }

    /**
     * @dev Calculates the mint fee for a given mint amount.
     * The fee is based on the mint fee percentage in basis points, and a minimum mint fee is applied if the calculated fee is too low.
     * @param _usdxAmount The amount of USDx being minted, scaled by 1e18.
     * @return The calculated mint fee, scaled by 1e18.
     */
    function calculateMintFee(uint256 _usdxAmount) public view returns (uint256) {
        uint256 mintFee = (_usdxAmount * mintFeePercentage) / 10000; // Convert basis points to percentage

        // Apply minimum mint fee
        mintFee = mintFee >= minMintFee ? mintFee : minMintFee;

        return mintFee;
    }

    /**
     * @dev Calculates the redeem fee for a given redeem amount.
     * The fee is based on the redeem fee percentage in basis points, and a minimum redeem fee is applied if the calculated fee is too low.
     * @param _usdxAmount The amount of USDx being redeemed, scaled by 1e18.
     * @return The calculated redeem fee, scaled by 1e18.
     */
    function calculateRedeemFee(uint256 _usdxAmount) public view returns (uint256) {
        uint256 redeemFee = (_usdxAmount * redeemFeePercentage) / 10000; // Convert basis points to percentage

        // Apply minimum redeem fee
        redeemFee = redeemFee >= minRedeemFee ? redeemFee : minRedeemFee;

        return redeemFee;
    }

    /**
     * @dev Updates the target price of USDx in collateral terms.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _targetPrice The new target price for USDx, in USDx terms (e.g., 1 for $1).
     */
    function setTargetPrice(uint256 _targetPrice) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        targetPrice = _targetPrice * 1e18;
    }

    /**
     * @dev Updates the mint fee parameters.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _mintFeePercentage The new mint fee percentage in basis points (e.g., 15 for 0.15%).
     * @param _minMintFee The new minimum mint fee, in USDx terms. This function scales it by 1e16 internally.
     */
    function setMintFeeParams(uint256 _mintFeePercentage, uint256 _minMintFee) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        mintFeePercentage = _mintFeePercentage;
        minMintFee = _minMintFee * 1e16;
    }

    /**
     * @dev Updates the redeem fee parameters.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _redeemFeePercentage The new redeem fee percentage in basis points (e.g., 25 for 0.25%).
     * @param _minRedeemFee The new minimum redeem fee, in USDx terms. This function scales it by 1e16 internally.
     */
    function setRedeemFeeParams(uint256 _redeemFeePercentage, uint256 _minRedeemFee) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        redeemFeePercentage = _redeemFeePercentage;
        minRedeemFee = _minRedeemFee * 1e16;
    }

    /**
     * @dev Updates the minimum amount of USDx required for minting.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _minMintAmount The new minimum mint amount, in USDx terms. This function scales it by 1e18 internally.
     */
    function setMinMintAmount(uint256 _minMintAmount) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        minMintAmount = _minMintAmount * 1e18;
    }

    /**
     * @dev Updates the minimum amount of USDx required for redeeming.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _minRedeemAmount The new minimum redeem amount, in USDx terms. This function scales it by 1e18 internally.
     */
    function setMinRedeemAmount(uint256 _minRedeemAmount) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        minRedeemAmount = _minRedeemAmount * 1e18;
    }

    /**
     * @dev Updates the maximum amount of USDx allowed for minting.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _maxMintAmount The new maximum mint amount, in USDx terms. This function scales it by 1e18 internally.
     */
    function setMaxMintAmount(uint256 _maxMintAmount) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        maxMintAmount = _maxMintAmount * 1e18;
    }

    /**
     * @dev Updates the maximum amount of USDx allowed for redeeming.
     * Can only be called by addresses with the DEFAULT_ADMIN_ROLE.
     * @param _maxRedeemAmount The new maximum redeem amount, in USDx terms. This function scales it by 1e18 internally.
     */
    function setMaxRedeemAmount(uint256 _maxRedeemAmount) external onlyRole(DEFAULT_ADMIN_ROLE)  {
        maxRedeemAmount = _maxRedeemAmount * 1e18;
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
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}
}
