// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/draft-ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

contract CustomToken is Initializable, ERC20Upgradeable, ERC20BurnableUpgradeable, ERC20PausableUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Pause();
    event Unpause();
    event WithdrawEther(address indexed to, uint256 amount);
    event WithdrawERC20(address indexed token, address indexed to, uint256 amount);

    error AccountFrozen(address account);
    error InsufficientBalance();
    
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the contract with a name and symbol and grants `admin` the default admin role.
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
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(WITHDRAWER_ROLE, admin);
    }

    /**
     * @dev Mints `amount` of tokens to the address `to`.
     */
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) whenNotPaused {
        _mint(to, amount);
        emit Mint(to, amount);
    }

    /**
     * @dev Burns `amount` of tokens from the address `from`.
     */
    function burn(address from, uint256 amount) public onlyRole(BURNER_ROLE) whenNotPaused {
        _burn(from, amount);
        emit Burn(from, amount);
    }

    /**
     * @dev Pauses all token transfers.
     */
    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
        emit Pause();
    }

    /**
     * @dev Unpauses all token transfers.
     */
    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
        emit Unpause();
    }

    /**
     * @dev Withdraws `amount` of Ether from the contract to the caller's address.
     */
    function withdrawEther(uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE) {
        if (amount > address(this).balance) revert InsufficientBalance();
        payable(_msgSender()).transfer(amount);
        emit WithdrawEther(_msgSender(), amount);
    }

    /**
     * @dev Withdraws `amount` of ERC20 tokens from the contract to the caller's address.
     */
    function withdrawERC20(address tokenAddress, uint256 amount) public nonReentrant onlyRole(WITHDRAWER_ROLE) whenNotPaused {
        IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
        uint256 balance = token.balanceOf(address(this));
        if (amount > balance) revert InsufficientBalance();
        token.safeTransfer(_msgSender(), amount);
        emit WithdrawERC20(tokenAddress, _msgSender(), amount);
    }

    /**
     * @dev Overrides required by Solidity for internal functions.
     */
    function _update(address from, address to, uint256 value)
        internal
        override(ERC20Upgradeable, ERC20PausableUpgradeable)
    {
        super._update(from, to, value);
    }

    /**
     * @dev Authorizes contract upgrades.
     */
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(UPGRADER_ROLE) {}

    // Fallback and receive functions to handle Ether transfers
    receive() external payable {}
    fallback() external payable {}
}
