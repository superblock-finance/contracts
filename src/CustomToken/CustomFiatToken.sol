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

contract CustomFiatToken is Initializable, ERC20Upgradeable, ERC20BurnableUpgradeable, ERC20PausableUpgradeable, ERC20PermitUpgradeable, AccessControlUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable {

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant BLACKLISTER_ROLE = keccak256("BLACKLISTER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    mapping(address => bool) private _blacklistedAccounts;

    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event Blacklist(address indexed account);
    event Unblacklist(address indexed account);
    event Pause();
    event Unpause();
    event WithdrawEther(address indexed to, uint256 amount);

    error AccountBlacklisted(address account);
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
        _grantRole(BLACKLISTER_ROLE, admin);
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
     * @dev Blacklist the account `account`.
     */
    function blacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _blacklistedAccounts[account] = true;
        emit Blacklist(account);
    }

    /**
     * @dev Unblacklist the account `account`.
     */
    function unblacklist(address account) public onlyRole(BLACKLISTER_ROLE) {
        _blacklistedAccounts[account] = false;
        emit Unblacklist(account);
    }

    /**
     * @dev Returns true if the account `account` is blacklisted.
     */
    function isBlacklisted(address account) public view returns (bool) {
        return _blacklistedAccounts[account];
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
     * @dev Overrides required by Solidity for internal functions.
     */
    function _update(address from, address to, uint256 value)
        internal
        override(ERC20Upgradeable, ERC20PausableUpgradeable)
    {
        if (_blacklistedAccounts[from]) revert AccountBlacklisted(from);
        if (_blacklistedAccounts[to]) revert AccountBlacklisted(to);
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
