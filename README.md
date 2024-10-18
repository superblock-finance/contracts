# Contracts

This repository contains a smart contract for creating and managing custom ERC20 tokens with advanced features such as minting, burning, pausing, freezing, and blacklisting.

Developed by: Robert Chanphakeo

## Contracts

- `CustomToken\CustomToken.sol`: Implementation of a customizable ERC20 token.
- `CustomToken\CustomFiatToken.sol`: Implementation of a customizable ERC20 token for stablecoins with additional features such as freeze account and unfreeze account.
- `CustomToken\USDxCollateralPool.sol`: Implementation of a contract that manages the collateral for USDx stablecoin.
- `CrossChainBridge\CrossChainBridge.sol`: Implementation of a contract for bridging tokens across different chains.
- `Vault\Vault.sol`: Implementation of a simple vault contract that securely holds tokens and allows only the owner to manage the stored assets.

Note that no initial supply is minted during deployment; tokens can be minted in a separate transaction.

## License

This project is licensed under the MIT License.
