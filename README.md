## Demo-starter-foundry


* Install foundry: ```curl -L https://foundry.paradigm.xyz | bash```
* ```foundryup```
* ```forge build``` (we can ignore the error for now)



To run on testnet, first export PRIVATE_KEY env variable:
export PRIVATE_KEY=<private_key>

```bash
forge script script/DeployMessageBox.s.sol --rpc-url sapphire_testnet --broadcast --skip-simulation  -vvv --legacy --via-ir
```


