// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import "forge-std/console.sol";
import {MessageBox} from "../src/MessageBox.sol";
// import {encryptCallDataOnlyData} from "../lib/sapphire-paratime/contracts/contracts/CalldataEncryption.sol";
import "./CBOR.sol" as CBOR;

// Define the interface for the MessageBox contract based on the ABI
interface IMessageBox {
    function getMessage() external view returns (string memory);
    function setMessage(string memory newMessage) external;
}

contract MessageBoxScript is Script {
    MessageBox public messageBox;

    // Oasis-specific, confidential precompiles
    address internal constant RANDOM_BYTES =
        0x0100000000000000000000000000000000000001;
    address internal constant DERIVE_KEY =
        0x0100000000000000000000000000000000000002;
    address internal constant ENCRYPT =
        0x0100000000000000000000000000000000000003;
    address internal constant DECRYPT =
        0x0100000000000000000000000000000000000004;
    address internal constant GENERATE_SIGNING_KEYPAIR =
        0x0100000000000000000000000000000000000005;
    address internal constant SIGN_DIGEST =
        0x0100000000000000000000000000000000000006;
    address internal constant VERIFY_DIGEST =
        0x0100000000000000000000000000000000000007;
    address internal constant CURVE25519_PUBLIC_KEY =
        0x0100000000000000000000000000000000000008;
    address internal constant GAS_USED =
        0x0100000000000000000000000000000000000009;
    address internal constant PAD_GAS =
        0x010000000000000000000000000000000000000a;

    // Oasis-specific, general precompiles
    address internal constant SHA512_256 =
        0x0100000000000000000000000000000000000101;
    address internal constant SHA512 =
        0x0100000000000000000000000000000000000102;
    address internal constant SUBCALL =
        0x0100000000000000000000000000000000000103;
    address internal constant SHA384 =
        0x0100000000000000000000000000000000000104;

    string private constant CORE_CALLDATAPUBLICKEY = "core.CallDataPublicKey";

    type Curve25519PublicKey is bytes32;
    type Curve25519SecretKey is bytes32;

    struct CallDataPublicKey {
        bytes32 key;
        bytes32 checksum;
        bytes32[2] signature;
        uint256 expiration;
    }

    error CoreCallDataPublicKeyError(uint64);
    error SubcallError();

    
    function setUp() public {
        // Create fork to enable vm.rpc
        vm.createSelectFork("sapphire_testnet");
        
    }

    function _parseCBORPublicKeyInner(bytes memory in_data, uint256 in_offset)
        internal
        pure
        returns (uint256 offset, CallDataPublicKey memory public_key)
    {
        uint256 mapLen;

        (mapLen, offset) = CBOR.parseMapStart(in_data, in_offset);

        while (mapLen > 0) {
            mapLen -= 1;

            bytes32 keyDigest;

            (offset, keyDigest) = CBOR.parseKey(in_data, offset);

            if (keyDigest == keccak256("key")) {
                uint256 tmp;
                (offset, tmp) = CBOR.parseUint(in_data, offset);
                public_key.key = bytes32(tmp);
            } else if (keyDigest == keccak256("checksum")) {
                uint256 tmp;
                (offset, tmp) = CBOR.parseUint(in_data, offset);
                public_key.checksum = bytes32(tmp);
            } else if (keyDigest == keccak256("expiration")) {
                (offset, public_key.expiration) = CBOR.parseUint(
                    in_data,
                    offset
                );
            } else if (keyDigest == keccak256("signature")) {
                if (in_data[offset++] != 0x58) {
                    revert CBOR.CBOR_InvalidUintPrefix(
                        uint8(in_data[offset - 1])
                    );
                }
                if (in_data[offset++] != 0x40) {
                    revert CBOR.CBOR_InvalidUintSize(
                        uint8(in_data[offset - 1])
                    );
                }
                uint256 tmp;
                assembly {
                    tmp := mload(add(in_data, add(offset, 0x20)))
                }
                public_key.signature[0] = bytes32(tmp);
                assembly {
                    tmp := mload(add(in_data, add(offset, 0x40)))
                }
                public_key.signature[1] = bytes32(tmp);

                offset += 0x40;
            } else {
                revert CBOR.CBOR_InvalidKey();
            }
        }
    }

    function _parseCBORCallDataPublicKey(bytes memory in_data)
        internal
        pure
        returns (uint256 epoch, CallDataPublicKey memory public_key)
    {
        (uint256 outerMapLen, uint256 offset) = CBOR.parseMapStart(in_data, 0);

        while (outerMapLen > 0) {
            bytes32 keyDigest;

            outerMapLen -= 1;

            (offset, keyDigest) = CBOR.parseKey(in_data, offset);

            if (keyDigest == keccak256("epoch")) {
                (offset, epoch) = CBOR.parseUint(in_data, offset);
            } else if (keyDigest == keccak256("public_key")) {
                (offset, public_key) = _parseCBORPublicKeyInner(
                    in_data,
                    offset
                );
            } else {
                revert CBOR.CBOR_InvalidKey();
            }
        }
    }

    // Helper to detect if we're in simulation
    function isSimulation() internal view returns (bool) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        console.log("Chain ID:", chainId);
        // Foundry's default chainid for simulation is 31337
        return chainId != 0x5aff;
    }

    function run() public {
        // Exit early if we're in simulation
        if (isSimulation()) {
            console.log("Simulation detected, skipping execution");
            return;
        }
        // Get the private key from the environment variable    
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy MessageBox
        messageBox = new MessageBox();
        // IMessageBox messageBox = IMessageBox(messageBoxAddress);

        messageBox.setMessage("Hello!");

        // Prepare getMessage() calldata
        bytes memory getMessageCalldata = abi.encodeWithSignature("getMessage()");
        

        Curve25519PublicKey myPublic;
        Curve25519SecretKey mySecret;

        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(32, ""));
        // Create the transaction arguments as a structured object
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );

        // Call eth_call with the structured transaction object in an array
        bytes memory scalar = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES: ", vm.toString(scalar));

        // Twiddle some bits, as per RFC 7748 §5.
        scalar[0] &= 0xf8; // Make it a multiple of 8 to avoid small subgroup attacks.
        scalar[31] &= 0x7f; // Clamp to < 2^255 - 19
        scalar[31] |= 0x40; // Clamp to >= 2^254

        inputs = new string[](2);
        inputs[0] = vm.toString(CURVE25519_PUBLIC_KEY);
        inputs[1] = vm.toString(scalar);
        // Create the transaction arguments as a structured object
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory pkBytes = vm.rpc("eth_call", transactionArgs);
        console.log("CURVE25519_PUBLIC_KEY: ", vm.toString(pkBytes));

        bytes32 mySecret2 = bytes32(scalar);
        (myPublic, mySecret) = (
            Curve25519PublicKey.wrap(bytes32(pkBytes)),
            Curve25519SecretKey.wrap(bytes32(scalar))
        );

        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(15, ""));
        // Create the transaction arguments as a structured object
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        scalar = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES: ", vm.toString(scalar));

        bytes15 nonce = bytes15(scalar);
        CallDataPublicKey memory cdpk;
        uint256 epoch;

        inputs[0] = vm.toString(SUBCALL);
        inputs[1] = vm.toString(abi.encode("core.CallDataPublicKey", hex"f6"));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        console.log("inputs: ", transactionArgs);
        bytes memory tmp = vm.rpc("eth_call", transactionArgs);
        console.log("core.CallDataPublicKey: ", vm.toString(tmp));
        (uint64 status, bytes memory data) = abi.decode(tmp, (uint64, bytes));
        console.log(vm.toString(status), vm.toString(data));
        
        if (status != 0) {
            revert CoreCallDataPublicKeyError(status);
        }

        (epoch, cdpk) = _parseCBORCallDataPublicKey(data);
        
        bytes memory plaintextEnvelope = abi.encodePacked(
            hex"a1", // map(1)
            hex"64", //     text(4) "body"
            "body",
            CBOR.encodeBytes(getMessageCalldata)
        );

        console.logBytes32(cdpk.key);
        inputs[0] = vm.toString(DERIVE_KEY);
        console.log("Key: ", vm.toString(cdpk.key));
        console.log("secret: ", vm.toString(mySecret2));
        inputs[1] = vm.toString(abi.encode(Curve25519PublicKey.wrap(cdpk.key), mySecret));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory symmetric = vm.rpc("eth_call", transactionArgs);
        console.log(vm.toString(symmetric));

        inputs[0] = vm.toString(ENCRYPT);
        inputs[1] = vm.toString(abi.encode(symmetric, nonce, plaintextEnvelope, hex"40"));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory ciphertext = vm.rpc("eth_call", transactionArgs);
        console.log("Ciphertext: ", vm.toString(ciphertext));

        console.log(vm.toString(CBOR.encodeUint(epoch)));
        bytes memory encryptedCalldata = abi.encodePacked(
                hex"a2", //  map(2)
                hex"64", //      text(4) "body"
                "body",
                hex"a3", //          map(3)
                hex"62", //              text(2) "pk"
                "pk",
                hex"5820", //                 bytes(32)
                myPublic,
                hex"64", //              text(4) "data"
                "data",
                CBOR.encodeBytes(ciphertext), //     bytes(n) inner
                // hex"65", //              text(5) "epoch"
                // "epoch",
                // CBOR.encodeUint(epoch), // 
                hex"65", //              text(5) "nonce"
                "nonce",
                hex"4f", //                  bytes(15) nonce
                nonce,
                hex"66", //      text(6) "format"
                "format",
                hex"01" //      unsigned(1)
            );

        string memory messageBoxAddressStr = vm.toString(address(messageBox));

        transactionArgs = string.concat(
            "[{\"to\":\"", messageBoxAddressStr, "\",\"data\":\"", vm.toString(encryptedCalldata), "\"}, \"latest\"]"
        );
        
        // Make the call with encrypted calldata
        bytes memory result_gas = vm.rpc("eth_estimateGas", transactionArgs);
        // (bool success, bytes memory result) = address(messageBox).call("getMessage()");
        // string memory result = messageBox.getMessage();
        // Send the transaction using vm.rpc
        (bool success, bytes memory result) = address(messageBox).call(encryptedCalldata);
        console.log(vm.toString(encryptedCalldata));
        console.log(vm.toString(result_gas));

        
        vm.stopBroadcast();
    }
}