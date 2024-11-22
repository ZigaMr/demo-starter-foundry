// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import "forge-std/console.sol";
import {MessageBox} from "../src/MessageBox.sol";
// import {SapphireSign, DataPack} from "./SapphireSign.sol";
import "./CBOR.sol" as CBOR;


contract MessageBoxScript is Script {
    MessageBox public messageBox;

    // Oasis-specific, confidential precompiles
    address internal constant DERIVE_KEY =
        0x0100000000000000000000000000000000000002;
    address internal constant ENCRYPT =
        0x0100000000000000000000000000000000000003;
    address internal constant DECRYPT =
        0x0100000000000000000000000000000000000004;
    address internal constant CURVE25519_PUBLIC_KEY =
        0x0100000000000000000000000000000000000008;


    // Oasis-specific, general precompiles
    address internal constant SUBCALL =
        0x0100000000000000000000000000000000000103;
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
    function isSimulation() internal returns (bool) {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        return chainId != 0x5aff;
    }

    function encryptCalldata(bytes memory indata) internal returns (bytes memory encryptedCalldata)
    {
        
        Curve25519PublicKey myPublic;
        Curve25519SecretKey mySecret;

        bytes memory privateKeyCurve25519 = abi.encodePacked((vm.randomUint()));
        console.log("RANDOM_BYTES: ", vm.toString(privateKeyCurve25519));

        // Twiddle some bits, as per RFC 7748 §5.
        privateKeyCurve25519[0] &= 0xf8; // Make it a multiple of 8 to avoid small subgroup attacks.
        privateKeyCurve25519[31] &= 0x7f; // Clamp to < 2^255 - 19
        privateKeyCurve25519[31] |= 0x40; // Clamp to >= 2^254

        // Create the transaction arguments as a structured object
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", vm.toString(CURVE25519_PUBLIC_KEY), "\",\"data\":\"", 
            vm.toString(privateKeyCurve25519), "\"}, \"latest\"]"
        );
        bytes memory pubKeyCurve25519 = vm.rpc("eth_call", transactionArgs);
        console.log("CURVE25519_PUBLIC_KEY: ", vm.toString(pubKeyCurve25519));

        (myPublic, mySecret) = (
            Curve25519PublicKey.wrap(bytes32(pubKeyCurve25519)),
            Curve25519SecretKey.wrap(bytes32(privateKeyCurve25519))
        );

        bytes15 nonce = bytes15(abi.encodePacked(vm.randomUint()));
        console.log("NONCE: ", vm.toString(nonce));

        CallDataPublicKey memory cdpk;
        uint256 epoch;

        transactionArgs = string.concat(
            "[{\"to\":\"", 
            vm.toString(SUBCALL),
            "\",\"data\":\"",
            vm.toString(abi.encode("core.CallDataPublicKey", hex"f6")),
            "\"}, \"latest\"]"
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
        console.logBytes(vm.rpc("oasis_callDataPublicKey", "[]"));
                
        bytes memory plaintextEnvelope = abi.encodePacked(
            hex"a1", // map(1)
            hex"64", //     text(4) "body"
            "body",
            CBOR.encodeBytes(indata)
        );

        transactionArgs = string.concat(
            "[{\"to\":\"",
            vm.toString(DERIVE_KEY),
            "\",\"data\":\"",
            vm.toString(abi.encode(Curve25519PublicKey.wrap(cdpk.key),
                                    mySecret)),
            "\"}, \"latest\"]"
        );
        bytes memory symmetric = vm.rpc("eth_call", transactionArgs);
        console.log(vm.toString(symmetric));

        transactionArgs = string.concat(
            "[{\"to\":\"",
            vm.toString(ENCRYPT),
            "\",\"data\":\"",
            vm.toString(abi.encode(bytes32(symmetric),
                        bytes32(nonce),
                        plaintextEnvelope,
                        hex"")),
            "\"}, \"latest\"]"
        );
        bytes memory ciphertext = vm.rpc("eth_call", transactionArgs);
        console.log("Ciphertext: ", vm.toString(ciphertext));

        console.log(vm.toString(CBOR.encodeUint(epoch)));
        encryptedCalldata = abi.encodePacked(
                hex"a2", //  map(2)
                hex"64", //      text(4) "body"
                "body",
                hex"a4", //          map(4)
                hex"62", //              text(2) "pk"
                "pk",
                hex"5820", //                 bytes(32)
                myPublic,
                hex"64", //              text(4) "data"
                "data",
                CBOR.encodeBytes(ciphertext), //     bytes(n) inner
                hex"65", //              text(5) "epoch"
                "epoch",
                CBOR.encodeUint(epoch), // 
                hex"65", //              text(5) "nonce"
                "nonce",
                hex"4f", //                  bytes(15) nonce
                nonce,
                hex"66", //      text(6) "format"
                "format",
                hex"01" //      unsigned(1)
            );
    }

    function decryptCalldata(bytes32 key, bytes32 nonce, bytes memory encrypted) internal returns (bytes memory encryptedCalldata){
        
        string memory transactionArgs = string.concat(
            "[{\"to\":\"",
            vm.toString(DECRYPT),
            "\",\"data\":\"",
            vm.toString(
                abi.encode(
                    key,
                    nonce,
                    encrypted,
                    hex"")
                    ),
            "\"}, \"latest\"]"
        );
        bytes memory decrypted = vm.rpc("eth_call", transactionArgs);
        return decrypted;        
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

        // send_transaction with unencrypted calldata
        messageBox.setMessage("Hello!");

        // send_transaction with encrypted calldata
        // Get the full calldata
        bytes memory setMessageCalldata = abi.encodeWithSignature(
            "setMessage(string)",
            "Hello encrypted!"
        );
        bytes memory encryptedCalldata = encryptCalldata(setMessageCalldata);
        (bool success,) = address(messageBox).call(encryptedCalldata);

        bytes memory fun_sig = abi.encodeWithSignature("greet()");
        
        encryptedCalldata = encryptCalldata(fun_sig);

        // Send the call with unencrypted calldata
        (success,) = address(messageBox).call(fun_sig);

        // Send the call with encrypted calldata
        (success,) = address(messageBox).call(encryptedCalldata);
        console.log("Function signature:", vm.toString(fun_sig));

        // address from = vm.addr(deployerPrivateKey);
        // address to = address(MessageBox);

        // // Get packed data with signature
        // bytes memory packed = SapphireSign.signAndPackData(
        //     encryptedCallData,
        //     callData,
        //     from,
        //     to,
        //     privateKey
        // );

        // // If you need individual components, can also do:
        // Call memory call = SapphireSign.createCall(from, to, callData);
        // bytes memory signature = SapphireSign.signCall(call, privateKey);
        // bytes memory packed2 = SapphireSign.packData(encryptedCallData, call.leash, signature)

        vm.stopBroadcast();
    }
}