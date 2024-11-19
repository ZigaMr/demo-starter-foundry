// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import "../script/CBOR.sol" as CBOR;

contract PrecompileTest is Test {
    // Oasis-specific precompile addresses
    address internal constant RANDOM_BYTES = 0x0100000000000000000000000000000000000001;
    address internal constant DERIVE_KEY = 0x0100000000000000000000000000000000000002;
    address internal constant ENCRYPT = 0x0100000000000000000000000000000000000003;
    address internal constant GENERATE_SIGNING_KEYPAIR = 0x0100000000000000000000000000000000000005;
    address internal constant CURVE25519_PUBLIC_KEY = 0x0100000000000000000000000000000000000008;
    address internal constant SUBCALL = 0x0100000000000000000000000000000000000103;
    

    // Types for curve25519 keys
    type Curve25519PublicKey is bytes32;
    type Curve25519SecretKey is bytes32;

    // Define SigningAlg enum to match Sapphire library
    enum SigningAlg {
        Ed25519Oasis,
        Ed25519Pure,
        Ed25519PrehashedSha512,
        Secp256k1Oasis,
        Secp256k1PrehashedKeccak256,
        Secp256k1PrehashedSha256,
        Sr25519,
        Secp256r1PrehashedSha256,
        Secp384r1PrehashedSha384
    }

    function setUp() public {
        // Create fork to enable vm.rpc calls
        vm.createSelectFork("sapphire_testnet");
    }

    function testRandomBytes() public {
        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(32, ""));
        
        // Create the transaction arguments
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );

        // Test getting 32 bytes of random data
        bytes memory scalar = vm.rpc("eth_call", transactionArgs);
        assertEq(scalar.length, 32, "Should return 32 bytes");
        console.log("RANDOM_BYTES32:", vm.toString(scalar));

        // Test getting 15 bytes for nonce
        inputs[1] = vm.toString(abi.encode(15, ""));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory nonce = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES15: ", vm.toString(nonce));
        assertEq(nonce.length, 15, "Should return 15 bytes");
    }

    function testCurve25519PublicKey() public {
        // First get random scalar
        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(32, ""));
        
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory scalar = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES32:", vm.toString(scalar));

        // Apply RFC 7748 §5 tweaks
        scalar[0] &= 0xf8;
        scalar[31] &= 0x7f;
        scalar[31] |= 0x40;

        // Test public key generation
        inputs[0] = vm.toString(CURVE25519_PUBLIC_KEY);
        inputs[1] = vm.toString(scalar);
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory pkBytes = vm.rpc("eth_call", transactionArgs);
        console.log("CURVE25519_PUBLIC_KEY:", vm.toString(pkBytes));
        assertEq(pkBytes.length, 32, "Public key should be 32 bytes");
    }

    function testDeriveKey() public {
        // First get random scalar
        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(32, ""));
        
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory scalar = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES_32:", vm.toString(scalar));

        // Apply RFC 7748 §5 tweaks
        scalar[0] &= 0xf8;
        scalar[31] &= 0x7f;
        scalar[31] |= 0x40;

        // Generate public key
        inputs[0] = vm.toString(CURVE25519_PUBLIC_KEY);
        inputs[1] = vm.toString(scalar);
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory pkBytes = vm.rpc("eth_call", transactionArgs);
        console.log("CURVE25519_PUBLIC_KEY:", vm.toString(pkBytes));

        Curve25519SecretKey mySecret = Curve25519SecretKey.wrap(bytes32(scalar));
        Curve25519PublicKey remotePublic = Curve25519PublicKey.wrap(bytes32(pkBytes));

        // Test derive key
        inputs[0] = vm.toString(DERIVE_KEY);
        inputs[1] = vm.toString(abi.encode(remotePublic, mySecret));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory symmetric = vm.rpc("eth_call", transactionArgs);
        assertEq(symmetric.length, 32, "Derived key should be 32 bytes");
    }

    function testSubcall() public {
        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(SUBCALL);
        inputs[1] = vm.toString(abi.encode("core.CallDataPublicKey", hex"f6"));
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );

        bytes memory result = vm.rpc("eth_call", transactionArgs);
        (uint64 status, bytes memory data) = abi.decode(result, (uint64, bytes));
        console.log("SUBCALL: ", vm.toString(data));
        assertEq(status, 0, "CallDataPublicKey status should be 0");
        assertTrue(data.length > 0, "CallDataPublicKey data should not be empty");
        
        // Parse CBOR data (simplified test)
        assertTrue(data[0] == 0xa1 || data[0] == 0xa2, "Invalid CBOR map start");
    }

    function testEncrypt() public {
        // Get symmetric key
        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(32, ""));
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory symmetric = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES_32:", vm.toString(symmetric));

        // Get nonce
        inputs[1] = vm.toString(abi.encode(15, ""));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory nonce = vm.rpc("eth_call", transactionArgs);
        console.log("RANDOM_BYTES_15:", vm.toString(nonce));
        // Create message envelope using same structure as original script
        bytes memory plaintextEnvelope = abi.encodePacked(
            hex"a1", // map(1)
            hex"64", // text(4) "body"
            "body",
            CBOR.encodeBytes(abi.encodeWithSignature("getMessage()"))
        );

        // Test encryption
        inputs[0] = vm.toString(ENCRYPT);
        inputs[1] = vm.toString(abi.encode(symmetric, nonce, plaintextEnvelope, hex"40"));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory ciphertext = vm.rpc("eth_call", transactionArgs);
        console.log("ENCRYPT:", vm.toString(ciphertext));
        assertTrue(ciphertext.length > 0, "Ciphertext should not be empty");
    }

    function testGenerateSigningKeyPair() public {
        // Generate random seed for key generation
        string[] memory inputs = new string[](2);
        inputs[0] = vm.toString(RANDOM_BYTES);
        inputs[1] = vm.toString(abi.encode(32, ""));
        string memory transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory seed = vm.rpc("eth_call", transactionArgs);
        console.log("Random seed:");
        console.logBytes(seed);

        // Generate Ed25519Pure keypair
        inputs[0] = vm.toString(GENERATE_SIGNING_KEYPAIR);
        inputs[1] = vm.toString(abi.encode(SigningAlg.Ed25519Pure, seed));
        transactionArgs = string.concat(
            "[{\"to\":\"", inputs[0], "\",\"data\":\"", inputs[1], "\"}, \"latest\"]"
        );
        bytes memory result = vm.rpc("eth_call", transactionArgs);
        console.log("Generate signing keypair result:");
        console.logBytes(result);

        (bytes memory publicKey, bytes memory secretKey) = abi.decode(result, (bytes, bytes));
        console.log("Public key:");
        console.logBytes(publicKey);
        console.log("Secret key:");
        console.logBytes(secretKey);

        assertEq(publicKey.length, 32, "Ed25519 public key should be 32 bytes");
        assertEq(secretKey.length, 32, "Ed25519 secret key should be 32 bytes");
    }
}