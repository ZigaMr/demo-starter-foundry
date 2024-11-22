// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

struct EIP712Domain {
    string name;
    string version;
    uint256 chainId;
}

struct Leash {
    uint64 nonce;
    uint64 blockNumber;
    bytes32 blockHash;
    uint64 blockRange;
}

struct Call {
    address from;
    address to;
    uint64 gasLimit;
    uint256 gasPrice;
    uint256 value;
    bytes data;
    Leash leash;
}

contract SapphireSign {
    bytes32 private DOMAIN_SEPARATOR;

    constructor() {
        DOMAIN_SEPARATOR = hashDomain(EIP712Domain({
            name: "oasis-runtime-sdk/evm: signed query",
            version: "1.0.0",
            chainId: block.chainid
        }));
    }

    function hashDomain(EIP712Domain memory domain) private pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId)"),
            keccak256(bytes(domain.name)),
            keccak256(bytes(domain.version)),
            domain.chainId
        ));
    }

    function hashLeash(Leash memory leash) private pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("Leash(uint64 nonce,uint64 blockNumber,bytes32 blockHash,uint64 blockRange)"),
            leash.nonce,
            leash.blockNumber,
            leash.blockHash,
            leash.blockRange
        ));
    }

    function hashCall(Call memory call) private pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("Call(address from,address to,uint64 gasLimit,uint256 gasPrice,uint256 value,bytes data,Leash leash)Leash(uint64 nonce,uint64 blockNumber,bytes32 blockHash,uint64 blockRange)"),
            call.from,
            call.to,
            call.gasLimit,
            call.gasPrice,
            call.value,
            keccak256(call.data),
            hashLeash(call.leash)
        ));
    }

    function verifyCall(Call memory call, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            hashCall(call)
        ));

        address recoveredAddress = ecrecover(digest, v, r, s);
        return (recoveredAddress == call.from);
    }

    // Helper to get the domain separator
    function getDomainSeparator() public view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

        struct DataPack {
        bytes data;        // encrypted_data
        Leash leash;      // leash struct
        bytes signature;   // signature bytes
    }

    function packData(
        bytes memory encrypted_data,
        Leash memory leash,
        bytes memory signature
    ) public pure returns (bytes memory) {
        DataPack memory pack = DataPack({
            data: encrypted_data,
            leash: leash,
            signature: signature
        });
        
        return abi.encode(pack);
    }
}