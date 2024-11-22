// src/SapphireSign.sol
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

struct DataPack {
   bytes data;
   Leash leash;
   bytes signature;
}

library SapphireSign {
   uint64 constant DEFAULT_GAS_LIMIT = 10000000;
   uint256 constant DEFAULT_GAS_PRICE = 0;
   uint64 constant DEFAULT_BLOCK_RANGE = 10;

   function hashDomain(EIP712Domain memory domain) internal pure returns (bytes32) {
       return keccak256(abi.encode(
           keccak256("EIP712Domain(string name,string version,uint256 chainId)"),
           keccak256(bytes(domain.name)),
           keccak256(bytes(domain.version)),
           domain.chainId
       ));
   }

   function hashLeash(Leash memory leash) internal pure returns (bytes32) {
       return keccak256(abi.encode(
           keccak256("Leash(uint64 nonce,uint64 blockNumber,bytes32 blockHash,uint64 blockRange)"),
           leash.nonce,
           leash.blockNumber,
           leash.blockHash,
           leash.blockRange
       ));
   }

   function hashCall(Call memory call) internal pure returns (bytes32) {
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

   function createLeash(address from) internal view returns (Leash memory) {
       return Leash({
           nonce: uint64(vm.getNonce(from)),
           blockNumber: uint64(block.number - 1),
           blockHash: blockhash(block.number - 1),
           blockRange: DEFAULT_BLOCK_RANGE
       });
   }

   function createCall(
       address from,
       address to,
       bytes memory callData
   ) internal view returns (Call memory) {
       return Call({
           from: from,
           to: to,
           gasLimit: DEFAULT_GAS_LIMIT,
           gasPrice: DEFAULT_GAS_PRICE,
           value: 0,
           data: callData,
           leash: createLeash(from)
       });
   }

   function signCall(
       Call memory call,
       uint256 privateKey
   ) internal view returns (bytes memory signature) {
       bytes32 DOMAIN_SEPARATOR = hashDomain(EIP712Domain({
           name: "oasis-runtime-sdk/evm: signed query",
           version: "1.0.0",
           chainId: block.chainid
       }));

       bytes32 digest = keccak256(abi.encodePacked(
           "\x19\x01",
           DOMAIN_SEPARATOR,
           hashCall(call)
       ));

       (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
       return abi.encodePacked(r, s, v);
   }

   function packData(
       bytes memory encryptedData,
       Leash memory leash,
       bytes memory signature
   ) internal pure returns (bytes memory) {
       return abi.encode(DataPack({
           data: encryptedData,
           leash: leash,
           signature: signature
       }));
   }

   function signAndPackData(
       bytes memory encryptedData,
       bytes memory callData,
       address from,
       address to,
       uint256 privateKey
   ) internal view returns (bytes memory) {
       Call memory call = createCall(from, to, callData);
       bytes memory signature = signCall(call, privateKey);
       return packData(encryptedData, call.leash, signature);
   }
}