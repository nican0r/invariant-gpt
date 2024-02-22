---
sponsor: "Centrifuge"
slug: "2023-09-centrifuge"
date: "2023-10-11"
title: "Centrifuge"
findings: "https://github.com/code-423n4/2023-09-centrifuge-findings/issues"
contest: 285
---


# Medium Risk Findings (8)
## [M-01] `onlyCentrifugeChainOrigin()` can't require `msg.sender` equal `axelarGateway`

In `AxelarRouter.sol`, we need to ensure the legitimacy of the `execute()` method execution, mainly through two methods:

1.  `axelarGateway.validateContractCall ()` to validate if the `command` is approved or not.
2.  `onlyCentrifugeChainOrigin()` is used to validate that `sourceChain` `sourceAddress` is legal.

Let's look at the implementation of `onlyCentrifugeChainOrigin()`:

```solidity
    modifier onlyCentrifugeChainOrigin(string calldata sourceChain, string calldata sourceAddress) {        
@>      require(msg.sender == address(axelarGateway), "AxelarRouter/invalid-origin");
        require(
            keccak256(bytes(axelarCentrifugeChainId)) == keccak256(bytes(sourceChain)),
            "AxelarRouter/invalid-source-chain"
        );
        require(
            keccak256(bytes(axelarCentrifugeChainAddress)) == keccak256(bytes(sourceAddress)),
            "AxelarRouter/invalid-source-address"
        );
        _;
    }
```

The problem is that this restriction `msg.sender == address(axelarGateway)`.

When we look at the official `axelarGateway.sol` contract, it doesn't provide any call external contract 's`execute()` method.

So `msg.sender` cannot be `axelarGateway`, and the official example does not restrict `msg.sender`.

The security of the command can be guaranteed by `axelarGateway.validateContractCall()`, `sourceChain`, `sourceAddress`.

There is no need to restrict `msg.sender`.

`axelarGateway` code address<br>
<https://github.com/axelarnetwork/axelar-cgp-solidity/blob/main/contracts/AxelarGateway.sol>

Can't find anything that calls `router.execute()`.

### Impact

`router.execute()` cannot be executed properly, resulting in commands from other chains not being executed， protocol not working properly.

***

## [M-02] `LiquidityPool::requestRedeemWithPermit` transaction can be front run with the different liquidity pool

The permit signature is linked only to the tranche token. That's why it can be used with any liquidity pool with the same tranche token. Since anyone can call `LiquidityPool::requestRedeemWithPermit` the following scenario is possible:

1.  Let's assume that some user has some amount of tranche tokens. Let's also assume that there are multiple liquidity pools with the same tranche token. For example, USDX pool and USDY pool.
2.  The user wants to redeem USDX from the USDX pool using `requestRedeemWithPermit`. The user signs the permit and sends a transaction.
3.  A malicious actor can see this transaction in the mempool and use the signature from it to request a redemption from the USDY pool with a greater fee amount.
4.  Since this transaction has a greater fee amount it will likely be executed before the valid transaction.
5.  The user's transaction will be reverted since the permit has already been used.
6.  If the user will not cancel this malicious request until the end of the epoch this request will be executed, and the user will be forced to claim USDY instead of USDX.

This scenario assumes some user's negligence and usually doesn't lead to a significant loss. But in some cases (for example, USDY depeg) a user can end up losing significantly.

### Proof of Concept

The test below illustrates the scenario described above:

```solidity
function testPOCIssue1(
    uint64 poolId,
    string memory tokenName,
    string memory tokenSymbol,
    bytes16 trancheId,
    uint128 currencyId,
    uint256 amount
) public {
    vm.assume(currencyId > 0);
    vm.assume(amount < MAX_UINT128);
    vm.assume(amount > 1);

    // Use a wallet with a known private key so we can sign the permit message
    address investor = vm.addr(0xABCD);
    vm.prank(vm.addr(0xABCD));

    LiquidityPool lPool =
        LiquidityPool(deployLiquidityPool(poolId, erc20.decimals(), tokenName, tokenSymbol, trancheId, currencyId));
    erc20.mint(investor, amount);
    homePools.updateMember(poolId, trancheId, investor, type(uint64).max);

    // Sign permit for depositing investment currency
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(
        0xABCD,
        keccak256(
            abi.encodePacked(
                "\x19\x01",
                erc20.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        erc20.PERMIT_TYPEHASH(), investor, address(investmentManager), amount, 0, block.timestamp
                    )
                )
            )
        )
    );

    lPool.requestDepositWithPermit(amount, investor, block.timestamp, v, r, s);
    // To avoid stack too deep errors
    delete v;
    delete r;
    delete s;

    // ensure funds are locked in escrow
    assertEq(erc20.balanceOf(address(escrow)), amount);
    assertEq(erc20.balanceOf(investor), 0);

    // collect 50% of the tranche tokens
    homePools.isExecutedCollectInvest(
        poolId,
        trancheId,
        bytes32(bytes20(investor)),
        poolManager.currencyAddressToId(address(erc20)),
        uint128(amount),
        uint128(amount)
    );

    uint256 maxMint = lPool.maxMint(investor);
    lPool.mint(maxMint, investor);

    {
        TrancheToken trancheToken = TrancheToken(address(lPool.share()));
        assertEq(trancheToken.balanceOf(address(investor)), maxMint);

        // Sign permit for redeeming tranche tokens
        (v, r, s) = vm.sign(
            0xABCD,
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    trancheToken.DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            trancheToken.PERMIT_TYPEHASH(),
                            investor,
                            address(investmentManager),
                            maxMint,
                            0,
                            block.timestamp
                        )
                    )
                )
            )
        );
    }

    // Let's assume that there is another liquidity pool with the same poolId and trancheId
    // but a different currency
    LiquidityPool newLPool;
    {
        assert(currencyId != 123);
        address newErc20 = address(_newErc20("Y's Dollar", "USDY", 6));
        homePools.addCurrency(123, newErc20);
        homePools.allowPoolCurrency(poolId, 123);
        newLPool = LiquidityPool(poolManager.deployLiquidityPool(poolId, trancheId, newErc20));
    }
    assert(address(lPool) != address(newLPool));
    
    // Malicious actor can use the signature extracted from the mempool to 
    // request redemption from the different liquidity pool
    vm.prank(makeAddr("malicious"));
    newLPool.requestRedeemWithPermit(maxMint, investor, block.timestamp, v, r, s);

    // User's transaction will fail since the signature has already been used
    vm.expectRevert();
    lPool.requestRedeemWithPermit(maxMint, investor, block.timestamp, v, r, s);
}
```

***

## [M-03] Cached `DOMAIN_SEPARATOR` is incorrect for tranche tokens potentially breaking permit integrations

Attempts to interact with tranche tokens via `permit` may always revert.

### Proof of Concept

When new tranche tokens are deployed, the initial `DOMAIN_SEPARATOR` is calculated and cached in the constructor.<br>
<https://github.com/code-423n4/2023-09-centrifuge/blob/512e7a71ebd9ae76384f837204216f26380c9f91/src/token/ERC20.sol#L42-L49>

```solidity
    constructor(uint8 decimals_) {
        ...
        deploymentChainId = block.chainid;
        _DOMAIN_SEPARATOR = _calculateDomainSeparator(block.chainid);
    }
```

This uses an empty string since `name` is only set after deployment.<br>
<https://github.com/code-423n4/2023-09-centrifuge/blob/512e7a71ebd9ae76384f837204216f26380c9f91/src/util/Factory.sol#L81-L109>

```solidity
    function newTrancheToken(
        uint64 poolId,
        bytes16 trancheId,
        string memory name,
        string memory symbol,
        uint8 decimals,
        address[] calldata trancheTokenWards,
        address[] calldata restrictionManagerWards
    ) public auth returns (address) {
        ...
        TrancheToken token = new TrancheToken{salt: salt}(decimals);

        token.file("name", name);
        ...
    }
```

Consequently, the domain separator is incorrect (when `block.chainid == deploymentChainId` where the domain separator is not recalculated) and will cause reverts when signatures for `permit` are attempted to be constructed using the tranche token's `name` (which will not be empty).

It should also be noted that the tranche token `name` could be changed by a call to `updateTranchTokenMetadata` which may also introduce complications with the domain separator.

***

## [M-04] You can deposit really small amount for other users to DoS them

Deposit and mint under [**LiquidityPool**] lack access control, which enables any user to **proceed** the  mint/deposit for another user. Attacker can deposit (this does not require tokens) some wai before users TX to DoS the deposit.

### Proof of Concept

[deposit] and [mint] do [processDeposit]/[processMint] which are the secondary functions to the requests. These function do not take any value in the form of tokens, but only send shares to the receivers. This means they can be called for free.

With this an attacker who wants to DoS a user, can wait him to make the request to deposit and on the next epoch front run him by calling  [deposit] with something small like 1 wei. Afterwards when the user calls `deposit`, his TX will inevitable revert, as he will not have enough balance for the full deposit.

***

## [M-05] Investors claiming their `maxDeposit` by using the `LiquidityPool.deposit()` will cause other users to be unable to claim their `maxDeposit`/`maxMint`

Claiming deposits using the [`LiquidityPool.deposit()`] will cause the Escrow contract to not have enough shares to allow other investors to claim their maxDeposit or maxMint values for their deposited assets.

### Proof of Concept

*   Before an investor can claim their deposits, they first needs to request the deposit and wait for the Centrigue Chain to validate it in the next epoch.

*   Investors can request deposits at different epochs without the need to claim all the approved deposits before requesting a new deposit, in the end, the maxDeposit and maxMint values that the investor can claim will be increased accordingly based on all the request deposits that the investor makes.

*   When the requestDeposit of the investor is processed in the Centrifuge chain, a number of TrancheShares will be minted based on the price at the moment when the request was processed and the total amount of deposited assets, this TrancheShares will be deposited to the Escrow contract, and the TrancheShares will be waiting for the investors to claim their deposits.

*   When investors decide to claim their deposit they can use the [`LiquidityPool.deposit()`](https://github.com/code-423n4/2023-09-centrifuge/blob/main/src/LiquidityPool.sol#L141-L144) function, this function receives as arguments the number of assets that are being claimed and the address of the account to claim the deposits for.

```solidity
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    shares = investmentManager.processDeposit(receiver, assets);
    emit Deposit(address(this), receiver, assets, shares);
}
```

*   The [`LiquidityPool.deposit()`] function calls the [`InvestmentManager::processDeposit()`] which will validate that the amount of assets being claimed doesn't exceed the investor's deposit limits, will compute the deposit price in the [`InvestmentManager::calculateDepositPrice()`], which basically computes an average price for all the request deposits that have been accepted in the Centrifuge Chain, each of those request deposits could've been executed at a different price, so, this function, based on the values of maxDeposit and maxMint will estimate an average price for all the unclaimed deposits, later, using this computed price for the deposits will compute the equivalent of TrancheTokens for the CurrencyAmount being claimed, and finally, processDeposit() will transferFrom the escrow to the investor account the computed amount of TranchTokens.

```solidity
function processDeposit(address user, uint256 currencyAmount) public auth returns (uint256 trancheTokenAmount) {
    address liquidityPool = msg.sender;
    uint128 _currencyAmount = _toUint128(currencyAmount);
    require(
        //@audit-info => orderbook[][].maxDeposit is updated when the handleExecutedCollectInvest() was executed!
        //@audit-info => The orderbook keeps track of the number of TrancheToken shares that have been minted to the Escrow contract on the user's behalf!
        (_currencyAmount <= orderbook[user][liquidityPool].maxDeposit && _currencyAmount != 0),
        "InvestmentManager/amount-exceeds-deposit-limits"
    );

    //@audit-info => computes an average price for all the request deposits that have been accepted in the Centrifuge Chain and haven't been claimed yet!
    uint256 depositPrice = calculateDepositPrice(user, liquidityPool);
    require(depositPrice != 0, "LiquidityPool/deposit-token-price-0");

    //@audit-info => Based on the computed depositPrice will compute the equivalent of TrancheTokens for the CurrencyAmount being claimed
    uint128 _trancheTokenAmount = _calculateTrancheTokenAmount(_currencyAmount, liquidityPool, depositPrice);

    //@audit-info => transferFrom the escrow to the investor account the computed amount of TranchTokens.
    _deposit(_trancheTokenAmount, _currencyAmount, liquidityPool, user);
    trancheTokenAmount = uint256(_trancheTokenAmount);
}
```

**The problem** occurs when an investor hasn't claimed their deposits and has requested multiple deposits on different epochs at different prices. The [`InvestmentManager::calculateDepositPrice()`]function will compute an equivalent/average price for all the requestDeposits that haven't been claimed yet. Because of the different prices that the request deposits where processed at, the computed price will compute the most accurate average of the deposit's price, but there is a slight rounding error that causes the computed value of trancheTokenAmount to be slightly different from what it should exactly be.

*   That slight difference will make that the Escrow contract transfers slightly more shares to the investor claiming the deposits by using the [`LiquidityPool.deposit()`]
*   **As a result**, when another investor tries to claim their [maxDeposit] or [maxMint], now the Escrow contract doesn't have enough shares to make whole the request of the other investor, and as a consequence the other investor transaction will be reverted. That means the second investor won't be able to claim all the shares that it is entitled to claim because the Escrow contract doesn't have all those shares anymore.

**Coded PoC**

*   I used the [`LiquidityPool.t.sol`] test file as the base file for this PoC, please add the below testPoC to the LiquidityPool.t.sol file

*   In this PoC I demonstrate that Alice (A second investor) won't be able to claim her maxDeposit or maxMint amounts after the first investor uses the [`LiquidityPool.deposit()`] function to claim his [maxDeposit() assets]. The first investor makes two requestDeposit, each of them at a different epoch and at a different price, Alice on the other hand only does 1 requestDeposit in the second epoch.

*   Run this PoC two times, check the comments on the last 4 lines, one time we want to test Alice claiming her deposits using LiquidityPool::deposit(), and the second time using LiquidityPool::mint()
    *   The two executions should fail with the same problem.

<details>

```solidity
    function testDepositAtDifferentPricesPoC(uint64 poolId, bytes16 trancheId, uint128 currencyId) public {
        vm.assume(currencyId > 0);

        uint8 TRANCHE_TOKEN_DECIMALS = 18; // Like DAI
        uint8 INVESTMENT_CURRENCY_DECIMALS = 6; // 6, like USDC

        ERC20 currency = _newErc20("Currency", "CR", INVESTMENT_CURRENCY_DECIMALS);
        address lPool_ =
            deployLiquidityPool(poolId, TRANCHE_TOKEN_DECIMALS, "", "", trancheId, currencyId, address(currency));
        LiquidityPool lPool = LiquidityPool(lPool_);
        homePools.updateTrancheTokenPrice(poolId, trancheId, currencyId, 1000000000000000000);

        //@audit-info => Add Alice as a Member
        address alice = address(0x23232323);
        homePools.updateMember(poolId, trancheId, alice, type(uint64).max);

        // invest
        uint256 investmentAmount = 100000000; // 100 * 10**6
        homePools.updateMember(poolId, trancheId, self, type(uint64).max);
        currency.approve(address(investmentManager), investmentAmount);
        currency.mint(self, investmentAmount);
        lPool.requestDeposit(investmentAmount, self);

        // trigger executed collectInvest at a price of 1.25
        uint128 _currencyId = poolManager.currencyAddressToId(address(currency)); // retrieve currencyId
        uint128 currencyPayout = 100000000; // 100 * 10**6                                          
        uint128 firstTrancheTokenPayout = 80000000000000000000; // 100 * 10**18 / 1.25, rounded down
        homePools.isExecutedCollectInvest(
            poolId, trancheId, bytes32(bytes20(self)), _currencyId, currencyPayout, firstTrancheTokenPayout
        );

        // assert deposit & mint values adjusted
        assertEq(lPool.maxDeposit(self), currencyPayout);
        assertEq(lPool.maxMint(self), firstTrancheTokenPayout);

        // deposit price should be ~1.25*10**18 === 1250000000000000000
        assertEq(investmentManager.calculateDepositPrice(self, address(lPool)), 1250000000000000000);


        // second investment in a different epoch => different price
        currency.approve(address(investmentManager), investmentAmount);
        currency.mint(self, investmentAmount);
        lPool.requestDeposit(investmentAmount, self);

        // trigger executed collectInvest at a price of 2
        currencyPayout = 100000000; // 100 * 10**6
        uint128 secondTrancheTokenPayout = 50000000000000000000; // 100 * 10**18 / 1.4, rounded down
        homePools.isExecutedCollectInvest(
            poolId, trancheId, bytes32(bytes20(self)), _currencyId, currencyPayout, secondTrancheTokenPayout
        );

        // Alice invests the same amount as the other investor in the second epoch - Price is at 2
        currency.mint(alice, investmentAmount);

        vm.startPrank(alice);
        currency.approve(address(investmentManager), investmentAmount);
        lPool.requestDeposit(investmentAmount, alice);
        vm.stopPrank();

        homePools.isExecutedCollectInvest(
            poolId, trancheId, bytes32(bytes20(alice)), _currencyId, currencyPayout, secondTrancheTokenPayout
        );

        uint128 AliceTrancheTokenPayout = 50000000000000000000; // 100 * 10**18 / 1.4, rounded down

        //@audit-info => At this point, the Escrow contract should have the firstTrancheTokenPayout + secondTrancheTokenPayout + AliceTrancheTokenPayout
        assertEq(lPool.balanceOf(address(escrow)),firstTrancheTokenPayout + secondTrancheTokenPayout + AliceTrancheTokenPayout);


        // Investor collects his the deposited assets using the LiquidityPool::deposit()
        lPool.deposit(lPool.maxDeposit(self), self);
        

        // Alice tries to collect her deposited assets and gets her transactions reverted because the Escrow doesn't have the required TokenShares for Alice!
        vm.startPrank(alice);

        //@audit-info => Run the PoC one time to test Alice trying to claim their deposit using LiquidityPool.deposit()
        lPool.deposit(lPool.maxDeposit(alice), alice);
        
        //@audit-info => Run the PoC a second time, but now using LiquidityPool.mint()
        // lPool.mint(lPool.maxMint(alice), alice);
        vm.stopPrank();
    }
```

</details>

## [M-06] DelayedAdmin Cannot `PauseAdmin.removePauser`

As per the audit repository's documentation, which is confirmed as up-to-date, there are carefully considered emergency scenarios. Among these scenarios, one is described as follows:



    **Someone controls 1 pause admin and triggers a malicious `pause()`**

    * The delayed admin is a `ward` on the pause admin and can trigger `PauseAdmin.removePauser`.
    * It can then trigger `root.unpause()`.

That makes perfect sense from a security perspective. However the provided `DelayedAdmin` implementation lacks the necessary functionality to execute `PauseAdmin.removePauser` in the case of an emergency.

Striving to adhere to the documented [Severity Categorization], I have categorized this as Medium instead of Low. The reason is that it does not qualify as Low due to representing both a "function incorrect as to spec" issue and a critical feature missing from the project's security model. Without this emergency action for `PauseAdmin`, other recovery paths may have to wait for `Root`'s delay period or, at least temporarily, change the protocol's security model to make a recovery. In my view, this aligns with the "Assets not at direct risk, but the function of the protocol or its availability could be impacted" requirement for Medium severity. With that said, I realize the sponsors and judges will ultimately evaluate and categorise it based on their final risk analysis, not mine. I'm simply streamlining the process by presenting my perspective in advance.

### Proof of Concept

In order to remove a pauser from the `PauseAdmin` contract, the `removePause` function must be called:


```
    function removePauser(address user) external auth {
        pausers[user] = 0;
        emit RemovePauser(user);
    }
```

Since it is a short contract, here is the whole `DelayedAdmin` implementation:


```
// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.21;

import {Root} from "../Root.sol";
import {Auth} from "./../util/Auth.sol";

/// @title  Delayed Admin
/// @dev    Any ward on this contract can trigger
///         instantaneous pausing and unpausing
///         on the Root, as well as schedule and cancel
///         new relys through the timelock.
contract DelayedAdmin is Auth {
    Root public immutable root;

    // --- Events ---
    event File(bytes32 indexed what, address indexed data);

    constructor(address root_) {
        root = Root(root_);

        wards[msg.sender] = 1;
        emit Rely(msg.sender);
    }

    // --- Admin actions ---
    function pause() public auth {
        root.pause();
    }

    function unpause() public auth {
        root.unpause();
    }

    function scheduleRely(address target) public auth {
        root.scheduleRely(target);
    }

    function cancelRely(address target) public auth {
        root.cancelRely(target);
    }
}
```

No implemented functionalities exist to trigger `PauseAdmin.removePauser`. Additionally, the contract features an unused `event File`,
a and fails to record the `PauseAdmin`'s address upon initiation or elsewhere.

As anticipated, `Auth` (inherited) also does not handle this responsibility:

To confirm that I did not misunderstand anything, I thoroughly searched the entire audit repository for occurrences of `removePauser`.
However, I could only find them in `PauseAdmin.sol`, where the function to remove a pauser is implemented, and in a test case that
directly calls the `PauseAdmin`.


**1. Implement the `PauseAdmin.removePauser` Functionality in `DelayedAdmin.sol` with This Diff:**

```diff
5a6
> import {PauseAdmin} from "./PauseAdmin.sol";
13a15
>     PauseAdmin public immutable pauseAdmin;
18c20
<     constructor(address root_) {
---
>     constructor(address root_, address pauseAdmin_) {
19a22
>         pauseAdmin = PauseAdmin(pauseAdmin_);
41,42c44,48
<     // @audit HM? How can delayed admin call `PauseAdmin.removePauser if not coded here?
<     // @audit According to documentation: "The delayed admin is a ward on the pause admin and can trigger PauseAdmin.removePauser."
---
> 
>     // --- Emergency actions --
>     function removePauser(address pauser) public auth {
>         pauseAdmin.removePauser(pauser);
>     }

```

**2. Add This Test Function to `AdminTest` Contract in `test/Admin.t.sol`**

```
    function testEmergencyRemovePauser() public {
        address evilPauser = address(0x1337);
        pauseAdmin.addPauser(evilPauser);
        assertEq(pauseAdmin.pausers(evilPauser), 1);

        delayedAdmin.removePauser(evilPauser);
        assertEq(pauseAdmin.pausers(evilPauser), 0);
    }
```

**3. Change the `DelayedAdmin` Creation in `script/Deployer.sol` with This diff:**

```diff
55c55
<         delayedAdmin = new DelayedAdmin(address(root));
---
>         delayedAdmin = new DelayedAdmin(address(root), address(pauseAdmin));

```

**4. Test**

`$ forge test`

**[RaymondFam (lookout) commented](https://github.com/code-423n4/2023-09-centrifuge-findings/issues/92#issuecomment-1720289509):**
 > The sponsor has highlighted in Discord that these are EOAs capable of triggering to removePauser.

**[gzeon (judge) commented](https://github.com/code-423n4/2023-09-centrifuge-findings/issues/92#issuecomment-1735729992):**
 > Since the `removePauser` usecase is explicitly documented in the README and DelayedAdmin.sol is in-scope, I believe this is a valid Medium issue as the warden described.

**[hieronx (Centrifuge) confirmed and commented](https://github.com/code-423n4/2023-09-centrifuge-findings/issues/92#issuecomment-1745030969):**
 > Mitigated in https://github.com/centrifuge/liquidity-pools/pull/139



***

## [M-07] ```trancheTokenAmount``` should be rounded UP when proceeding to a withdrawal or previewing a withdrawal

This is good practice when implementing the EIP-4626 vault standard as it is more secure to favour the vault than its users in that case.<br>
This can also lead to issues down the line for other protocol integrating Centrifuge, that may assume that rounding was handled according to EIP-4626 best practices.

### Proof of Concept

When calling the [`processWithdraw`] function, the `trancheTokenAmount` is computed through the [`_calculateTrancheTokenAmount`] function, which rounds DOWN the number of shares required to be burnt to receive the `currencyAmount` payout/withdrawal.

```solidity
/// @dev Processes user's tranche token redemption after the epoch has been executed on Centrifuge.
/// In case user's redempion order was fullfilled on Centrifuge during epoch execution MaxRedeem and MaxWithdraw
/// are increased and LiquidityPool currency can be transferred to user's wallet on calling processRedeem or processWithdraw.
/// Note: The trancheTokenAmount required to fullfill the redemption order was already locked in escrow upon calling requestRedeem and burned upon collectRedeem.
/// @notice trancheTokenAmount return value is type of uint256 to be compliant with EIP4626 LiquidityPool interface
/// @return trancheTokenAmount the amount of trancheTokens redeemed/burned required to receive the currencyAmount payout/withdrawel.
function processWithdraw(uint256 currencyAmount, address receiver, address user)
public
auth
returns (uint256 trancheTokenAmount)
{
address liquidityPool = msg.sender;
uint128 _currencyAmount = _toUint128(currencyAmount);
require(
(_currencyAmount <= orderbook[user][liquidityPool].maxWithdraw && _currencyAmount != 0),
"InvestmentManager/amount-exceeds-withdraw-limits"
);

uint256 redeemPrice = calculateRedeemPrice(user, liquidityPool);
require(redeemPrice != 0, "LiquidityPool/redeem-token-price-0");

uint128 _trancheTokenAmount = _calculateTrancheTokenAmount(_currencyAmount, liquidityPool, redeemPrice);
_redeem(_trancheTokenAmount, _currencyAmount, liquidityPool, receiver, user);
trancheTokenAmount = uint256(_trancheTokenAmount);
}
```

```solidity
function _calculateTrancheTokenAmount(uint128 currencyAmount, address liquidityPool, uint256 price)
internal
view
returns (uint128 trancheTokenAmount)
{
(uint8 currencyDecimals, uint8 trancheTokenDecimals) = _getPoolDecimals(liquidityPool);

uint256 currencyAmountInPriceDecimals = _toPriceDecimals(currencyAmount, currencyDecimals, liquidityPool).mulDiv(
10 ** PRICE_DECIMALS, price, MathLib.Rounding.Down
);

trancheTokenAmount = _fromPriceDecimals(currencyAmountInPriceDecimals, trancheTokenDecimals, liquidityPool);
}
```

As an additional reason the round UP the amount, the computed amount of shares is also used to [`_decreaseRedemptionLimits`], which could potentially lead to a rounded UP remaining redemption limit post withdrawal (note that for the same reason it would we wise to round UP the `_currency` amount as well when calling `_decreaseRedemptionLimits`).

The same function is used in the [`previewWithdraw`] function, where is should be rounded UP for the same reasons.

```solidity
/// @return trancheTokenAmount is type of uin256 to support the EIP4626 Liquidity Pool interface
function previewWithdraw(address user, address liquidityPool, uint256 _currencyAmount)
public
view
returns (uint256 trancheTokenAmount)
{
uint128 currencyAmount = _toUint128(_currencyAmount);
uint256 redeemPrice = calculateRedeemPrice(user, liquidityPool);
if (redeemPrice == 0) return 0;

trancheTokenAmount = uint256(_calculateTrancheTokenAmount(currencyAmount, liquidityPool, redeemPrice));
}
```

## [M-08] The Restriction Manager does not completely implement ERC1404 which leads to accounts that are supposed to be restricted actually having access to do with their tokens as they see fit

Medium, contract's intended logic is for *blacklisted* users not to be able to interact with their system so as to follow rules set by regulationary bodies in the case where a user does anything that warrants them to be blacklisted, but this is clearly broken since only half the window is closed as current implementation only checks on receiver being blacklisted and not sender.

### Proof of Concept

The current implementation of the ERC1404 restrictions within the `RestrictionManager.sol` contract only places restrictions on the receiving address in token transfer instances. This oversight means that the sending addresses are not restricted, which poses a regulatory and compliance risk. Should a user be `blacklisted` for any reason, they can continue to transfer tokens as long as the receiving address is a valid member. This behaviour is contrary to expectations from regulatory bodies, especially say in the U.S where these bodies are very strict and a little in-compliance could land Centrifuge a lawsuit., which may expect complete trading restrictions for such blacklisted individuals.

Within the `RestrictionManager` contract, the method `detectTransferRestriction` only checks if the receiving address (`to`) is a valid member:

[RestrictionManager.sol#L28-L34]

```solidity
function detectTransferRestriction(address from, address to, uint256 value) public view returns (uint8) {
    if (!hasMember(to)) {
        return DESTINATION_NOT_A_MEMBER_RESTRICTION_CODE;
    }
    return SUCCESS_CODE;
}
```

In the above code, the sending address (`from`) is never checked against the membership restrictions, which means blacklisted users can still initiate transfers and when checking the transfer restriction from both `tranchtoken.sol` and the `liquiditypool.sol` it's going to wrongly return true for a personnel that should be false

See [Tranche.sol#L80-L82)]

```solidity
// function checkTransferRestriction(address from, address to, uint256 value) public view returns (bool) {
//     return share.checkTransferRestriction(from, to, value);
// }
```

Also [Tranche.sol#L35-L39]

```solidity
    modifier restricted(address from, address to, uint256 value) {
        uint8 restrictionCode = detectTransferRestriction(from, to, value);
        require(restrictionCode == restrictionManager.SUCCESS_CODE(), messageForTransferRestriction(restrictionCode));
        _;
    }
```

This function suggests that the system's logic may rely on the `detectTransferRestriction` method in other parts of the ecosystem. Consequently, if the restriction manager's logic is flawed, these other parts may also allow unauthorised transfers.

**Foundry POC**

Add this to the `Tranche.t.sol` contract

```solidity
    function testTransferFromTokensFromBlacklistedAccountWorks(uint256 amount, address targetUser, uint256 validUntil) public {
        vm.assume(baseAssumptions(validUntil, targetUser));

        restrictionManager.updateMember(targetUser, validUntil);
        assertEq(restrictionManager.members(targetUser), validUntil);
        restrictionManager.updateMember(address(this), block.timestamp);
        assertEq(restrictionManager.members(address(this)), block.timestamp);

        token.mint(address(this), amount);
        vm.warp(block.timestamp + 1);

        token.transferFrom(address(this), targetUser, amount);
        assertEq(token.balanceOf(targetUser), amount);
    }
```

As seen even after `address(this)` stops being a member they could still transfer tokens to another user in as much as said user is still a member, which means a *blacklisted* user could easily do anything with their tokens all they need to do is to delegate to another member.