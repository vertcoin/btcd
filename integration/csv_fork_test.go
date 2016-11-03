// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This file is ignored during the regular tests due to the following build tag.
// +build rpctest

package integration

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpctest"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// makeTestOutput creates an on-chain output paying to a freshly generated
// p2pkh output with the specified amount.
func makeTestOutput(r *rpctest.Harness, t *testing.T,
	amt btcutil.Amount) (*btcec.PrivateKey, *wire.OutPoint, []byte, error) {

	// Create a fresh key, then send some coins to an address spendable by
	// that key.
	key, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, nil, nil, err
	}

	// Using the key created above, generate a pkScript which it's able to
	// spend.
	a, err := btcutil.NewAddressPubKey(key.PubKey().SerializeCompressed(), r.ActiveNet)
	if err != nil {
		return nil, nil, nil, err
	}
	selfAddrScript, err := txscript.PayToAddrScript(a.AddressPubKeyHash())
	if err != nil {
		return nil, nil, nil, err
	}
	output := &wire.TxOut{PkScript: selfAddrScript, Value: 1e8}

	// Next, create and broadcast a transaction paying to the output.
	fundTx, err := r.CreateTransaction([]*wire.TxOut{output}, 10)
	if err != nil {
		return nil, nil, nil, err
	}
	txid, err := r.Node.SendRawTransaction(fundTx, true)
	if err != nil {
		return nil, nil, nil, err
	}

	// The transaction created above should be included within the next
	// generated block.
	blockHash, err := r.Node.Generate(1)
	if err != nil {
		return nil, nil, nil, err
	}
	assertTxInBlock(r, t, blockHash[0], txid)

	// Locate the output index of the coins spendable by the key we
	// generated above, this is needed in order to create a proper utxo for
	// this output.
	var outputIndex uint32
	if bytes.Equal(fundTx.TxOut[0].PkScript, selfAddrScript) {
		outputIndex = 0
	} else {
		outputIndex = 1
	}

	utxo := &wire.OutPoint{
		Hash:  fundTx.TxHash(),
		Index: outputIndex,
	}

	return key, utxo, selfAddrScript, nil
}

// TestBIP0113Activation tests for proper adherance of the BIP 113 rule
// constraint which requires all transaction finality tests to use the MTP of
// the last 11 blocks, rather than the timestamp of the block which includes
// them.
//
// Overview:
//  - Pre soft-fork:
//    - Transactions with non-final lock-times from the PoV of MTP should be
//    rejected from the mempool.
//    - Transactions within non-final MTP based lock-times should be accepted
//    in valid blocks.
//
//  - Post soft-fork:
//    - Transactions with non-final lock-times from the PoV of MTP should be
//    rejected from the mempool and when found within otherwise valid blocks.
//    - Transactions with final lock-times from the PoV of MTP should be
//    accepted to the mempool and mined in future block.
func TestBIP0113Activation(t *testing.T) {
	t.Parallel()

	// Initialize the primary mining node with only the genesis block.
	btcdCfg := []string{"--rejectnonstd"}
	r, err := rpctest.New(&chaincfg.SimNetParams, nil, btcdCfg)
	if err != nil {
		t.Fatal("unable to create primary harness: ", err)
	}
	if err := r.SetUp(true, 10); err != nil {
		t.Fatalf("unable to setup test chain: %v", err)
	}
	defer r.TearDown()

	// Create a fresh output for usage within the test below.
	const outputValue = btcutil.SatoshiPerBitcoin
	outputKey, testOutput, testPkScript, err := makeTestOutput(r, t,
		outputValue)
	if err != nil {
		t.Fatalf("unable to create test output: %v", err)
	}

	// Fetch a fresh address from the harness, we'll use this address to
	// send funds back into the Harness.
	addr, err := r.NewAddress()
	if err != nil {
		t.Fatalf("unable to generate address: %v", err)
	}
	addrScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to generate addr script: %v", err)
	}

	// Now create a transaction with a lock time which is "final" according
	// to the latest block, but not according to the current median time
	// past.
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *testOutput,
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: addrScript,
		Value:    outputValue - 1000,
	})

	// We set the lock-time of the transaction to just one minute after the
	// current MTP of the chain.
	chainInfo, err := r.Node.GetBlockChainInfo()
	if err != nil {
		t.Fatalf("unable to query for chain info: %v", err)
	}
	tx.LockTime = uint32(chainInfo.MedianTime) + 1

	sigScript, err := txscript.SignatureScript(tx, 0, testPkScript,
		txscript.SigHashAll, outputKey, true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[0].SignatureScript = sigScript

	// This transaction should be rejected from the mempool as using MTP
	// for transactions finality is now a policy rule. Additionally, the
	// exact error should be the rejection of a non-final transaction.
	_, err = r.Node.SendRawTransaction(tx, true)
	if err == nil {
		t.Fatalf("transaction accepted, but should be non-final")
	} else if !strings.Contains(err.Error(), "not finalized") {
		t.Fatalf("transaction should be rejected due to being "+
			"non-final, instead :%v", err)
	}

	// However, since the block validation consensus rules haven't yet
	// activated, a block including the transaction should be accepted.
	txns := []*btcutil.Tx{btcutil.NewTx(tx)}
	block, err := r.GenerateAndSubmitBlock(txns, -1, time.Time{})
	if err != nil {
		t.Fatalf("unable to submit block: %v", err)
	}
	txid := tx.TxHash()
	assertTxInBlock(r, t, block.Hash(), &txid)

	// Next, mine enough blocks to ensure that the soft-fork becomes
	// activated. Assert that the block version of the second-to-last block
	// in the final range is active.
	numBlocks := (r.ActiveNet.MinerConfirmationWindow * 2) + 1
	if _, err := r.Node.Generate(numBlocks); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}
	if !isSoftForkActive(r, t, "csv") {
		t.Fatal("csv soft-fork not yet active, but should be!")
	}

	// With the fork-active, we repeat a similar scenario to the one above.
	// This time, all transactions which are final according to the MTP
	// *should* be accepted to both the mempool and within a valid block.
	// While transactions with lock-times *after* the current MTP should be
	// rejected.
	chainInfo, err = r.Node.GetBlockChainInfo()
	if err != nil {
		t.Fatalf("unable to query for chain info: %v", err)
	}
	medianTimePast := chainInfo.MedianTime

	// Create another test output to be spent shortly below.
	outputKey, testOutput, testPkScript, err = makeTestOutput(r, t,
		outputValue)
	if err != nil {
		t.Fatalf("unable to create test output: %v", err)
	}

	// Create a new transaction with a lock-time past the current known
	// MTP.
	tx = wire.NewMsgTx(1)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *testOutput,
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: addrScript,
		Value:    outputValue - 1000,
	})
	tx.LockTime = uint32(medianTimePast + 60)
	sigScript, err = txscript.SignatureScript(tx, 0, testPkScript,
		txscript.SigHashAll, outputKey, true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[0].SignatureScript = sigScript

	// This transaction should be rejected from both the mempool and within
	// a block.
	if _, err = r.Node.SendRawTransaction(tx, true); err == nil {
		t.Fatal("transaction was accepted into the mempool but should " +
			"be rejected!")
	}
	txns = []*btcutil.Tx{btcutil.NewTx(tx)}
	if _, err := r.GenerateAndSubmitBlock(txns, -1, time.Time{}); err == nil {
		t.Fatal("block should be rejected due to non-final txn, but was " +
			"accepted")
	}

	// Finally, a transaction with a lock-time before the current MTP.
	outputKey, testOutput, testPkScript, err = makeTestOutput(r, t,
		outputValue)
	if err != nil {
		t.Fatalf("unable to create test output: %v", err)
	}
	tx = wire.NewMsgTx(1)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *testOutput,
	})
	tx.AddTxOut(&wire.TxOut{
		PkScript: addrScript,
		Value:    outputValue - 1000,
	})
	tx.LockTime = uint32(medianTimePast - 100)
	sigScript, err = txscript.SignatureScript(tx, 0, testPkScript,
		txscript.SigHashAll, outputKey, true)
	if err != nil {
		t.Fatalf("unable to generate sig: %v", err)
	}
	tx.TxIn[0].SignatureScript = sigScript

	// The transaction should be accepted both into the mempool and found
	// in the next mined block.
	txHash, err := r.Node.SendRawTransaction(tx, true)
	if err != nil {
		t.Fatalf("unable to broadcast transaction: %v", err)
	}
	blockHash, err := r.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}
	assertTxInBlock(r, t, blockHash[0], txHash)
}

// createCSVOutput creates an output paying to a trivially redeemable CSV
// pkScript with the specified time-lock.
func createCSVOutput(r *rpctest.Harness, t *testing.T,
	numSatoshis btcutil.Amount, timeLock int32,
	isSeconds bool) ([]byte, *wire.OutPoint, *wire.MsgTx, error) {

	// Convert the time-lock to the proper sequence lock based according to
	// if the lock is seconds or time based.
	sequenceLock := blockchain.LockTimeToSequence(isSeconds,
		uint32(timeLock))

	// Our CSV script is simply: <sequenceLock> OP_CSV OP_DROP
	b := txscript.NewScriptBuilder()
	b.AddInt64(int64(sequenceLock))
	b.AddOp(txscript.OP_CHECKSEQUENCEVERIFY)
	b.AddOp(txscript.OP_DROP)
	csvScript, err := b.Script()
	if err != nil {
		return nil, nil, nil, err
	}

	// Using the script generated above, create a P2SH output which will be
	// accepted into the mempool.
	p2shAddr, err := btcutil.NewAddressScriptHash(csvScript, r.ActiveNet)
	if err != nil {
		return nil, nil, nil, err
	}
	p2shScript, err := txscript.PayToAddrScript(p2shAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	output := &wire.TxOut{
		PkScript: p2shScript,
		Value:    int64(numSatoshis),
	}

	// Finally create a valid transactions which creates the output crafted
	// above.
	tx, err := r.CreateTransaction([]*wire.TxOut{output}, 10)
	if err != nil {
		return nil, nil, nil, err
	}

	var outputIndex uint32
	if bytes.Equal(tx.TxOut[0].PkScript, p2shScript) {
		outputIndex = 0
	} else {
		outputIndex = 1
	}

	utxo := &wire.OutPoint{
		Hash:  tx.TxHash(),
		Index: outputIndex,
	}

	return csvScript, utxo, tx, nil
}

// spendCSVOutput spends an output previously created by the createCSVOutput
// function. The sigScript is a trivial push of OP_TRUE followed by the
// redeemScript to pass P2SH evaluation.
func spendCSVOutput(redeemScript []byte, csvUTXO *wire.OutPoint,
	sequence uint32, targetOutput *wire.TxOut,
	txVersion int32) (*wire.MsgTx, error) {

	tx := wire.NewMsgTx(txVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: *csvUTXO,
		Sequence:         sequence,
	})
	tx.AddTxOut(targetOutput)

	b := txscript.NewScriptBuilder()
	b.AddOp(txscript.OP_TRUE)
	b.AddData(redeemScript)

	sigScript, err := b.Script()
	if err != nil {
		return nil, err
	}
	tx.TxIn[0].SignatureScript = sigScript

	return tx, nil
}

// isSoftForkActive returns true if the soft-fork as defined by the passed
// string is currently active.
func isSoftForkActive(r *rpctest.Harness, t *testing.T, bip9ForkName string) bool {
	chainInfo, err := r.Node.GetBlockChainInfo()
	if err != nil {
		t.Fatalf("unable to query for chain info: %v", err)
	}

	csvForkState, ok := chainInfo.Bip9SoftForks[bip9ForkName]
	if !ok {
		t.Fatalf("%v soft-fork state not found in getblockchaininfo "+
			"response", bip9ForkName)
	}

	return csvForkState.Status == "active"
}

// assertTxInBlock asserts a transaction with the specified txid is found
// within the block with the passed block hash.
func assertTxInBlock(r *rpctest.Harness, t *testing.T, blockHash *chainhash.Hash,
	txid *chainhash.Hash) {

	block, err := r.Node.GetBlock(blockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	if len(block.Transactions) < 2 {
		t.Fatal("target transaction was not mined")
	}

	for _, txn := range block.Transactions {
		txHash := txn.TxHash()
		if (&txHash).IsEqual(txid) {
			return
		}
	}

	t.Fatalf("txid %v was not found in block %v", txid, blockHash)
}

// TestBIP0068AndBIP0112Activation tests for the proper adherence to the BIP
// 112 and BIP 68 rule-set after the activation of the CSV-package soft-fork.
//
// Overview:
//  - Pre soft-fork:
//    - A transaction spending a CSV output validly should be rejected from the
//    mempool, but accepted in a valid generated block including the
//    transaction.
//  - Post soft-fork:
//    - See the cases exercised within the table driven tests towards the end
//    of this test.
func TestBIP0068AndBIP0112Activation(t *testing.T) {
	t.Parallel()

	// We'd like the test proper evaluation and validation of the BIP 68
	// (sequence locks) and BIP 112 rule-sets which add input-age based
	// relative lock times.

	// Initialize the primary mining node with only the genesis block.
	btcdCfg := []string{"--rejectnonstd"}
	r, err := rpctest.New(&chaincfg.SimNetParams, nil, btcdCfg)
	if err != nil {
		t.Fatal("unable to create primary harness: ", err)
	}
	if err := r.SetUp(true, 10); err != nil {
		t.Fatalf("unable to setup test chain: %v", err)
	}

	if isSoftForkActive(r, t, "csv") {
		t.Fatal("CSV soft-fork is active, yet shouldn't be")
	}

	harnessAddr, err := r.NewAddress()
	if err != nil {
		t.Fatalf("unable to obtain harness address: %v", err)
	}
	harnessScript, err := txscript.PayToAddrScript(harnessAddr)
	if err != nil {
		t.Fatalf("unable to generate pkScript: %v", err)
	}

	const outputAmt = btcutil.SatoshiPerBitcoin

	// Create a trivially spendable output with a CSV lock-time of 10
	// relative blocks.
	redeemScript, testUTXO, tx, err := createCSVOutput(r, t, outputAmt, 10,
		false)
	if err != nil {
		t.Fatalf("unable to create CSV encumbered output: %v", err)
	}

	// As the transaction is p2sh it should be accepted into the mempool
	// and fond within the next generated block.
	if _, err := r.Node.SendRawTransaction(tx, true); err != nil {
		t.Fatalf("unable to broadcast tx: %v", err)
	}
	blocks, err := r.Node.Generate(1)
	if err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}
	txid := tx.TxHash()
	assertTxInBlock(r, t, blocks[0], &txid)

	sweepOutput := &wire.TxOut{
		Value:    outputAmt - 5000,
		PkScript: harnessScript,
	}

	// Generate a custom transaction which spends the CSV output.
	sequenceNum := blockchain.LockTimeToSequence(false, 10)
	spendingTx, err := spendCSVOutput(redeemScript, testUTXO, sequenceNum,
		sweepOutput, 2)
	if err != nil {
		t.Fatalf("unable to spend csv output: %v", err)
	}

	// This transaction should be rejected from the mempool since CSV
	// validation is already mempool policy pre-fork.
	_, err = r.Node.SendRawTransaction(spendingTx, true)
	if err == nil {
		t.Fatalf("transaction should have been rejected, but was " +
			"instead accepted")
	}

	// However, this transaction should be accepted in a custom generate
	// block as CSV validation for scripts within blocks shouldn't yet be
	// active.
	txns := []*btcutil.Tx{btcutil.NewTx(spendingTx)}
	block, err := r.GenerateAndSubmitBlock(txns, -1, time.Time{})
	if err != nil {
		t.Fatalf("unable to submit block: %v", err)
	}
	txid = spendingTx.TxHash()
	assertTxInBlock(r, t, block.Hash(), &txid)

	// Next generate enough blocks to trigger activation of the CSV
	// soft-fork. At this point, the fork should now be marked as active.
	numBlocks := (r.ActiveNet.MinerConfirmationWindow * 2) + 1
	if _, err := r.Node.Generate(numBlocks); err != nil {
		t.Fatalf("unable to generate blocks: %v", err)
	}
	if !isSoftForkActive(r, t, "csv") {
		t.Fatalf("csv soft-fork not yet active, but should be!")
	}

	// Knowing the number of outputs needed for the tests below, create a
	// fresh output for use within each of the test-cases below.
	const relativeBlockLock = 10
	const relativeTimeLock = 512
	const numTests = 6
	type csvOutput struct {
		RedeemScript []byte
		Utxo         *wire.OutPoint
		Timelock     int32
	}
	var spendableInputs [numTests]csvOutput

	// Create three outputs which have a block-based sequence locks, and
	// three outputs which use the above time based sequence lock.
	for i := 0; i < numTests; i++ {
		var timeLock int32
		var isSeconds bool

		if i < 3 {
			timeLock = relativeBlockLock
			isSeconds = false
		} else {
			timeLock = relativeTimeLock
			isSeconds = true
		}

		redeemScript, utxo, tx, err := createCSVOutput(r, t, outputAmt,
			timeLock, isSeconds)
		if err != nil {
			t.Fatalf("unable to create CSV output: %v", err)
		}

		if _, err := r.Node.SendRawTransaction(tx, true); err != nil {
			t.Fatalf("unable to broadcast transaction: %v", err)
		}

		spendableInputs[i] = csvOutput{
			RedeemScript: redeemScript,
			Utxo:         utxo,
			Timelock:     timeLock,
		}
	}

	// Mine a single block including all the transactions generated above.
	if _, err := r.Node.Generate(1); err != nil {
		t.Fatalf("unable to generate block: %v", err)
	}

	// Now mine 10 additional blocks giving the inputs generated above a
	// age of 11. Space out each block 10 minutes after the previous block.
	prevBlockHash, err := r.Node.GetBestBlockHash()
	if err != nil {
		t.Fatalf("unable to get prior block hash: %v", err)
	}
	prevBlock, err := r.Node.GetBlock(prevBlockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	for i := 0; i < 10; i++ {
		timeStamp := prevBlock.Header.Timestamp.Add(time.Minute * 10)
		b, err := r.GenerateAndSubmitBlock(nil, -1, timeStamp)
		if err != nil {
			t.Fatalf("unable to generate block: %v", err)
		}

		prevBlock = b.MsgBlock()
	}

	// A helper function to create fully signed transactions in-line during
	// the array initialization below.
	var inputIndex uint32
	makeTxCase := func(sequenceNum uint32, txVersion int32) *wire.MsgTx {
		csvInput := spendableInputs[inputIndex]

		tx, err := spendCSVOutput(csvInput.RedeemScript, csvInput.Utxo,
			sequenceNum, sweepOutput, txVersion)
		if err != nil {
			t.Fatalf("unable to spend CSV output: %v", err)
		}

		inputIndex++
		return tx
	}

	tests := [numTests]struct {
		tx *wire.MsgTx

		accept bool
	}{
		// A valid transaction with a single input a sequence number
		// creating a 100 block relative time-lock. This transaction
		// should be rejected as its version number is 1, and only tx
		// of version > 2 will trigger the CSV behavior.
		{
			tx:     makeTxCase(blockchain.LockTimeToSequence(false, 100), 1),
			accept: false,
		},
		// A transaction of version 2 spending a single input. The
		// input has a relative time-lock of 1 blocks, but the disable
		// bit it set. The transaction should be rejected as a result.
		{
			tx: makeTxCase(
				blockchain.LockTimeToSequence(false, 1)|wire.SequenceLockTimeDisabled,
				2,
			),
			accept: false,
		},
		// A v2 transaction with a single input having a 10 lock
		// relative time lock. The referenced input is 11 blocks old so
		// the transaction should be accepted.
		{
			tx:     makeTxCase(blockchain.LockTimeToSequence(false, 10), 2),
			accept: true,
		},
		// A v2 transaction whose input has a 1000 relative time lock.
		// This should be rejected as the input's age is only 11
		// blocks.
		{
			tx:     makeTxCase(blockchain.LockTimeToSequence(false, 1000), 2),
			accept: false,
		},
		// A v2 transaction with a single input having a 512,000 second
		// relative time-lock. This transaction should be rejected as 6
		// days worth of blocks haven't yet been mined. The referenced
		// input doesn't have sufficient age.
		{
			tx:     makeTxCase(blockchain.LockTimeToSequence(true, 512000), 2),
			accept: false,
		},
		// A v2 transaction whose single input has a 512 second
		// relative time-lock. This transaction should be accepted as
		// finalized.
		{
			tx:     makeTxCase(blockchain.LockTimeToSequence(true, 512), 2),
			accept: true,
		},
	}

	for i, test := range tests {
		txid, err := r.Node.SendRawTransaction(test.tx, true)
		switch {
		// Test case passes, nothing further to report.
		case test.accept && err == nil:

		// Transaction should have been accepted but we have a non-nil
		// error.
		case test.accept && err != nil:
			t.Fatalf("test #%d, transaction should be accepted, "+
				"but was rejected: %v", i, err)

		// Transaction should have been rejected, but it was accepted.
		case !test.accept && err == nil:
			t.Fatalf("test #%d, transaction should be rejected, "+
				"but was accepted", i)

		// Transaction was rejected as wanted, nothing more to do.
		case !test.accept && err != nil:
		}

		// If the transaction should be rejected, manually mine a block
		// with the non-final transaction. It should be rejected.
		if !test.accept {
			txns := []*btcutil.Tx{btcutil.NewTx(test.tx)}
			_, err := r.GenerateAndSubmitBlock(txns, -1, time.Time{})
			if err == nil {
				t.Fatalf("test #%d, invalid block accepted", i)
			}

			continue
		}

		// Generate a block, the transaction should be included within
		// the newly mined block.
		blockHashes, err := r.Node.Generate(1)
		if err != nil {
			t.Fatalf("unable to mine block: %v", err)
		}
		assertTxInBlock(r, t, blockHashes[0], txid)
	}
}
