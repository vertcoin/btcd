// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"math/big"
  "math"
	"time"
  "io"
  "os"

	"github.com/adiabat/btcd/chaincfg/chainhash"
  "github.com/adiabat/btcd/chaincfg/difficulty"
	"github.com/adiabat/btcd/wire"
	
	"golang.org/x/crypto/scrypt"
	"github.com/bitgoin/lyra2rev2"
)

// These variables are the chain proof-of-work limit parameters for each default
// network.
var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// mainPowLimit is the highest proof of work value a Bitcoin block can
	// have for the main network.  It is the value 2^224 - 1.
	mainPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	// regressionPowLimit is the highest proof of work value a Bitcoin block
	// can have for the regression test network.  It is the value 2^255 - 1.
	regressionPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)

	// testNet3PowLimit is the highest proof of work value a Bitcoin block
	// can have for the test network (version 3).  It is the value
	// 2^224 - 1.
	testNet3PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 224), bigOne)

	bc2NetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 231), bigOne)

	liteCoinTestNet4PowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 236), bigOne)

	// simNetPowLimit is the highest proof of work value a Bitcoin block
	// can have for the simulation test network.  It is the value 2^255 - 1.
	simNetPowLimit = new(big.Int).Sub(new(big.Int).Lsh(bigOne, 255), bigOne)
)

// Checkpoint identifies a known good point in the block chain.  Using
// checkpoints allows a few optimizations for old blocks during initial download
// and also prevents forks from old blocks.
//
// Each checkpoint is selected based upon several factors.  See the
// documentation for blockchain.IsCheckpointCandidate for details on the
// selection criteria.
type Checkpoint struct {
	Height int32
	Hash   *chainhash.Hash
}

// Params defines a Bitcoin network by its parameters.  These parameters may be
// used by Bitcoin applications to differentiate networks as well as addresses
// and keys for one network from those intended for use on another network.
type Params struct {
	// Name defines a human-readable identifier for the network.
	Name string

	// Net defines the magic bytes used to identify the network.
	Net wire.BitcoinNet

	// DefaultPort defines the default peer-to-peer port for the network.
	DefaultPort string

	// DNSSeeds defines a list of DNS seeds for the network that are used
	// as one method to discover peers.
	DNSSeeds []string

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash

	// The function used to calculate the proof of work value for a block
	PoWFunction func(b []byte, height int32) chainhash.Hash
  
  // The function used to calculate the difficulty of a given block
  DiffCalcFunction func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error)

	// PowLimit defines the highest allowed proof of work value for a block
	// as a uint256.
	PowLimit *big.Int

	// PowLimitBits defines the highest allowed proof of work value for a
	// block in compact form.
	PowLimitBits uint32

	// CoinbaseMaturity is the number of blocks required before newly mined
	// coins (coinbase transactions) can be spent.
	CoinbaseMaturity uint16

	// SubsidyReductionInterval is the interval of blocks before the subsidy
	// is reduced.
	SubsidyReductionInterval int32

	// TargetTimespan is the desired amount of time that should elapse
	// before the block difficulty requirement is examined to determine how
	// it should be changed in order to maintain the desired block
	// generation rate.
	TargetTimespan time.Duration

	// TargetTimePerBlock is the desired amount of time to generate each
	// block.
	TargetTimePerBlock time.Duration

	// RetargetAdjustmentFactor is the adjustment factor used to limit
	// the minimum and maximum amount of adjustment that can occur between
	// difficulty retargets.
	RetargetAdjustmentFactor int64

	// ReduceMinDifficulty defines whether the network should reduce the
	// minimum required difficulty after a long enough period of time has
	// passed without finding a block.  This is really only useful for test
	// networks and should not be set on a main network.
	ReduceMinDifficulty bool

	// MinDiffReductionTime is the amount of time after which the minimum
	// required difficulty should be reduced when a block hasn't been found.
	//
	// NOTE: This only applies if ReduceMinDifficulty is true.
	MinDiffReductionTime time.Duration

	// GenerateSupported specifies whether or not CPU mining is allowed.
	GenerateSupported bool

	// Checkpoints ordered from oldest to newest.
	Checkpoints []Checkpoint

	// Enforce current block version once network has
	// upgraded.  This is part of BIP0034.
	BlockEnforceNumRequired uint64

	// Reject previous block versions once network has
	// upgraded.  This is part of BIP0034.
	BlockRejectNumRequired uint64

	// The number of nodes to check.  This is part of BIP0034.
	BlockUpgradeNumToCheck uint64

	// Mempool parameters
	RelayNonStdTxs bool

	// Address encoding magics
	PubKeyHashAddrID byte   // First byte of a P2PKH address
	ScriptHashAddrID byte   // First byte of a P2SH address
	PrivateKeyID     byte   // First byte of a WIF private key
	Bech32Prefix     string // HRP for bech32 address

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID [4]byte
	HDPublicKeyID  [4]byte

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType uint32
}

/* calcDiff returns a bool given two block headers.  This bool is
true if the correct dificulty adjustment is seen in the "next" header.
Only feed it headers n-2016 and n-1, otherwise it will calculate a difficulty
when no adjustment should take place, and return false.
Note that the epoch is actually 2015 blocks long, which is confusing. */
func calcDiffAdjustBitcoin(start, end wire.BlockHeader, p *Params) uint32 {
	minRetargetTimespan := int64(p.TargetTimespan.Seconds()) / p.RetargetAdjustmentFactor
	maxRetargetTimespan := int64(p.TargetTimespan.Seconds()) * p.RetargetAdjustmentFactor
	duration := end.Timestamp.UnixNano() - start.Timestamp.UnixNano()
	if duration < minRetargetTimespan {
		duration = minRetargetTimespan
	} else if duration > maxRetargetTimespan {
		duration = maxRetargetTimespan
	}

	// calculation of new 32-byte difficulty target
	// first turn the previous target into a big int
	prevTarget := difficulty.CompactToBig(start.Bits)
	// new target is old * duration...
	newTarget := new(big.Int).Mul(prevTarget, big.NewInt(duration))
	// divided by 2 weeks
	newTarget.Div(newTarget, big.NewInt(int64(p.TargetTimespan.Seconds())))

  powLimit := difficulty.CompactToBig(p.PowLimitBits)
  
	// clip again if above minimum target (too easy)
	if newTarget.Cmp(powLimit) > 0 {
		newTarget.Set(powLimit)
	}
  
	// calculate and return 4-byte 'bits' difficulty from 32-byte target
	return difficulty.BigToCompact(newTarget)
}

func BTCDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  epochLength := int32(p.TargetTimespan / p.TargetTimePerBlock)
  var err error
  var cur, prev, epochStart wire.BlockHeader
  
  offsetHeight := height - startheight
  
  // seek to n-1 header
  _, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  // read in n-1
  err = prev.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
    // seek to curHeight header and read in
  _, err = r.Seek(int64(80*(offsetHeight)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = cur.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
  _, err = r.Seek(int64(80*(offsetHeight-(height%epochLength))), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = epochStart.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
  var rightBits uint32
  
  if (height)%epochLength == 0 {
    // if so, check if difficulty adjustment is valid.
    // That whole "controlled supply" thing.
    // calculate diff n based on n-2016 ... n-1
    rightBits = calcDiffAdjustBitcoin(epochStart, prev, p)
  } else { // not a new epoch
    rightBits = epochStart.Bits
    
    // if on testnet, check for difficulty nerfing
    if p.ReduceMinDifficulty && cur.Timestamp.After(
      prev.Timestamp.Add(p.TargetTimePerBlock*2)) {
      rightBits = p.PowLimitBits // difficulty 1
    }
  }
  
  return rightBits, nil
}

func LTCDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  epochLength := int32(p.TargetTimespan / p.TargetTimePerBlock)
  var err error
  var cur, prev, epochStart wire.BlockHeader
  
  offsetHeight := height - startheight
  
  // seek to n-1 header
  _, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  // read in n-1
  err = prev.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
    // seek to curHeight header and read in
  _, err = r.Seek(int64(80*(offsetHeight)), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = cur.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
  _, err = r.Seek(int64(80*(offsetHeight-(height%epochLength))), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  err = epochStart.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
  var rightBits uint32
  
  if (height)%epochLength == 0 {
    // if so, check if difficulty adjustment is valid.
    // That whole "controlled supply" thing.
    // calculate diff n based on n-2016 ... n-1
    
    // In Litecoin the first epoch recalculates 2015 blocks back
    if height == epochLength {
      _, err = r.Seek(int64(80), os.SEEK_SET)
      if err != nil {
        return 0, err
      }
    } else {
      _, err = r.Seek(int64(offsetHeight - epochLength), os.SEEK_SET)
      if err != nil {
        return 0, err
      }
    }
    
    err = epochStart.Deserialize(r)
    if err != nil {
      return 0, err
    }
    
    rightBits = calcDiffAdjustBitcoin(epochStart, prev, p)
  } else { // not a new epoch
    rightBits = epochStart.Bits
    
    // if on testnet, check for difficulty nerfing
    if p.ReduceMinDifficulty && cur.Timestamp.After(
      prev.Timestamp.Add(p.TargetTimePerBlock*2)) {
      rightBits = p.PowLimitBits // difficulty 1
    }
  }
  
  return rightBits, nil
}

// Uses Kimoto Gravity Well for difficulty adjustment. Used in VTC, MONA etc
func calcDiffAdjustKGW(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  var minBlocks, maxBlocks int32
  minBlocks = 144
  maxBlocks = 4032
  
  if height - 1 < minBlocks {
    return p.PowLimitBits, nil
  }
  
  offsetHeight := height - startheight - 1
  
  var currentBlock wire.BlockHeader
  var err error
  
  // seek to n-1 header
  _, err = r.Seek(int64(80*offsetHeight), os.SEEK_SET)
  if err != nil {
    return 0, err
  }
  // read in n-1
  err = currentBlock.Deserialize(r)
  if err != nil {
    return 0, err
  }
  
  lastSolved := currentBlock
  
  var blocksScanned, actualRate, targetRate int64
  var difficultyAverage, previousDifficultyAverage big.Int
  var rateAdjustmentRatio, eventHorizonDeviation, eventHorizonDeviationFast, eventHorizonDevationSlow float64
  rateAdjustmentRatio = 1
  
  currentHeight := height - 1
  
  var i int32
  
  for i = 1; currentHeight > 0; i++ {
    if i > maxBlocks {
      break
    }
    
    blocksScanned++
    
    if i == 1 {
      difficultyAverage = *difficulty.CompactToBig(currentBlock.Bits)
    } else {
      compact := difficulty.CompactToBig(currentBlock.Bits)
      
      difference  := new(big.Int).Sub(compact, &previousDifficultyAverage)
      difference.Div(difference, big.NewInt(int64(i)))
      difference.Add(difference, &previousDifficultyAverage)
      difficultyAverage = *difference
    }
    
    previousDifficultyAverage = difficultyAverage
    
    actualRate = lastSolved.Timestamp.Unix() - currentBlock.Timestamp.Unix()
    targetRate = int64(p.TargetTimePerBlock.Nanoseconds() / 10^6) * blocksScanned
    rateAdjustmentRatio = 1
    
    if actualRate < 0 {
      actualRate = 0
    }
    
    if actualRate != 0 && targetRate != 0 {
      rateAdjustmentRatio = float64(targetRate) / float64(actualRate)
    }
    
    eventHorizonDeviation = 1 + (0.7084 * math.Pow(float64(blocksScanned)/float64(minBlocks), -1.228))
    eventHorizonDeviationFast = eventHorizonDeviation
    eventHorizonDevationSlow = 1 / eventHorizonDeviation
    
    if blocksScanned >= int64(minBlocks) && (rateAdjustmentRatio <= eventHorizonDevationSlow || rateAdjustmentRatio >= eventHorizonDeviationFast) {
      break
    }
    
    if currentHeight <= 1 {
      break
    }
    
    currentHeight--
    
    _, err = r.Seek(int64(80*(currentHeight - startheight)), os.SEEK_SET)
    if err != nil {
      return 0, err
    }
    // read in n-1
    err = currentBlock.Deserialize(r)
    if err != nil {
      return 0, err
    }
  }
  
  newTarget := difficultyAverage
  if actualRate != 0 && targetRate != 0 {
    newTarget.Mul(&newTarget, big.NewInt(actualRate))
    
    newTarget.Div(&newTarget, big.NewInt(targetRate))
  }
  
  if newTarget.Cmp(p.PowLimit) == 1 {
    newTarget = *p.PowLimit
  }
  
  return difficulty.BigToCompact(&newTarget), nil
}

func VTCTestDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  if height < 2116 {
      return LTCDiff(r, height, startheight, p)
  }
  
  offsetHeight := height - startheight
  
  // Testnet retargets only every 12 blocks
  if height % 12 != 0 {
      var prev wire.BlockHeader
      var err error
  
      // seek to n-1 header
      _, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
      if err != nil {
        return 0, err
      }
      // read in n-1
      err = prev.Deserialize(r)
      if err != nil {
        return 0, err
      }
      
      return prev.Bits, nil
  }
  
  // Run KGW
  return calcDiffAdjustKGW(r, height, startheight, p)
}

func VTCDiff (r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  if height < 26754 {
      return LTCDiff(r, height, startheight, p)
  }
  
  if height == 208301 {
    return 0x1e0ffff0, nil
  }
  
  // Run KGW
  return calcDiffAdjustKGW(r, height, startheight, p)
}

// MainNetParams defines the network parameters for the main Bitcoin network.
var MainNetParams = Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "8333",
	DNSSeeds: []string{
		"seed.bitcoin.sipa.be",
		"dnsseed.bluematt.me",
		"dnsseed.bitcoin.dashjr.org",
		"seed.bitcoinstats.com",
		"seed.bitnodes.io",
		"bitseed.xf2.org",
		"seed.bitcoin.jonasschnelli.ch",
	},

	// Chain parameters
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
  DiffCalcFunction:         BTCDiff,
	PoWFunction:		          func(b []byte, height int32) chainhash.Hash {
                              return chainhash.DoubleHashH(b)
                            },
	PowLimit:                 mainPowLimit,
	PowLimitBits:             0x1d00ffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     0,
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{33333, newHashFromStr("000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
		{74000, newHashFromStr("0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
		{105000, newHashFromStr("00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
		{134444, newHashFromStr("00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
		{168000, newHashFromStr("000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
		{193000, newHashFromStr("000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
		{210000, newHashFromStr("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
		{216116, newHashFromStr("00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
		{225430, newHashFromStr("00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
		{250000, newHashFromStr("000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
		{267300, newHashFromStr("000000000000000a83fbd660e918f218bf37edd92b748ad940483c7c116179ac")},
		{279000, newHashFromStr("0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
		{300255, newHashFromStr("0000000000000000162804527c6e9b9f0563a280525f9d08c12041def0a0f3b2")},
		{319400, newHashFromStr("000000000000000021c6052e9becade189495d1c539aa37c58917305fd15f13b")},
		{343185, newHashFromStr("0000000000000000072b8bf361d01a6ba7d445dd024203fafc78768ed4368554")},
		{352940, newHashFromStr("000000000000000010755df42dba556bb72be6a32f3ce0b6941ce4430152c9ff")},
		{382320, newHashFromStr("00000000000000000a8dc6ed5b133d0eb2fd6af56203e4159789b092defd8ab2")},
	},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// Mempool parameters
	RelayNonStdTxs: false,

	// Address encoding magics
	PubKeyHashAddrID: 0x00, // starts with 1
	ScriptHashAddrID: 0x05, // starts with 3
	PrivateKeyID:     0x80, // starts with 5 (uncompressed) or K (compressed)
	Bech32Prefix:     "bc", // starts with bc1

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,
}

// RegressionNetParams defines the network parameters for the regression test
// Bitcoin network.  Not to be confused with the test Bitcoin network (version
// 3), this network is sometimes simply called "testnet".
var RegressionNetParams = Params{
	Name:        "regtest",
	Net:         wire.TestNet,
	DefaultPort: "18444",
	DNSSeeds:    []string{},

	// Chain parameters
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                              return chainhash.DoubleHashH(b)
                            },
  DiffCalcFunction:         BTCDiff,
	PowLimit:                 regressionPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 150,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 75% (750 / 1000)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 95% (950 / 1000)
	BlockEnforceNumRequired: 750,
	BlockRejectNumRequired:  950,
	BlockUpgradeNumToCheck:  1000,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)
	Bech32Prefix:     "rt",

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 257,
}

// BC2NetParams are the parameters for the BC2 test network.
var BC2NetParams = Params{
	Name:        "bc2",
	Net:         wire.BC2Net,
	DefaultPort: "8444",
	DNSSeeds:    []string{},

	// Chain parameters
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                              return chainhash.DoubleHashH(b)
                            },
  DiffCalcFunction:         BTCDiff,
	GenesisBlock:             &bc2GenesisBlock,
	GenesisHash:              &bc2GenesisHash,
	PowLimit:                 bc2NetPowLimit,
	PowLimitBits:             0x1d7fffff,
	CoinbaseMaturity:         10,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 1,   // 1 hour
	TargetTimePerBlock:       time.Minute * 1, // 1 minute
	RetargetAdjustmentFactor: 4,               // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x19, // starts with B
	ScriptHashAddrID: 0x1c, // starts with ?
	Bech32Prefix:     "bc2",
	PrivateKeyID:     0xef, // starts with 9 7(uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 2,
}

var VertcoinParams = Params{
	Name:        "vtc",
	Net:         wire.VertcoinNet,
	DefaultPort: "5889",
	DNSSeeds: []string{
		"fr1.vtconline.org",
	},

	// Chain parameters
  DiffCalcFunction:         VTCDiff,
	GenesisBlock:             &VertcoinGenesisBlock,
	GenesisHash:              &VertcoinGenesisHash,
	PowLimit:                 liteCoinTestNet4PowLimit,
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                                lyraBytes, _ := lyra2rev2.Sum(b)
                                asChainHash, _ := chainhash.NewHash(lyraBytes)
                                return *asChainHash
                            },
	PowLimitBits:             0x1e0fffff,
	CoinbaseMaturity:         120,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Second * 302400,    // 3.5 weeks
	TargetTimePerBlock:       time.Second * 150, // 150 seconds
	RetargetAdjustmentFactor: 4,                 // 25% less, 400% more
	ReduceMinDifficulty:      false,
	MinDiffReductionTime:     time.Minute * 10, // ?? unknown
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 1512,
	BlockRejectNumRequired:  1915,
	BlockUpgradeNumToCheck:  2016,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID:        0x47, // starts with m or n
	ScriptHashAddrID:        0x05, // starts with 2
	Bech32Prefix:           "vtc",
	PrivateKeyID:            0x80, // starts with 9 7(uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 65537, // i dunno, 0x010001 ?
}

// LiteCoinTestNet4Params are the parameters for the litecoin test network 4.
var VertcoinTestNetParams = Params{
	Name:        "vtctest",
	Net:         wire.VertTestNet,
	DefaultPort: "15889",
	DNSSeeds: []string{
		"fr1.vtconline.org",
	},

	// Chain parameters
  DiffCalcFunction:         VTCTestDiff,
	GenesisBlock:             &VertcoinTestnetGenesisBlock,
	GenesisHash:              &VertcoinTestnetGenesisHash,
	PowLimit:                 liteCoinTestNet4PowLimit,
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                              lyraBytes, _ := lyra2rev2.Sum(b)
                              asChainHash, _ := chainhash.NewHash(lyraBytes)
                              return *asChainHash
                            },
	PowLimitBits:             0x1e0fffff,
	CoinbaseMaturity:         120,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Second * 302400,    // 3.5 weeks
	TargetTimePerBlock:       time.Second * 150, // 150 seconds
	RetargetAdjustmentFactor: 4,                 // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 10, // ?? unknown
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 26,
	BlockRejectNumRequired:  49,
	BlockUpgradeNumToCheck:  50,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID:        0x4a, // starts with m or n
	ScriptHashAddrID:        0xc4, // starts with 2
	Bech32Prefix:           "tvtc",
	PrivateKeyID:            0xef, // starts with 9 7(uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 65537, // i dunno, 0x010001 ?
}

// LiteCoinTestNet4Params are the parameters for the litecoin test network 4.
var LiteCoinTestNet4Params = Params{
	Name:        "litetest4",
	Net:         wire.LiteTest4Net,
	DefaultPort: "19335",
	DNSSeeds: []string{
		"testnet-seed.litecointools.com",
		"seed-b.litecoin.loshan.co.uk",
		"dnsseed-testnet.thrasher.io",
	},

	// Chain parameters
  DiffCalcFunction:         LTCDiff,
	GenesisBlock:             &bc2GenesisBlock, // no it's not
	GenesisHash:              &liteCoinTestNet4GenesisHash,
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                              scryptBytes, _ := scrypt.Key(b, b, 1024, 1, 1, 32)
                              asChainHash, _ := chainhash.NewHash(scryptBytes)
                              return *asChainHash
                            },
	PowLimit:                 liteCoinTestNet4PowLimit,
	PowLimitBits:             0x1e0fffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Second * 302400,    // 3.5 weeks
	TargetTimePerBlock:       time.Second * 150, // 150 seconds
	RetargetAdjustmentFactor: 4,                 // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 10, // ?? unknown
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	Bech32Prefix:     "tltc",
	PrivateKeyID:     0xef, // starts with 9 7(uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 65537, // i dunno, 0x010001 ?
}

// TestNet3Params defines the network parameters for the test Bitcoin network
// (version 3).  Not to be confused with the regression test network, this
// network is sometimes simply called "testnet".
var TestNet3Params = Params{
	Name:        "testnet3",
	Net:         wire.TestNet3,
	DefaultPort: "18333",
	DNSSeeds: []string{
		"testnet-seed.bitcoin.schildbach.de",
		"testnet-seed.bitcoin.petertodd.org",
		"testnet-seed.bluematt.me",
	},

	// Chain parameters
  DiffCalcFunction:         BTCDiff,
	GenesisBlock:             &testNet3GenesisBlock,
	GenesisHash:              &testNet3GenesisHash,
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                              return chainhash.DoubleHashH(b)
                            },
	PowLimit:                 testNet3PowLimit,
	PowLimitBits:             0x1d00ffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
		{546, newHashFromStr("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
	},

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x6f, // starts with m or n
	ScriptHashAddrID: 0xc4, // starts with 2
	Bech32Prefix:     "tb",
	PrivateKeyID:     0xef, // starts with 9 (uncompressed) or c (compressed)

	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with tprv
	HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with tpub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 1,
}

// SimNetParams defines the network parameters for the simulation test Bitcoin
// network.  This network is similar to the normal test network except it is
// intended for private use within a group of individuals doing simulation
// testing.  The functionality is intended to differ in that the only nodes
// which are specifically specified are used to create the network rather than
// following normal discovery rules.  This is important as otherwise it would
// just turn into another public testnet.
var SimNetParams = Params{
	Name:        "simnet",
	Net:         wire.SimNet,
	DefaultPort: "18555",
	DNSSeeds:    []string{}, // NOTE: There must NOT be any seeds.

	// Chain parameters
  DiffCalcFunction:         BTCDiff,
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
	PoWFunction:              func(b []byte, height int32) chainhash.Hash {
                              return chainhash.DoubleHashH(b)
                            },
	PowLimit:                 simNetPowLimit,
	PowLimitBits:             0x207fffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 210000,
	TargetTimespan:           time.Hour * 24 * 14, // 14 days
	TargetTimePerBlock:       time.Minute * 10,    // 10 minutes
	RetargetAdjustmentFactor: 4,                   // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Minute * 20, // TargetTimePerBlock * 2
	GenerateSupported:        true,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: nil,

	// Enforce current block version once majority of the network has
	// upgraded.
	// 51% (51 / 100)
	// Reject previous block versions once a majority of the network has
	// upgraded.
	// 75% (75 / 100)
	BlockEnforceNumRequired: 51,
	BlockRejectNumRequired:  75,
	BlockUpgradeNumToCheck:  100,

	// Mempool parameters
	RelayNonStdTxs: true,

	// Address encoding magics
	PubKeyHashAddrID: 0x3f, // starts with S
	ScriptHashAddrID: 0x7b, // starts with s
	PrivateKeyID:     0x64, // starts with 4 (uncompressed) or F (compressed)
	Bech32Prefix:     "smn",
	// BIP32 hierarchical deterministic extended key magics
	HDPrivateKeyID: [4]byte{0x04, 0x20, 0xb9, 0x00}, // starts with sprv
	HDPublicKeyID:  [4]byte{0x04, 0x20, 0xbd, 0x3a}, // starts with spub

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 115, // ASCII for s
}

var (
	// ErrDuplicateNet describes an error where the parameters for a Bitcoin
	// network could not be set due to the network already being a standard
	// network or previously-registered into this package.
	ErrDuplicateNet = errors.New("duplicate Bitcoin network")

	// ErrUnknownHDKeyID describes an error where the provided id which
	// is intended to identify the network for a hierarchical deterministic
	// private extended key is not registered.
	ErrUnknownHDKeyID = errors.New("unknown hd private extended key bytes")

	// ErrUnknownPrefix describes and error where the provided prefix string
	// isn't found associated with a parameter set / HDCoinType
	ErrUnknownPrefix = errors.New("unknown bech32 prefix")
)

var (
	registeredNets    = make(map[wire.BitcoinNet]struct{})
	bech32Prefixes    = make(map[string]uint32)
	pubKeyHashAddrIDs = make(map[byte]struct{})
	scriptHashAddrIDs = make(map[byte]struct{})
	hdPrivToPubKeyIDs = make(map[[4]byte][]byte)
)

// Register registers the network parameters for a Bitcoin network.  This may
// error with ErrDuplicateNet if the network is already registered (either
// due to a previous Register call, or the network being one of the default
// networks).
//
// Network parameters should be registered into this package by a main package
// as early as possible.  Then, library packages may lookup networks or network
// parameters based on inputs and work regardless of the network being standard
// or not.
func Register(params *Params) error {
	if _, ok := registeredNets[params.Net]; ok {
		return ErrDuplicateNet
	}
	registeredNets[params.Net] = struct{}{}
	bech32Prefixes[params.Bech32Prefix] = params.HDCoinType
	pubKeyHashAddrIDs[params.PubKeyHashAddrID] = struct{}{}
	scriptHashAddrIDs[params.ScriptHashAddrID] = struct{}{}
	hdPrivToPubKeyIDs[params.HDPrivateKeyID] = params.HDPublicKeyID[:]
	return nil
}

// mustRegister performs the same function as Register except it panics if there
// is an error.  This should only be called from package init functions.
func mustRegister(params *Params) {
	if err := Register(params); err != nil {
		panic("failed to register network: " + err.Error())
	}
}

// PrefixToCoinType returns the HDCoinType for a params set given the bech32 prefix.
// If that prefix isn't registered, it returns an error.
func PrefixToCoinType(prefix string) (uint32, error) {
	coinType, ok := bech32Prefixes[prefix]
	if !ok {
		return 0, ErrUnknownPrefix
	}
	return coinType, nil
}

// IsPubKeyHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-pubkey-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsScriptHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsPubKeyHashAddrID(id byte) bool {
	_, ok := pubKeyHashAddrIDs[id]
	return ok
}

// IsScriptHashAddrID returns whether the id is an identifier known to prefix a
// pay-to-script-hash address on any default or registered network.  This is
// used when decoding an address string into a specific address type.  It is up
// to the caller to check both this and IsPubKeyHashAddrID and decide whether an
// address is a pubkey hash address, script hash address, neither, or
// undeterminable (if both return true).
func IsScriptHashAddrID(id byte) bool {
	_, ok := scriptHashAddrIDs[id]
	return ok
}

// HDPrivateKeyToPublicKeyID accepts a private hierarchical deterministic
// extended key id and returns the associated public key id.  When the provided
// id is not registered, the ErrUnknownHDKeyID error will be returned.
func HDPrivateKeyToPublicKeyID(id []byte) ([]byte, error) {
	if len(id) != 4 {
		return nil, ErrUnknownHDKeyID
	}

	var key [4]byte
	copy(key[:], id)
	pubBytes, ok := hdPrivToPubKeyIDs[key]
	if !ok {
		return nil, ErrUnknownHDKeyID
	}

	return pubBytes, nil
}

// newHashFromStr converts the passed big-endian hex string into a
// chainhash.Hash.  It only differs from the one available in chainhash in that
// it panics on an error since it will only (and must only) be called with
// hard-coded, and therefore known good, hashes.
func newHashFromStr(hexStr string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(hexStr)
	if err != nil {
		// Ordinarily I don't like panics in library code since it
		// can take applications down without them having a chance to
		// recover which is extremely annoying, however an exception is
		// being made in this case because the only way this can panic
		// is if there is an error in the hard-coded hashes.  Thus it
		// will only ever potentially panic on init and therefore is
		// 100% predictable.
		panic(err)
	}
	return hash
}

func init() {
	// Register all default networks when the package is initialized.
	mustRegister(&MainNetParams)
	mustRegister(&TestNet3Params)
	mustRegister(&RegressionNetParams)
	mustRegister(&SimNetParams)
	mustRegister(&BC2NetParams)
	mustRegister(&LiteCoinTestNet4Params)
}
