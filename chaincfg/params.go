// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chaincfg

import (
	"errors"
	"math/big"
	"time"
  "io"
  "log"
  "os"
  "math"

	"github.com/adiabat/btcd/chaincfg/chainhash"
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
  
  // The function used to calculate the proof of work value for a block
	PoWFunction func(b []byte) chainhash.Hash
  
  // The function used to calculate the difficulty of a given block
  DiffCalcFunction func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error)

	// GenesisBlock defines the first block of the chain.
	GenesisBlock *wire.MsgBlock

	// GenesisHash is the starting block hash.
	GenesisHash *chainhash.Hash
  
  // The block header to start downloading blocks from
  StartHeader string
  
  // The height of the StartHash
  StartHeight int32
  
  // Assume the difficulty bits are valid before this header height
  // This is needed for coins with variable retarget lookbacks that use 
  // StartHeader to offset the beginning of the header chain for SPV
  AssumeDiffBefore int32

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
	duration := end.Timestamp.Unix() - start.Timestamp.Unix()
	if duration < minRetargetTimespan {
		duration = minRetargetTimespan
	} else if duration > maxRetargetTimespan {
		duration = maxRetargetTimespan
	}

	// calculation of new 32-byte difficulty target
	// first turn the previous target into a big int
	prevTarget := CompactToBig(end.Bits)
	// new target is old * duration...
	newTarget := new(big.Int).Mul(prevTarget, big.NewInt(duration))
	// divided by 2 weeks
	newTarget.Div(newTarget, big.NewInt(int64(p.TargetTimespan.Seconds())))

	// clip again if above minimum target (too easy)
	if newTarget.Cmp(p.PowLimit) > 0 {
		newTarget.Set(p.PowLimit)
	}

	// calculate and return 4-byte 'bits' difficulty from 32-byte target
	return BigToCompact(newTarget)
}

func diffBTC(r io.ReadSeeker, height, startheight int32, p *Params, ltc bool) (uint32, error) {
  epochLength := int32(p.TargetTimespan / p.TargetTimePerBlock)
	var err error
	var cur, prev wire.BlockHeader
  
  offsetHeight := height - startheight
	// seek to n-1 header
	_, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
	if err != nil {
		log.Printf(err.Error())
		return 0, err
	}  
	// read in n-1
	err = prev.Deserialize(r)
	if err != nil {
		log.Printf(err.Error())
		return 0, err
	}
	// seek to curHeight header and read in
	_, err = r.Seek(int64(80*(offsetHeight)), os.SEEK_SET)
	if err != nil {
		log.Printf(err.Error())
		return 0, err
	}
	err = cur.Deserialize(r)
	if err != nil {
		log.Printf(err.Error())
		return 0, err
	}
  
  rightBits := prev.Bits // normal, no adjustment; Dn = Dn-1
	// see if we're on a difficulty adjustment block
	if (height)%epochLength == 0 {
    var epochStart wire.BlockHeader
    if ltc {
      if height == epochLength {
        _, err = r.Seek(int64(80*(offsetHeight-epochLength)), os.SEEK_SET)
      } else {
        _, err = r.Seek(int64(80*(offsetHeight-epochLength-1)), os.SEEK_SET)
      }
    } else {
      _, err = r.Seek(int64(80*(offsetHeight-epochLength)), os.SEEK_SET)
    }
    if err != nil {
      log.Printf(err.Error())
      return 0, err
    }
    err = epochStart.Deserialize(r)
    if err != nil {
      log.Printf(err.Error())
      return 0, err
    }
		// if so, check if difficulty adjustment is valid.
		// That whole "controlled supply" thing.
		// calculate diff n based on n-2016 ... n-1
		rightBits = calcDiffAdjustBitcoin(epochStart, prev, p)
	} else { // not a new epoch
		// if on testnet, check for difficulty nerfing
		if p.ReduceMinDifficulty && cur.Timestamp.After(
			prev.Timestamp.Add(p.TargetTimePerBlock*2)) {
			rightBits = p.PowLimitBits // difficulty 1
		} else {
    
      // Get last non-nerfed header
      curHeight := offsetHeight
      curHeader := prev
      for curHeight % epochLength != 0 && curHeader.Bits == p.PowLimitBits && curHeight >= 0 {
        curHeight--
        _, err = r.Seek(int64(80*curHeight), os.SEEK_SET)
        if err != nil {
          log.Printf(err.Error())
          return 0, err
        }
        err = curHeader.Deserialize(r)
        if err != nil {
          log.Printf(err.Error())
          return 0, err
        }
      }
      
      rightBits = curHeader.Bits
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
      difficultyAverage = *CompactToBig(currentBlock.Bits)
    } else {
      compact := CompactToBig(currentBlock.Bits)
      
      difference  := new(big.Int).Sub(compact, &previousDifficultyAverage)
      difference.Div(difference, big.NewInt(int64(i)))
      difference.Add(difference, &previousDifficultyAverage)
      difficultyAverage = *difference
    }
    
    previousDifficultyAverage = difficultyAverage
    
    actualRate = lastSolved.Timestamp.Unix() - currentBlock.Timestamp.Unix()
    targetRate = int64(p.TargetTimePerBlock.Seconds()) * blocksScanned
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
  
  return BigToCompact(&newTarget), nil
}

func diffVTCtest(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
  if height < 2116 {
      return diffBTC(r, height, startheight, p, true)
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
  PoWFunction:		          chainhash.DoubleHashH,
  DiffCalcFunction:         func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
                              return diffBTC(r, height, startheight, p, false)
                            },
	GenesisBlock:             &genesisBlock,
	GenesisHash:              &genesisHash,
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
		{11111, newHashFromStr("0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
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
  PoWFunction:		          chainhash.DoubleHashH,
  DiffCalcFunction:         func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
                              return diffBTC(r, height, startheight, p, false)
                            },
	GenesisBlock:             &regTestGenesisBlock,
	GenesisHash:              &regTestGenesisHash,
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
  PoWFunction:		          chainhash.DoubleHashH,
  DiffCalcFunction:         func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
                              return diffBTC(r, height, startheight, p, false)
                            },
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
  PoWFunction:              func(b []byte) chainhash.Hash {
                              scryptBytes, _ := scrypt.Key(b, b, 1024, 1, 1, 32)
                              asChainHash, _ := chainhash.NewHash(scryptBytes)
                              return *asChainHash
                            },
  DiffCalcFunction:         func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
                              return diffBTC(r, height, startheight, p, true)
                            },
  StartHeader:              "010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97f60ba158f0ff0f1ee1790400",
  StartHeight:              48384,
  AssumeDiffBefore:         50401,
	GenesisBlock:             &bc2GenesisBlock, // no it's not
	GenesisHash:              &liteCoinTestNet4GenesisHash,
	PowLimit:                 liteCoinTestNet4PowLimit,
	PowLimitBits:             0x1e0fffff,
	CoinbaseMaturity:         100,
	SubsidyReductionInterval: 840000,
	TargetTimespan:           time.Hour * 84,    // 84 hours
	TargetTimePerBlock:       time.Second * 150, // 150 seconds
	RetargetAdjustmentFactor: 4,                 // 25% less, 400% more
	ReduceMinDifficulty:      true,
	MinDiffReductionTime:     time.Second * 150 * 2, // TargetTimePerBlock * 2
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
  PoWFunction:              chainhash.DoubleHashH,
  DiffCalcFunction:         func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
                              return diffBTC(r, height, startheight, p, false)
                            },
  StartHeader:              "00000020da33925b1f7a55e9fa8e6c955a20ea094148b60c5c88f69a4f500000000000003673b7b6ce8157d3cfcaf415b6740918df7610a8769d70334aa9abd9c941b25e7621215880ba371a85bf9646",
  StartHeight:              1032192,
	GenesisBlock:             &testNet3GenesisBlock,
	GenesisHash:              &testNet3GenesisHash,
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

var VertcoinTestNetParams = Params{
	Name:        "vtctest",
	Net:         wire.VertTestNet,
	DefaultPort: "15889",
	DNSSeeds: []string{
		"fr1.vtconline.org",
	},

	// Chain parameters
  DiffCalcFunction:         diffVTCtest,
	GenesisBlock:             &VertcoinTestnetGenesisBlock,
	GenesisHash:              &VertcoinTestnetGenesisHash,
	PowLimit:                 liteCoinTestNet4PowLimit,
	PoWFunction:              func(b []byte) chainhash.Hash {
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
	MinDiffReductionTime:     time.Second * 150 * 2, // ?? unknown
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
	HDCoinType: 65536, // i dunno, 0x010001 ?
}

var VertcoinParams = Params{
	Name:        "vtc",
	Net:         wire.VertcoinNet,
	DefaultPort: "5889",
	DNSSeeds: []string{
		"fr1.vtconline.org",
    "uk1.vtconline.org",
    "useast1.vtconline.org",
    "vtc.alwayshashing.com",
    "crypto.office-on-the.net",
    "p2pool.kosmoplovci.org",
	},

	// Chain parameters
  StartHeader:              "0200000036dc16c771631c52a43db7b0a9869595ed7dc168e72eaf0f550802989f5c7be437a6907666a7ba5575d88ac5140186118e34e24a047b9d6e9641bb29e204cb493c5308583ff44d1b42226e8a",
  StartHeight:              598752,
  AssumeDiffBefore:         602784,
  DiffCalcFunction:         calcDiffAdjustKGW,
	GenesisBlock:             &VertcoinGenesisBlock,
	GenesisHash:              &VertcoinGenesisHash,
	PowLimit:                 liteCoinTestNet4PowLimit,
	PoWFunction:              func(b []byte) chainhash.Hash {
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
	MinDiffReductionTime:     time.Second * 150 * 2, // ?? unknown
	GenerateSupported:        false,

	// Checkpoints ordered from oldest to newest.
	Checkpoints: []Checkpoint{
    {  0,      newHashFromStr("4d96a915f49d40b1e5c2844d1ee2dccb90013a990ccea12c492d22110489f0c4")},
    {  24200,  newHashFromStr("d7ed819858011474c8b0cae4ad0b9bdbb745becc4c386bc22d1220cc5a4d1787")},
    {  65000,  newHashFromStr("9e673a69c35a423f736ab66f9a195d7c42f979847a729c0f3cef2c0b8b9d0289")},
    {  84065,  newHashFromStr("a904170a5a98109b2909379d9bc03ef97a6b44d5dafbc9084b8699b0cba5aa98")},
    {  228023, newHashFromStr("15c94667a9e941359d2ee6527e2876db1b5e7510a5ded3885ca02e7e0f516b51")},
    {  346992, newHashFromStr("f1714fa4c7990f4b3d472eb22132891ccd3c7ad7208e2d1ab15bde68854fb0ee")},
    {  347269, newHashFromStr("fa1e592b7ea2aa97c5f20ccd7c40f3aaaeb31d1232c978847a79f28f83b6c22a")},
    {  430000, newHashFromStr("2f5703cf7b6f956b84fd49948cbf49dc164cfcb5a7b55903b1c4f53bc7851611")},
    {  516999, newHashFromStr("572ed47da461743bcae526542053e7bc532de299345e4f51d77786f2870b7b28")},
	  {  627610, newHashFromStr("6000a787f2d8bb77d4f491a423241a4cc8439d862ca6cec6851aba4c79ccfedc")},
  },

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
	HDCoinType: 28, // i dunno, 0x010001 ?
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
  PoWFunction:              chainhash.DoubleHashH,
  DiffCalcFunction:         func(r io.ReadSeeker, height, startheight int32, p *Params) (uint32, error) {
                              return diffBTC(r, height, startheight, p, false)
                            },
	GenesisBlock:             &simNetGenesisBlock,
	GenesisHash:              &simNetGenesisHash,
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
