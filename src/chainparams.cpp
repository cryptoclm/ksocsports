// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libzerocoin/Params.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include <assert.h>
#include <boost/assign/list_of.hpp>
#include <limits>
#include "chainparamsseeds.h"

std::string CDNSSeedData::getHost(uint64_t requiredServiceBits) const {
    //use default host for non-filter-capable seeds or if we use the default service bits (NODE_NETWORK)
    if (!supportsServiceBitsFiltering || requiredServiceBits == NODE_NETWORK)
        return host;

    return strprintf("x%x.%s", requiredServiceBits, host);
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    //printf("genesis = %s\n", genesis.ToString().c_str());
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=1776d4804936840d61dda3ebb5d069bf9f9614dc88ee7da1826e330afec120e5, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000,
 * hashMerkleRoot=3a7112c2e43c7e59f5ada92631770b6c8e2bd1dfcde8670eaf9169dc321049f7, nTime=1539704377, nBits=1e0ffff0, nNonce=57612, vtx=1)
 * CTransaction(hash=3a7112c2e4, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *   CTxIn(COutPoint(0000000000000000000000000000000000000000000000000000000000000000, 4294967295),
 * coinbase 04ffff001d01044c514e592054696d65732031302f4f63742f3230313820487572726963616e65204d69636861656c204c69766520557064617465733a2053746f726d20557067726164656420746f2043617465676f72792033)
 *  CTxOut(nValue=0.00000000, scriptPubKey=04ab8dbce32c7daa6ff8a7d43794de)
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "NY Times 10/Oct/2018 Hurricane Michael Live Updates: Storm Upgraded to Category 3";
    const CScript genesisOutputScript = CScript() << ParseHex("04ab8dbce32c7daa6ff8a7d43794de3402a4e4f8909140d9d687624db0899ccc532c86b2310a9c10ac35fc3c7fdd5e7d5997928c7dfdebc568039790f6c141c0e8") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0, uint256("00000cd060c1a502ca5d2cc40a399d18d05b8f9836cd9831e4237e87a6a8ed6a"))
    (500, uint256S("7c53d16e6307923395ecccc4c9a80b508b9741368508c4cd2cca1ecc15a4f3c8"))
    (1000, uint256S("fe2d2c754aa6f913fa0a423edb85ba158cb37c1dd3c69a8be203e9a7ae54f1ac"))
    (5000, uint256S("64a1a14799fd2b273b692f5b658105f5796e3e1077eebca388c1dd68b63e5dfb"))
    (10000, uint256S("b689067d2efb791cedb85b9590572e1138ff05dcafb1677ef5e0a1f4759f767a"))
    (15000, uint256S("03ca25d201d71b9a2bfa43111331c48a390752b4c86be4e6372763ad1ddea88a"))
    (20000, uint256S("451180ed1fb008cda20fb1f894a89af90e6f2ed26e6dc7b1290bb896533e2dcd"));


static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1625016810, // * UNIX timestamp of last checkpoint block
    43812,        // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    2000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256S("1776d4804936840d61dda3ebb5d069bf9f9614dc88ee7da1826e330afec120e5"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1539704377,
    100,
    2000};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256S("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1454124731,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";

        genesis = CreateGenesisBlock(1539704377, 1591358, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("00000cd060c1a502ca5d2cc40a399d18d05b8f9836cd9831e4237e87a6a8ed6a"));
        assert(genesis.hashMerkleRoot == uint256("3a7112c2e43c7e59f5ada92631770b6c8e2bd1dfcde8670eaf9169dc321049f7"));
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // KICKSOCCER starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 20;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 43200;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 10;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 2;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 1000000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 60;
        consensus.nStakeMinDepth = 6;
        consensus.nTargetTimespan = 2 * 60;
        consensus.nTargetTimespanV2 = 2 * 60;
        consensus.nTargetSpacing = 2 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "KNTPdJ1yFDpqmY4dM5Gs8sg9kp5QMAwXBu";
	consensus.strDevFeeAddress = "KQYptvmcUGoxcdtZpwtB8RrSCe7x2sqtgs";
	consensus.strDevFeeAddress1 = "KF3aHMg1FDZ8Embg4vNzJ9uMYd99fh3vhc";

        // spork keys
        consensus.strSporkPubKey = "043e75dc3d44e52f40d4b4823807bfeedd5a8d07140d43a7278bef1b432a3f1b25eff51244106f010cf36671226ec124b9467cae8c38b624b11e11f477c11f4526";

        // height-based activations
        consensus.height_last_PoW = 150;
        consensus.height_RHF = 250;
        consensus.height_last_ZC_AccumCheckpoint = 150;
        consensus.height_start_BIP65 = consensus.height_RHF;             // 82629b7a9978f5c7ea3f70a12db92633a7d2e436711500db28b97efd48b1e527
        consensus.height_start_MessSignaturesV2 = consensus.height_RHF;  // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 1;
        consensus.height_start_StakeModifierV2 = consensus.height_RHF;
        consensus.height_start_TimeProtoV2 = consensus.height_RHF;       // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_ZC = 0;
        consensus.height_start_ZC_PublicSpends = consensus.height_RHF;
        consensus.height_start_ZC_SerialRangeCheck = consensus.height_RHF;
        consensus.height_start_ZC_SerialsV2 = consensus.height_RHF;

        // Zerocoin-related params
        consensus.ZC_Modulus = "d59f1d99dae2770f40fb82066b6f69bb0b3783113505ecf4d958a6021d7204a8612d7c824741ac69cbf426ba4056a0598f2683c54a72c9162821864da23add323b9af365c63d1c60af802a15c3961c4a23a0a4b8f8d0cd681faf9ff5f308a9d8348993a7f5e2560bdc4274aaa670878562ad8774c7fa15ec449385a7e3f2621b152e1f9978890cf02058d3f00d7ed1fc2fba76fe2b8358205dec3f0bd0b648b995f84b74e34ae77a2c134033075cf966b4339f028e039ce8200e279bd0169cf5994a4b135699280fa7be8f0328cfcaa1f7dc7cabe18ba0ec6f42e00792b3f128ec64fee8eb9306b871f6514946649d3fa2247c62ecd5050914570bb35b035fa80ef0995006790eb5ef2e383e7919b7e1aea89f59917c1a7adfdb1a73239c09e191cdde217c53ba0bf96ac9c265054aef811da8b51b1b3ea31d96f5d1ab9acf87363be80f42acf7353b3c4a5297eb3f5676f04b987a3144c5b04d1f6f3fdec243bab3fa2f463a1c50be50b49c156c421befad74c9b6f4367149163d3796355331";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
	consensus.ZC_TimeStart = 1547096400;        // October 17, 2017 4:30:00 AM

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbd;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd8;
        nDefaultPort = 20555;

        // Note that of those with the service bits flag, most only support a subset of possible options
        //vSeeds.push_back(CDNSSeedData("ksoc-network.com", "seeds.ksoc-network.com"));
        //vSeeds.push_back(CDNSSeedData("kicksoccercoin.com", "seeds.ksoc.kicksoccercoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 45);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 107);
	base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 107);     // starting with 'k'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 212);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        // base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x03)(0xbe).convert_to_container<std::vector<unsigned char> >();
        nExtCoinType = 958;

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
	consensus.fAllowMultiplePorts = false;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

	genesis = CreateGenesisBlock(1539704377, 57612, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("1776d4804936840d61dda3ebb5d069bf9f9614dc88ee7da1826e330afec120e5"));
        assert(genesis.hashMerkleRoot == uint256("3a7112c2e43c7e59f5ada92631770b6c8e2bd1dfcde8670eaf9169dc321049f7"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // KICKSOCCER starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 20;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on testnet)
        consensus.nCoinbaseMaturity = 15;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 1000000000 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 60;
        consensus.nStakeMinDepth = 6;
        consensus.nTargetTimespan = 1 * 60;
        consensus.nTargetTimespanV2 = 1 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "xzctEamdG1LveaMEsoV4WWFjSHeg7g3nBE";
	consensus.strDevFeeAddress = "yB1mVG3y3V5fjkBTQAjPYR2siL3oLETzPJ";
	consensus.strDevFeeAddress1 = "y21gusHYTNfCZnmteAqyZTZ2hi1hDDFMyc";

        // spork keys
        consensus.strSporkPubKey = "0427a26d2003ef77437c6287041e81812687077dbbb4a2243229756b926ae49fb1c858f7a671d081f51755cd6d53ed8540b90a25984165d939d701666ecd95995b";

        // height-based activations
        consensus.height_last_PoW = 100;
        consensus.height_RHF = 150;
        consensus.height_last_ZC_AccumCheckpoint = 100;
        consensus.height_start_BIP65 = consensus.height_RHF;             // 82629b7a9978f5c7ea3f70a12db92633a7d2e436711500db28b97efd48b1e527
        consensus.height_start_MessSignaturesV2 = consensus.height_RHF;  // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_StakeModifierNewSelection = 1;
        consensus.height_start_StakeModifierV2 = consensus.height_RHF;
        consensus.height_start_TimeProtoV2 = consensus.height_RHF;       // TimeProtocolV2, Blocks V7 and newMessageSignatures
        consensus.height_start_ZC = 0;
        consensus.height_start_ZC_PublicSpends = consensus.height_RHF;
        consensus.height_start_ZC_SerialRangeCheck = consensus.height_RHF;
        consensus.height_start_ZC_SerialsV2 = consensus.height_RHF;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1501776000;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x10;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x06;
        nDefaultPort = 21555;
        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 139); // Testnet ksoc addresses start with 'x' or 'y'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 19);  // Testnet ksoc script addresses start with '8' or '9'
	base58Prefixes[STAKING_ADDRESS] = std::vector<unsigned char>(1, 77); // starting with 'X' or 'Y'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet ksoc BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet ksoc BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        nExtCoinType = 1;

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
	consensus.fAllowMultiplePorts = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";


        genesis = CreateGenesisBlock(1539704377, 57612, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256("1776d4804936840d61dda3ebb5d069bf9f9614dc88ee7da1826e330afec120e5"));
        assert(genesis.hashMerkleRoot == uint256("3a7112c2e43c7e59f5ada92631770b6c8e2bd1dfcde8670eaf9169dc321049f7"));

        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.powLimit   = ~UINT256_ZERO >> 20;   // KICKSOCCER starting difficulty is 1 / 2^12
        consensus.posLimitV1 = ~UINT256_ZERO >> 20;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 144;         // approx 10 cycles per day
        consensus.nBudgetFeeConfirmations = 3;      // (only 8-blocks window for finalization on regtest)
        consensus.nCoinbaseMaturity = 100;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 4;        // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 43199500 * COIN;
        consensus.nPoolMaxTransactions = 2;
        consensus.nProposalEstablishmentTime = 60 * 5;  // at least 5 min old to make it into a budget
        consensus.nStakeMinAge = 0;
        consensus.nStakeMinDepth = 2;
        consensus.nTargetTimespan = 40 * 60;
        consensus.nTargetTimespanV2 = 30 * 60;
        consensus.nTargetSpacing = 1 * 60;
        consensus.nTimeSlotLength = 15;
        consensus.strObfuscationPoolDummyAddress = "xzctEamdG1LveaMEsoV4WWFjSHeg7g3nBE";

        // spork keys
        consensus.strSporkPubKey = "0427a26d2003ef77437c6287041e81812687077dbbb4a2243229756b926ae49fb1c858f7a671d081f51755cd6d53ed8540b90a25984165d939d701666ecd95995b";

        // height based activations
        consensus.height_last_PoW = 250;
        consensus.height_last_ZC_AccumCheckpoint = 310;     // no checkpoints on regtest
        consensus.height_start_BIP65 = 851019;              // Not defined for regtest. Inherit TestNet value.
        consensus.height_start_MessSignaturesV2 = 1;
        consensus.height_start_StakeModifierNewSelection = 0;
        consensus.height_start_StakeModifierV2 = 251;       // start with modifier V2 on regtest
        consensus.height_start_TimeProtoV2 = 999999999;
        consensus.height_start_ZC = 300;
        consensus.height_start_ZC_PublicSpends = 400;
        consensus.height_start_ZC_SerialRangeCheck = 300;
        consensus.height_start_ZC_SerialsV2 = 300;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 10;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 10;
        consensus.ZC_TimeStart = 0;                 // not implemented on regtest

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 22555;

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
	consensus.fAllowMultiplePorts = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
