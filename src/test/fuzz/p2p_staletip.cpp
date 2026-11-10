// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/merkle.h>
#include <net.h>
#include <net_processing.h>
#include <node/block_template_manager.h>
#include <node/protocol_version.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <staletips.h>
#include <streams.h>
#include <sync.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/script.h>
#include <test/util/setup_common.h>
#include <test/util/time.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>
#include <validationinterface.h>
#include <versionbits.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {
//! Long enough for stale branches of up to MAX_STALETIP_HEADERS blocks that
//! have less work than the active tip.
constexpr size_t ACTIVE_CHAIN_LENGTH{2 * MAX_STALETIP_HEADERS};

TestingSetup* g_setup;
std::vector<std::shared_ptr<CBlock>> g_chain;

//! Replace the chainman with one whose active chain is g_chain.
void ResetChain()
{
    auto& node{g_setup->m_node};
    node.peerman.reset();
    node.block_template_manager.reset();
    node.chainman.reset();
    g_setup->m_make_chainman();
    g_setup->LoadVerifyActivateChainstate();
    g_setup->CreateBlockTemplateManager();
    for (const auto& block : g_chain) {
        Assert(node.chainman->ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/nullptr));
    }
    Assert(WITH_LOCK(cs_main, return node.chainman->ActiveHeight()) == ACTIVE_CHAIN_LENGTH);
}

void initialize()
{
    static const auto testing_setup{MakeNoLogFileContext<TestingSetup>(ChainType::REGTEST)};
    g_setup = testing_setup.get();
    g_chain = CreateBlockChain(ACTIVE_CHAIN_LENGTH, Params());
    const FakeNodeClock clock{std::chrono::seconds{g_chain.back()->nTime}};
    ResetChain();
}

//! Deliver a message from `node` and process it, along with anything it causes
//! us to send.
void SendMessage(ConnmanTestMsg& connman, PeerManager& peerman, CNode& node, CSerializedNetMsg&& msg)
    EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex)
{
    connman.FlushSendBuffer(node);
    (void)connman.ReceiveMsgFrom(node, std::move(msg));
    bool more_work{true};
    while (more_work) {
        node.fPauseSend = false;
        try {
            more_work = connman.ProcessMessagesOnce(node);
        } catch (const std::ios_base::failure&) {
        }
        peerman.SendMessages(node);
    }
}

//! A header building on `prev`, with valid proof of work unless the fuzzer
//! picks a different difficulty.
CBlockHeader ConsumeHeader(FuzzedDataProvider& fuzzed_data_provider, const CBlockHeader& prev)
{
    CBlockHeader header;
    header.hashPrevBlock = prev.GetHash();
    header.nVersion = fuzzed_data_provider.ConsumeBool() ? VERSIONBITS_TOP_BITS : fuzzed_data_provider.ConsumeIntegral<int32_t>();
    header.hashMerkleRoot = ConsumeUInt256(fuzzed_data_provider);
    header.nTime = static_cast<uint32_t>(int64_t{prev.nTime} + fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(-60 * 60, 3 * 60 * 60));
    header.nBits = fuzzed_data_provider.ConsumeBool() ? prev.nBits : fuzzed_data_provider.ConsumeIntegral<uint32_t>();
    header.nNonce = 0;
    // Only the regtest difficulty is cheap enough to solve.
    if (header.nBits == Params().GenesisBlock().nBits) {
        while (!CheckProofOfWork(header.GetHash(), header.nBits, Params().GetConsensus())) ++header.nNonce;
    }
    return header;
}

//! A coinbase-only block building on `prev`, which is at height `height - 1`.
std::shared_ptr<CBlock> ConsumeBlock(FuzzedDataProvider& fuzzed_data_provider, const CBlockHeader& prev, int height)
{
    CMutableTransaction coinbase;
    coinbase.vin = {CTxIn{COutPoint{}, CScript{} << height << fuzzed_data_provider.ConsumeIntegral<int64_t>()}};
    coinbase.vout = {CTxOut{GetBlockSubsidy(height, Params().GetConsensus()), P2WSH_OP_TRUE}};

    auto block{std::make_shared<CBlock>()};
    block->vtx = {MakeTransactionRef(std::move(coinbase))};
    block->nVersion = VERSIONBITS_TOP_BITS;
    block->hashPrevBlock = prev.GetHash();
    block->hashMerkleRoot = BlockMerkleRoot(*block);
    block->nTime = prev.nTime + fuzzed_data_provider.ConsumeIntegralInRange<uint32_t>(1, 60 * 60);
    block->nBits = prev.nBits;
    while (!CheckProofOfWork(block->GetHash(), block->nBits, Params().GetConsensus())) ++block->nNonce;
    return block;
}
} // namespace

FUZZ_TARGET(p2p_staletip, .init = initialize)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fuzzed_data_provider{buffer.data(), buffer.size()};

    auto& node{g_setup->m_node};
    auto& connman{static_cast<ConnmanTestMsg&>(*node.connman)};
    connman.Reset();
    auto& chainman{static_cast<TestChainstateManager&>(*node.chainman)};
    const auto initial_block_index_size{WITH_LOCK(cs_main, return chainman.BlockIndex().size())};
    FakeNodeClock node_clock{std::chrono::seconds{g_chain.back()->nTime + fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 24 * 60 * 60)}};
    FakeSteadyClock steady_clock;
    chainman.ResetIbd();
    chainman.DisableNextWrite();

    node.addrman.reset();
    node.peerman.reset();
    node.addrman = std::make_unique<AddrMan>(*node.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0);
    node.peerman = PeerManager::make(connman, *node.addrman,
                                     /*banman=*/nullptr, chainman,
                                     *node.mempool, *node.warnings,
                                     PeerManager::Options{
                                         .stale_tip_mode = StaleTipMode::HEADERS,
                                         .deterministic_rng = true,
                                     });
    connman.SetMsgProc(node.peerman.get());
    connman.SetAddrman(*node.addrman);
    node.validation_signals->RegisterValidationInterface(node.peerman.get());

    // Check every staletip we send. MaybeSendStaleTips() holds cs_main while
    // it pushes them, so the block index can't change underneath.
    connman.SetCaptureMessages(true);
    const auto capture_message_orig{CaptureMessage};
    CaptureMessage = [&](const CAddress&, const std::string& msg_type, std::span<const unsigned char> data, bool is_incoming) NO_THREAD_SAFETY_ANALYSIS {
        if (is_incoming || msg_type != NetMsgType::STALETIP) return;
        AssertLockHeld(cs_main);
        SpanReader reader{data};
        StaleTipMessage stale_tip;
        reader >> stale_tip;
        Assert(reader.empty());
        const auto decompressed{stale_tip.DecompressHeaders()};
        const CBlockIndex* tip{Assert(chainman.m_blockman.LookupBlockIndex(decompressed.tip_hash))};
        const CChain& active_chain{chainman.ActiveChain()};
        const CBlockIndex* fork_point{Assert(active_chain.FindFork(*tip))};
        Assert(!active_chain.Contains(*tip));
        Assert(fork_point->GetBlockHash() == stale_tip.m_fork_point);
        Assert(static_cast<size_t>(tip->nHeight - fork_point->nHeight) == decompressed.headers.size());
        Assert(tip->nChainWork <= active_chain.Tip()->nChainWork);
        Assert(!stale_tip.m_have_block || (tip->nStatus & BLOCK_HAVE_DATA));
    };

    LOCK(NetEventsInterface::g_msgproc_mutex);

    constexpr std::array CONNECTION_TYPES{
        ConnectionType::INBOUND,
        ConnectionType::OUTBOUND_FULL_RELAY,
        ConnectionType::BLOCK_RELAY,
        ConnectionType::MANUAL,
    };
    std::vector<CNode*> peers;
    const int num_peers{fuzzed_data_provider.ConsumeIntegralInRange(1, 3)};
    for (NodeId id{0}; id < num_peers; ++id) {
        CAddress addr{};
        peers.push_back(new CNode{id, /*sock=*/nullptr, addr, /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0, addr, /*addrNameIn=*/"",
                                  PickValue(fuzzed_data_provider, CONNECTION_TYPES), /*inbound_onion=*/false, /*network_key=*/0});
        CNode& peer{*peers.back()};
        connman.Handshake(peer,
                          /*successfully_connected=*/false,
                          ConsumeWeakEnum(fuzzed_data_provider, ALL_SERVICE_FLAGS),
                          ServiceFlags(NODE_NETWORK | NODE_WITNESS),
                          fuzzed_data_provider.ConsumeBool() ? PROTOCOL_VERSION : fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION),
                          /*relay_txs=*/true);
        connman.AddTestNode(peer);
        if (fuzzed_data_provider.ConsumeBool()) {
            const std::vector<uint8_t> feature_data{fuzzed_data_provider.ConsumeBool() ?
                                                        std::vector<uint8_t>{fuzzed_data_provider.ConsumeBool()} :
                                                        ConsumeRandomLengthByteVector(fuzzed_data_provider, 2)};
            SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::FEATURE, NetMsgFeature::STALETIP, feature_data));
        }
        SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::VERACK));
    }

    // Headers and blocks built during this run, whether or not they were
    // accepted, so later messages can build on them.
    std::vector<CBlockHeader> built;
    const auto pick_parent{[&]() -> CBlockHeader {
        if (!built.empty() && fuzzed_data_provider.ConsumeBool()) return PickValue(fuzzed_data_provider, built);
        LOCK(cs_main);
        const CChain& active_chain{chainman.ActiveChain()};
        return active_chain[fuzzed_data_provider.ConsumeIntegralInRange(0, active_chain.Height())]->GetBlockHeader();
    }};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100)
    {
        if (fuzzed_data_provider.ConsumeBool() && chainman.IsInitialBlockDownload()) chainman.JumpOutOfIbd();
        CNode& peer{*PickValue(fuzzed_data_provider, peers)};
        CallOneOf(
            fuzzed_data_provider,
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Announce a branch forking from a block on or off the active
                // chain, or from a header we don't know.
                CBlockHeader prev{pick_parent()};
                StaleTipMessage stale_tip;
                stale_tip.m_fork_point = prev.GetHash();
                const auto num_headers{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, MAX_STALETIP_HEADERS)};
                for (size_t i{0}; i < num_headers; ++i) {
                    prev = ConsumeHeader(fuzzed_data_provider, prev);
                    built.push_back(prev);
                    stale_tip.m_headers.push_back({.version = prev.nVersion, .merkle_root = prev.hashMerkleRoot, .time = prev.nTime, .bits = prev.nBits, .nonce = prev.nNonce});
                }
                stale_tip.m_have_block = fuzzed_data_provider.ConsumeBool();
                SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::STALETIP, stale_tip));
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                CSerializedNetMsg msg;
                msg.m_type = NetMsgType::STALETIP;
                msg.data = ConsumeRandomLengthByteVector(fuzzed_data_provider);
                SendMessage(connman, *node.peerman, peer, std::move(msg));
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Tell us which headers the peer has, which decides what we
                // announce to it.
                std::vector<CBlock> headers{CBlock{pick_parent()}};
                SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers)));
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Mine a block, which can extend the active chain, reorg to a
                // stale branch, or give a stale tip its block data.
                const CBlockHeader prev{pick_parent()};
                if (prev.nBits != Params().GenesisBlock().nBits) return;
                const CBlockIndex* prev_index{WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(prev.GetHash()))};
                if (prev_index == nullptr) return;
                const auto block{ConsumeBlock(fuzzed_data_provider, prev, prev_index->nHeight + 1)};
                built.push_back(*block);
                (void)chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/nullptr);
            },
            [&] {
                node_clock += std::chrono::seconds{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 60 * 60)};
            });
        // Like the message handler, give every peer a chance to receive what
        // the last step caused us to announce.
        for (CNode* p : peers) {
            connman.FlushSendBuffer(*p);
            node.peerman->SendMessages(*p);
        }
    }

    CaptureMessage = capture_message_orig;
    connman.SetCaptureMessages(false);
    node.validation_signals->SyncWithValidationInterfaceQueue();
    node.validation_signals->UnregisterValidationInterface(node.peerman.get());
    connman.StopNodes();
    if (WITH_LOCK(cs_main, return chainman.BlockIndex().size()) != initial_block_index_size) ResetChain();
}
