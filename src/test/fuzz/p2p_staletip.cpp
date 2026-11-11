// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addrman.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <deploymentstatus.h>
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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <ios>
#include <map>
#include <memory>
#include <optional>
#include <set>
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

//! A block or, without transactions, a header built by the fuzzer.
struct BuiltBlock {
    CBlock block;
    int height;
};

//! A stale tip a peer announced to us, as net_processing records it.
struct StaleTipAnnouncement {
    uint256 tip;
    bool have_block;
};

//! Matches MAX_STALETIPS_FROM_PEER in net_processing.cpp.
constexpr size_t MAX_STALETIPS_FROM_PEER{2 * MAX_ADVERTISED_STALETIPS};

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
//! If its coinbase overpays, it passes the checks on receipt and is only found
//! invalid when connected.
std::shared_ptr<CBlock> ConsumeBlock(FuzzedDataProvider& fuzzed_data_provider, const CBlockHeader& prev, int height)
{
    CMutableTransaction coinbase;
    coinbase.vin = {CTxIn{COutPoint{}, CScript{} << height << fuzzed_data_provider.ConsumeIntegral<int64_t>()}};
    const CAmount overpay{fuzzed_data_provider.ConsumeBool() ? 1 : 0};
    coinbase.vout = {CTxOut{GetBlockSubsidy(height, Params().GetConsensus()) + overpay, P2WSH_OP_TRUE}};

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

    const auto stale_tip_mode{fuzzed_data_provider.ConsumeBool() ? StaleTipMode::BLOCKS : StaleTipMode::HEADERS};
    node.addrman.reset();
    node.peerman.reset();
    node.addrman = std::make_unique<AddrMan>(*node.netgroupman, /*deterministic=*/true, /*consistency_check_ratio=*/0);
    node.peerman = PeerManager::make(connman, *node.addrman,
                                     /*banman=*/nullptr, chainman,
                                     *node.mempool, *node.warnings,
                                     PeerManager::Options{
                                         .stale_tip_mode = stale_tip_mode,
                                         .deterministic_rng = true,
                                     });
    connman.SetMsgProc(node.peerman.get());
    connman.SetAddrman(*node.addrman);
    node.validation_signals->RegisterValidationInterface(node.peerman.get());

    // The peer whose messages we are processing, or who we are sending to.
    const CNode* current_peer{nullptr};
    // Tips each peer announced with have_block set.
    std::map<NodeId, std::vector<uint256>> announced_with_block;
    // Blocks we sent in reply to the last getdata.
    std::vector<uint256> served;
    // Peers that negotiated stale-tip relay.
    std::set<NodeId> negotiated;
    // Stale tips each peer announced that we recorded, oldest first, like
    // Peer::m_stale_tips_from_peer.
    std::map<NodeId, std::deque<StaleTipAnnouncement>> recorded_from_peer;
    // Tips we announced while processing a staletip, which are only checked
    // once the tip it announced is recorded.
    std::optional<std::vector<uint256>> announced_while_recording;
    const auto check_not_echoed{[&](NodeId id, const uint256& tip_hash) {
        Assert(std::ranges::find(recorded_from_peer[id], tip_hash, &StaleTipAnnouncement::tip) == recorded_from_peer[id].end());
    }};

    // Check what we send. MaybeSendStaleTips() and the block download logic
    // hold cs_main while they push, so the block index can't change
    // underneath. Blocks are served without cs_main, so they are checked
    // after the getdata that asked for them.
    connman.SetCaptureMessages(true);
    const auto capture_message_orig{CaptureMessage};
    CaptureMessage = [&](const CAddress&, const std::string& msg_type, std::span<const unsigned char> data, bool is_incoming) NO_THREAD_SAFETY_ANALYSIS {
        if (is_incoming) return;
        SpanReader reader{data};
        if (msg_type == NetMsgType::FEATURE) {
            std::string feature_id;
            std::vector<uint8_t> feature_data;
            reader >> feature_id >> feature_data;
            if (feature_id == NetMsgFeature::STALETIP) Assert(feature_data == std::vector<uint8_t>{stale_tip_mode == StaleTipMode::BLOCKS});
        } else if (msg_type == NetMsgType::BLOCK || msg_type == NetMsgType::CMPCTBLOCK) {
            CBlockHeader header;
            reader >> header;
            served.push_back(header.GetHash());
        } else if (msg_type == NetMsgType::GETDATA) {
            // Blocks are only requested towards a chain with at least as much
            // work as the active tip, or in blocks mode, on a branch the peer
            // announced with its block data.
            AssertLockHeld(cs_main);
            std::vector<CInv> invs;
            reader >> invs;
            const CBlockIndex* active_tip{chainman.ActiveTip()};
            for (const CInv& inv : invs) {
                if (!inv.IsGenBlkMsg()) continue;
                const CBlockIndex* block{Assert(chainman.m_blockman.LookupBlockIndex(inv.hash))};
                const auto on_branch{[&](const CBlockIndex& tip) { return tip.GetAncestor(block->nHeight) == block; }};
                const bool towards_enough_work{std::ranges::any_of(chainman.BlockIndex(), [&](const auto& entry) {
                    return entry.second.nChainWork >= active_tip->nChainWork && on_branch(entry.second);
                })};
                const bool on_announced_branch{stale_tip_mode == StaleTipMode::BLOCKS &&
                                               std::ranges::any_of(announced_with_block[Assert(current_peer)->GetId()], [&](const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
                                                   const CBlockIndex* tip{chainman.m_blockman.LookupBlockIndex(hash)};
                                                   return tip != nullptr && on_branch(*tip);
                                               })};
                Assert(towards_enough_work || on_announced_branch);
            }
        } else if (msg_type == NetMsgType::STALETIP) {
            AssertLockHeld(cs_main);
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
            // Only to peers that negotiated stale-tip relay, outside IBD, and
            // never back to a peer that announced the tip to us.
            const NodeId id{Assert(current_peer)->GetId()};
            Assert(negotiated.contains(id));
            Assert(!chainman.IsInitialBlockDownload());
            if (announced_while_recording) {
                announced_while_recording->push_back(decompressed.tip_hash);
            } else {
                check_not_echoed(id, decompressed.tip_hash);
            }
        }
    };

    LOCK(NetEventsInterface::g_msgproc_mutex);

    constexpr std::array CONNECTION_TYPES{
        ConnectionType::INBOUND,
        ConnectionType::OUTBOUND_FULL_RELAY,
        ConnectionType::BLOCK_RELAY,
        ConnectionType::MANUAL,
    };
    constexpr std::array LOCAL_SERVICES{
        ServiceFlags(NODE_NETWORK | NODE_WITNESS),
        ServiceFlags(NODE_NETWORK_LIMITED | NODE_WITNESS),
    };
    std::vector<CNode*> peers;
    const int num_peers{fuzzed_data_provider.ConsumeIntegralInRange(1, 3)};
    for (NodeId id{0}; id < num_peers; ++id) {
        CAddress addr{};
        peers.push_back(new CNode{id, /*sock=*/nullptr, addr, /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0, addr, /*addrNameIn=*/"",
                                  PickValue(fuzzed_data_provider, CONNECTION_TYPES), /*inbound_onion=*/false, /*network_key=*/0});
        CNode& peer{*peers.back()};
        current_peer = &peer;
        const int32_t version{fuzzed_data_provider.ConsumeBool() ? PROTOCOL_VERSION : fuzzed_data_provider.ConsumeIntegralInRange<int32_t>(MIN_PEER_PROTO_VERSION, PROTOCOL_VERSION)};
        connman.Handshake(peer,
                          /*successfully_connected=*/false,
                          ConsumeWeakEnum(fuzzed_data_provider, ALL_SERVICE_FLAGS),
                          PickValue(fuzzed_data_provider, LOCAL_SERVICES),
                          version,
                          /*relay_txs=*/true);
        connman.AddTestNode(peer);
        if (fuzzed_data_provider.ConsumeBool()) {
            const std::vector<uint8_t> feature_data{fuzzed_data_provider.ConsumeBool() ?
                                                        std::vector<uint8_t>{fuzzed_data_provider.ConsumeBool()} :
                                                        ConsumeRandomLengthByteVector(fuzzed_data_provider, 2)};
            SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::FEATURE, NetMsgFeature::STALETIP, feature_data));
            if (version >= FEATURE_VERSION && feature_data.size() == 1 && feature_data[0] <= 1) negotiated.insert(id);
        }
        SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::VERACK));
    }

    // Headers and blocks built during this run, whether or not they were
    // accepted, so later messages can build on them. Headers have no
    // transactions.
    std::vector<BuiltBlock> built;
    const auto pick_parent{[&]() -> BuiltBlock {
        if (!built.empty() && fuzzed_data_provider.ConsumeBool()) return PickValue(fuzzed_data_provider, built);
        LOCK(cs_main);
        const CChain& active_chain{chainman.ActiveChain()};
        const CBlockIndex& block{*active_chain[fuzzed_data_provider.ConsumeIntegralInRange(0, active_chain.Height())]};
        return {.block = CBlock{block.GetBlockHeader()}, .height = block.nHeight};
    }};

    // Send a staletip from `peer`. Like HandleStaleTip(), record its tip if
    // we process the message, it is well formed, and the tip ends up in the
    // block index and not invalid.
    const auto send_stale_tip{[&](CNode& peer, std::vector<uint8_t> payload) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        const bool processed{negotiated.contains(peer.GetId()) && peer.fSuccessfullyConnected && !peer.fDisconnect};
        CSerializedNetMsg msg;
        msg.m_type = NetMsgType::STALETIP;
        msg.data = payload;
        announced_while_recording.emplace();
        SendMessage(connman, *node.peerman, peer, std::move(msg));
        const std::vector<uint256> announced{std::move(*announced_while_recording)};
        announced_while_recording.reset();

        StaleTipMessage stale_tip;
        bool well_formed{false};
        try {
            SpanReader reader{payload};
            reader >> stale_tip;
            well_formed = reader.empty();
        } catch (const std::ios_base::failure&) {
        }
        if (processed && well_formed) {
            LOCK(cs_main);
            const CBlockIndex* tip{chainman.m_blockman.LookupBlockIndex(stale_tip.DecompressHeaders().tip_hash)};
            if (tip != nullptr && tip->IsValid(BLOCK_VALID_TREE)) {
                auto& recorded{recorded_from_peer[peer.GetId()]};
                if (auto it{std::ranges::find(recorded, tip->GetBlockHash(), &StaleTipAnnouncement::tip)}; it != recorded.end()) {
                    it->have_block |= stale_tip.m_have_block;
                } else {
                    if (recorded.size() >= MAX_STALETIPS_FROM_PEER) recorded.pop_front();
                    recorded.push_back({.tip = tip->GetBlockHash(), .have_block = stale_tip.m_have_block});
                }
            }
        }
        for (const uint256& tip_hash : announced) check_not_echoed(peer.GetId(), tip_hash);
    }};

    // Peers that delivered a block they may be punished for.
    std::set<NodeId> may_be_punished;
    // Deliver a block from `peer`.
    const auto deliver_block{[&](CNode& peer, const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(NetEventsInterface::g_msgproc_mutex) {
        // Let anything already due disconnect the peer first, so a
        // disconnect below is caused by this block.
        connman.FlushSendBuffer(peer);
        node.peerman->SendMessages(peer);
        const bool was_connected{!peer.fDisconnect};
        // Like IsAnnouncedStaleBranchBlock(): the block is on a branch
        // the peer announced with its block data. Mutated blocks are
        // still punished.
        const bool exempt{[&] {
            LOCK(cs_main);
            const CBlockIndex* index{chainman.m_blockman.LookupBlockIndex(block.GetHash())};
            if (index == nullptr || IsBlockMutated(block, DeploymentActiveAfter(index->pprev, chainman, Consensus::DEPLOYMENT_SEGWIT))) return false;
            return std::ranges::any_of(recorded_from_peer[peer.GetId()], [&](const StaleTipAnnouncement& announced) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
                return announced.have_block && Assert(chainman.m_blockman.LookupBlockIndex(announced.tip))->GetAncestor(index->nHeight) == index;
            });
        }()};
        if (!exempt) may_be_punished.insert(peer.GetId());
        SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::BLOCK, TX_WITH_WITNESS(block)));
        // A peer is not punished for an invalid block on a branch it
        // announced with its block data, as it may not have connected
        // the block. Connecting it may also connect blocks the peer
        // delivered earlier, which are only covered if they were
        // exempt too.
        if (exempt && was_connected && !may_be_punished.contains(peer.GetId())) Assert(!peer.fDisconnect);
    }};

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 100)
    {
        if (fuzzed_data_provider.ConsumeBool() && chainman.IsInitialBlockDownload()) chainman.JumpOutOfIbd();
        CNode& peer{*PickValue(fuzzed_data_provider, peers)};
        current_peer = &peer;
        CallOneOf(
            fuzzed_data_provider,
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Announce a branch forking from a block on or off the active
                // chain, or from a header we don't know. The branch is made of
                // blocks, which the peer can deliver later, or of headers.
                BuiltBlock prev{pick_parent()};
                std::vector<CBlock> branch;
                StaleTipMessage stale_tip;
                stale_tip.m_fork_point = prev.block.GetHash();
                const auto num_headers{fuzzed_data_provider.ConsumeIntegralInRange<size_t>(1, MAX_STALETIP_HEADERS)};
                for (size_t i{0}; i < num_headers; ++i) {
                    const bool full_block{prev.block.nBits == Params().GenesisBlock().nBits && fuzzed_data_provider.ConsumeBool()};
                    prev = {.block = full_block ? *ConsumeBlock(fuzzed_data_provider, prev.block, prev.height + 1) : CBlock{ConsumeHeader(fuzzed_data_provider, prev.block)},
                            .height = prev.height + 1};
                    built.push_back(prev);
                    branch.push_back(prev.block);
                    stale_tip.m_headers.push_back({.version = prev.block.nVersion, .merkle_root = prev.block.hashMerkleRoot, .time = prev.block.nTime, .bits = prev.block.nBits, .nonce = prev.block.nNonce});
                }
                stale_tip.m_have_block = fuzzed_data_provider.ConsumeBool();
                if (stale_tip.m_have_block) announced_with_block[peer.GetId()].push_back(prev.block.GetHash());
                send_stale_tip(peer, NetMsg::Make(NetMsgType::STALETIP, stale_tip).data);
                // Serve the branch right away, as an honest peer that has it
                // would once we ask.
                if (stale_tip.m_have_block && fuzzed_data_provider.ConsumeBool()) {
                    for (const CBlock& block : branch) deliver_block(peer, block);
                }
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                const std::vector<uint8_t> payload{ConsumeRandomLengthByteVector(fuzzed_data_provider)};
                try {
                    SpanReader reader{payload};
                    StaleTipMessage stale_tip;
                    reader >> stale_tip;
                    if (stale_tip.m_have_block) announced_with_block[peer.GetId()].push_back(stale_tip.DecompressHeaders().tip_hash);
                } catch (const std::ios_base::failure&) {
                }
                send_stale_tip(peer, payload);
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Tell us which headers the peer has, which decides what we
                // announce to it.
                std::vector<CBlock> headers{pick_parent().block};
                headers.front().vtx.clear();
                SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::HEADERS, TX_WITH_WITNESS(headers)));
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Deliver a block we built, which may be one we requested. A
                // header without transactions is a mutated block.
                if (built.empty()) return;
                deliver_block(peer, PickValue(fuzzed_data_provider, built).block);
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Ask for a block, which we only serve off the active chain if
                // we validated it or it is on a stale branch we track.
                constexpr std::array BLOCK_INV_TYPES{MSG_BLOCK, MSG_WITNESS_BLOCK, MSG_CMPCT_BLOCK};
                const uint256 hash{pick_parent().block.GetHash()};
                served.clear();
                SendMessage(connman, *node.peerman, peer, NetMsg::Make(NetMsgType::GETDATA, std::vector<CInv>{CInv{PickValue(fuzzed_data_provider, BLOCK_INV_TYPES), hash}}));
                const auto relayable{*Assert(node.peerman->GetRelayableStaleTips())};
                LOCK(cs_main);
                const CChain& active_chain{chainman.ActiveChain()};
                for (const uint256& served_hash : served) {
                    const CBlockIndex* block{Assert(chainman.m_blockman.LookupBlockIndex(served_hash))};
                    if (active_chain.Contains(*block) || block->IsValid(BLOCK_VALID_SCRIPTS)) continue;
                    Assert(negotiated.contains(peer.GetId()));
                    Assert(std::ranges::any_of(relayable, [&](const uint256& tip_hash) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
                        const CBlockIndex* tip{chainman.m_blockman.LookupBlockIndex(tip_hash)};
                        return (tip->nStatus & BLOCK_HAVE_DATA) && block->nHeight > active_chain.FindFork(*tip)->nHeight &&
                               tip->GetAncestor(block->nHeight) == block;
                    }));
                }
            },
            [&]() NO_THREAD_SAFETY_ANALYSIS {
                // Mine a block, which can extend the active chain, reorg to a
                // stale branch, or give a stale tip its block data.
                const BuiltBlock prev{pick_parent()};
                if (prev.block.nBits != Params().GenesisBlock().nBits) return;
                const CBlockIndex* prev_index{WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(prev.block.GetHash()))};
                if (prev_index == nullptr) return;
                const auto block{ConsumeBlock(fuzzed_data_provider, prev.block, prev_index->nHeight + 1)};
                built.push_back({.block = *block, .height = prev_index->nHeight + 1});
                (void)chainman.ProcessNewBlock(block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/nullptr);
            },
            [&] {
                node_clock += std::chrono::seconds{fuzzed_data_provider.ConsumeIntegralInRange<int64_t>(0, 60 * 60)};
            });
        // Like the message handler, give every peer a chance to receive what
        // the last step caused us to announce or request.
        for (CNode* p : peers) {
            current_peer = p;
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
