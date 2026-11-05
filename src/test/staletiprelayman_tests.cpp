// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <kernel/cs_main.h>
#include <net.h>
#include <node/staletiprelayman.h>
#include <staletips.h>
#include <sync.h>
#include <test/util/blocktree.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <functional>
#include <initializer_list>
#include <optional>
#include <set>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(staletiprelayman_tests, BasicTestingSetup)

namespace {

/** A peer's view of the block tree, as PeerManager reports it to the
 *  StaleTipRelayManager. */
struct TestPeer {
    NodeId id;
    const CBlockIndex* best_known{nullptr};

    bool HasHeader(const CBlockIndex& block) const
    {
        return best_known != nullptr && best_known->GetAncestor(block.nHeight) == &block;
    }
};

std::vector<StaleTipMessage> Announce(node::StaleTipRelayManager& manager, const CChain& chain, const TestPeer& peer,
                                               std::optional<int> max_serve_depth = std::nullopt, bool prefers_blocks = false,
                                               const std::set<uint256>& requested = {}) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    return manager.GetStaleTipsToAnnounce(
        peer.id, chain, prefers_blocks, max_serve_depth,
        [&](const CBlockIndex& block) { return peer.HasHeader(block); },
        [&](const uint256& hash) { return requested.contains(hash); });
}

std::vector<uint256> Tips(const std::vector<StaleTipMessage>& announcements)
{
    std::vector<uint256> tips;
    for (const auto& announcement : announcements) tips.push_back(announcement.DecompressHeaders().back().GetHash());
    return tips;
}

std::vector<uint256> Hashes(std::initializer_list<const CBlockIndex*> blocks)
{
    std::vector<uint256> hashes;
    for (const CBlockIndex* block : blocks) hashes.push_back(block->GetBlockHash());
    return hashes;
}

bool NotRequested(const uint256&) { return false; }

bool AnyBranch(const CBlockIndex&) { return true; }

} // namespace

BOOST_AUTO_TEST_CASE(announcement_policy)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 4; ++i) active = tree.Add(active, true, true);
    CBlockIndex* fork_a{Assert(active->pprev)};
    CBlockIndex* fork_b{Assert(fork_a->pprev)};
    CBlockIndex* tip_a{tree.Add(fork_a, false)};
    CBlockIndex* tip_b{tree.Add(tree.Add(fork_b, false), false)};
    const CChain& chain{tree.active_chain};

    node::StaleTipRelayManager manager{{}};
    const TestPeer source{.id = 0, .best_known = active};
    const TestPeer peer{.id = 1, .best_known = active};
    TestPeer below_fork{.id = 2, .best_known = fork_b};
    const TestPeer has_tip{.id = 3, .best_known = tip_a};
    for (NodeId id{0}; id < 4; ++id) manager.ConnectedPeer(id);

    BOOST_CHECK(manager.ReceivedStaleTip(source.id, chain, *tip_a, /*have_block=*/false));
    BOOST_CHECK(manager.AcceptedStaleTip(chain, *tip_b));
    BOOST_CHECK(!manager.AcceptedStaleTip(chain, *tip_b));

    // Tips are announced in the order they were tracked, but not back to the
    // peer that announced them, and not twice.
    const auto announcements{Announce(manager, chain, peer)};
    BOOST_CHECK(Tips(announcements) == Hashes({tip_a, tip_b}));
    BOOST_CHECK(!announcements.front().m_have_block);
    BOOST_CHECK(announcements.front().m_fork_point == fork_a->GetBlockHash());
    BOOST_CHECK(Tips(Announce(manager, chain, source)) == Hashes({tip_b}));
    BOOST_CHECK(Announce(manager, chain, peer).empty());

    // A tip is only announced to a peer that has its fork point.
    BOOST_CHECK(Tips(Announce(manager, chain, below_fork)) == Hashes({tip_b}));
    below_fork.best_known = active;
    BOOST_CHECK(Tips(Announce(manager, chain, below_fork)) == Hashes({tip_a}));

    // A tip is not announced to a peer that already has it.
    BOOST_CHECK(Tips(Announce(manager, chain, has_tip)) == Hashes({tip_b}));

    // A tip that is reorged onto the active chain and back stays tracked, so
    // it is not announced again.
    tree.active_chain.SetTip(*tip_a);
    BOOST_CHECK(Announce(manager, chain, peer).empty());
    tree.active_chain.SetTip(*active);
    BOOST_CHECK(Announce(manager, chain, peer).empty());

    // Only the last MAX_STALETIPS_FROM_PEER tips a peer announced are
    // remembered, so an older one may be announced back to it.
    for (size_t i{0}; i < node::MAX_STALETIPS_FROM_PEER; ++i) {
        manager.ReceivedStaleTip(source.id, chain, *tree.Add(fork_a, false), /*have_block=*/false);
    }
    BOOST_CHECK(Tips(Announce(manager, chain, source)) == Hashes({tip_a}));

    for (NodeId id{0}; id < 4; ++id) {
        manager.DisconnectedPeer(id);
        manager.CheckIsEmpty(id);
    }
    manager.CheckIsEmpty();
}

BOOST_AUTO_TEST_CASE(evicted_tip_not_readmitted)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 4; ++i) active = tree.Add(active, true, true);
    CBlockIndex* fork{Assert(active->GetAncestor(2))};

    node::StaleTipRelayManager manager{{}};
    const TestPeer peer{.id = 0, .best_known = active};
    manager.ConnectedPeer(peer.id);
    manager.ConnectedPeer(1);

    std::vector<CBlockIndex*> tips;
    for (size_t i{0}; i < MAX_ADVERTISED_STALETIPS; ++i) {
        tips.push_back(tree.Add(fork, false));
        BOOST_CHECK(manager.AcceptedStaleTip(tree.active_chain, *tips.back()));
    }
    BOOST_CHECK_EQUAL(Announce(manager, tree.active_chain, peer).size(), MAX_ADVERTISED_STALETIPS);

    // A higher-work tip evicts the oldest of the equal-work tips.
    CBlockIndex* higher{tree.Add(tree.Add(fork, false), false)};
    BOOST_CHECK(manager.AcceptedStaleTip(tree.active_chain, *higher));
    BOOST_CHECK(Tips(Announce(manager, tree.active_chain, peer)) == Hashes({higher}));

    // Another peer announcing the evicted tip cannot readmit it, so it is not
    // announced again.
    BOOST_CHECK(!manager.ReceivedStaleTip(1, tree.active_chain, *tips.front(), /*have_block=*/false));
    BOOST_CHECK(Announce(manager, tree.active_chain, peer).empty());
}

BOOST_AUTO_TEST_CASE(signet_announces_with_block)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);
    CBlockIndex* tip{tree.Add(Assert(active->pprev), false, true)};

    BOOST_CHECK(!node::StaleTipRelayManager{{}}.PrefersBlocks());
    node::StaleTipRelayManager manager{{.chain_type = ChainType::SIGNET}};
    BOOST_CHECK(manager.PrefersBlocks());
    const TestPeer peer{.id = 0, .best_known = active};
    manager.ConnectedPeer(peer.id);
    BOOST_CHECK(manager.AcceptedStaleTip(tree.active_chain, *tip));

    // A signet tip is only announced once its blocks can be served.
    BOOST_CHECK(Announce(manager, tree.active_chain, peer).empty());
    tip->m_chain_tx_count = 1;
    const auto announcements{Announce(manager, tree.active_chain, peer)};
    BOOST_REQUIRE_EQUAL(announcements.size(), 1U);
    BOOST_CHECK(announcements.front().m_have_block);
    manager.DisconnectedPeer(peer.id);
}

BOOST_AUTO_TEST_CASE(announced_branch_blocks)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 4; ++i) active = tree.Add(active, true, true);
    CBlockIndex* fork{Assert(active->pprev)};
    CBlockIndex* parent{tree.Add(fork, false)};
    CBlockIndex* tip{tree.Add(parent, false)};
    CBlockIndex* other{tree.Add(fork, false)};

    node::StaleTipRelayManager manager{{}};
    manager.ConnectedPeer(0);
    manager.ConnectedPeer(1);

    // Only a branch announced with block data counts.
    manager.ReceivedStaleTip(0, tree.active_chain, *tip, /*have_block=*/false);
    BOOST_CHECK(!manager.IsAnnouncedStaleBranchBlock(0, *tip));
    manager.ReceivedStaleTip(0, tree.active_chain, *tip, /*have_block=*/true);
    BOOST_CHECK(manager.IsAnnouncedStaleBranchBlock(0, *tip));
    BOOST_CHECK(manager.IsAnnouncedStaleBranchBlock(0, *parent));
    BOOST_CHECK(!manager.IsAnnouncedStaleBranchBlock(0, *other));
    BOOST_CHECK(!manager.IsAnnouncedStaleBranchBlock(1, *tip));

    // Announcing the tip again without block data keeps the offer.
    manager.ReceivedStaleTip(0, tree.active_chain, *tip, /*have_block=*/false);
    BOOST_CHECK(manager.IsAnnouncedStaleBranchBlock(0, *tip));

    manager.DisconnectedPeer(0);
    manager.DisconnectedPeer(1);
    BOOST_CHECK(!manager.IsAnnouncedStaleBranchBlock(0, *tip));
}

BOOST_AUTO_TEST_CASE(announces_servable_branches)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 5; ++i) active = tree.Add(active, true, true);
    CBlockIndex* first{tree.Add(active->GetAncestor(2), false, true)};
    CBlockIndex* tip{tree.Add(first, false, true)};

    node::StaleTipRelayManager manager{{}};
    BOOST_CHECK(manager.AcceptedStaleTip(tree.active_chain, *tip));
    NodeId next_id{0};
    const auto have_block{[&](std::optional<int> max_serve_depth) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        const TestPeer peer{.id = next_id++, .best_known = active};
        manager.ConnectedPeer(peer.id);
        const auto announcements{Announce(manager, tree.active_chain, peer, max_serve_depth)};
        BOOST_REQUIRE_EQUAL(announcements.size(), 1U);
        return announcements.front().m_have_block;
    }};

    // The tip's block is not enough: every block on the branch must be
    // available...
    BOOST_CHECK(!have_block(std::nullopt));
    tip->m_chain_tx_count = 1;
    BOOST_CHECK(have_block(std::nullopt));

    // ...and shallow enough to serve to the peer.
    const int first_depth{tree.active_chain.Height() - first->nHeight};
    BOOST_CHECK(have_block(first_depth));
    BOOST_CHECK(!have_block(first_depth - 1));
}

BOOST_AUTO_TEST_CASE(defers_while_downloading)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 3; ++i) active = tree.Add(active, true, true);
    CBlockIndex* tip{tree.Add(Assert(active->pprev), false)};
    const std::set<uint256> requested{tip->GetBlockHash()};

    node::StaleTipRelayManager headers_mode{{}};
    node::StaleTipRelayManager blocks_mode{{.fetch_blocks = true}};
    BOOST_CHECK(blocks_mode.PrefersBlocks());
    for (auto* manager : {&headers_mode, &blocks_mode}) {
        for (NodeId id{0}; id < 3; ++id) manager->ConnectedPeer(id);
        BOOST_CHECK(manager->AcceptedStaleTip(tree.active_chain, *tip));
    }

    // In blocks mode, a peer that prefers blocks waits while the tip's block
    // is being downloaded.
    const TestPeer prefers{.id = 0, .best_known = active};
    BOOST_CHECK(Announce(blocks_mode, tree.active_chain, prefers, std::nullopt, /*prefers_blocks=*/true, requested).empty());
    BOOST_CHECK_EQUAL(Announce(blocks_mode, tree.active_chain, prefers, std::nullopt, /*prefers_blocks=*/true).size(), 1U);

    // Other peers don't wait, nor does any peer in headers mode, nor once the
    // block can be served.
    const TestPeer indifferent{.id = 1, .best_known = active};
    BOOST_CHECK_EQUAL(Announce(blocks_mode, tree.active_chain, indifferent, std::nullopt, /*prefers_blocks=*/false, requested).size(), 1U);
    BOOST_CHECK_EQUAL(Announce(headers_mode, tree.active_chain, prefers, std::nullopt, /*prefers_blocks=*/true, requested).size(), 1U);
    tip->nStatus |= BLOCK_HAVE_DATA;
    tip->m_chain_tx_count = 1;
    const TestPeer served{.id = 2, .best_known = active};
    const auto announcements{Announce(blocks_mode, tree.active_chain, served, std::nullopt, /*prefers_blocks=*/true, requested)};
    BOOST_REQUIRE_EQUAL(announcements.size(), 1U);
    BOOST_CHECK(announcements.front().m_have_block);
}

BOOST_AUTO_TEST_CASE(branch_requests)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 12; ++i) active = tree.Add(active, true, true);
    std::vector<CBlockIndex*> branch{tree.Add(active->GetAncestor(2), false)};
    while (branch.size() < 10) branch.push_back(tree.Add(branch.back(), false));
    const CBlockIndex& tip{*branch.back()};
    const CChain& chain{tree.active_chain};
    const auto range{[&](size_t begin, size_t end) { return std::vector<const CBlockIndex*>(branch.begin() + begin, branch.begin() + end); }};

    node::StaleTipRelayManager manager{{.fetch_blocks = true}};
    manager.ConnectedPeer(0);
    const auto request{[&](size_t in_flight, const std::function<bool(const uint256&)>& is_requested) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return manager.GetBlocksToRequest(0, chain, in_flight, is_requested, AnyBranch);
    }};
    const size_t cap{node::MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS};

    // Only branches offered with block data are requested.
    manager.ReceivedStaleTip(0, chain, tip, /*have_block=*/false);
    BOOST_CHECK(request(0, NotRequested).empty());
    manager.ReceivedStaleTip(0, chain, tip, /*have_block=*/true);

    // Parents first, up to the in-flight cap, which counts blocks already in
    // flight from the peer.
    BOOST_CHECK(request(0, NotRequested) == range(0, cap));
    BOOST_CHECK(request(cap - 3, NotRequested) == range(0, 3));
    BOOST_CHECK(request(cap, NotRequested).empty());

    // Blocks we have, or that are in flight from any peer, are skipped.
    branch[0]->nStatus |= BLOCK_HAVE_DATA;
    const auto requested{[&](const uint256& hash) { return hash == branch[1]->GetBlockHash(); }};
    BOOST_CHECK(request(0, requested) == range(2, 2 + cap));

    // Nothing is requested in headers mode, or for an ineligible tip, here one
    // on the active chain.
    node::StaleTipRelayManager headers_mode{{}};
    headers_mode.ConnectedPeer(0);
    headers_mode.ReceivedStaleTip(0, chain, tip, /*have_block=*/true);
    BOOST_CHECK(headers_mode.GetBlocksToRequest(0, chain, 0, NotRequested, AnyBranch).empty());
    node::StaleTipRelayManager active_offer{{.fetch_blocks = true}};
    active_offer.ConnectedPeer(0);
    active_offer.ReceivedStaleTip(0, chain, *active, /*have_block=*/true);
    BOOST_CHECK(active_offer.GetBlocksToRequest(0, chain, 0, NotRequested, AnyBranch).empty());
}

BOOST_AUTO_TEST_CASE(requests_across_offers)
{
    LOCK(::cs_main);

    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, true, true)};
    for (int i{0}; i < 5; ++i) active = tree.Add(active, true, true);
    CBlockIndex* shared{tree.Add(active->GetAncestor(2), false)};
    CBlockIndex* tip_a{tree.Add(shared, false)};
    CBlockIndex* tip_b{tree.Add(shared, false)};
    const CChain& chain{tree.active_chain};
    using Blocks = std::vector<const CBlockIndex*>;

    node::StaleTipRelayManager manager{{.fetch_blocks = true}};
    manager.ConnectedPeer(0);
    manager.ReceivedStaleTip(0, chain, *tip_a, /*have_block=*/true);
    manager.ReceivedStaleTip(0, chain, *tip_b, /*have_block=*/true);

    // Oldest offer first, and blocks the branches share only once.
    BOOST_CHECK(manager.GetBlocksToRequest(0, chain, 0, NotRequested, AnyBranch) == Blocks({shared, tip_a, tip_b}));

    // The in-flight cap applies across branches.
    BOOST_CHECK(manager.GetBlocksToRequest(0, chain, node::MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS - 2, NotRequested, AnyBranch) == Blocks({shared, tip_a}));

    // Branches the peer cannot serve are skipped.
    BOOST_CHECK(manager.GetBlocksToRequest(0, chain, 0, NotRequested, [&](const CBlockIndex& tip) { return &tip != tip_a; }) == Blocks({shared, tip_b}));

    // Nothing is requested from an unknown peer.
    BOOST_CHECK(manager.GetBlocksToRequest(1, chain, 0, NotRequested, AnyBranch).empty());
}

BOOST_AUTO_TEST_SUITE_END()
