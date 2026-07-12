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
#include <initializer_list>
#include <optional>
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
                                               std::optional<int> max_serve_depth = std::nullopt) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    return manager.GetStaleTipsToAnnounce(
        peer.id, chain, max_serve_depth,
        [&](const CBlockIndex& block) { return peer.HasHeader(block); });
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

BOOST_AUTO_TEST_SUITE_END()
