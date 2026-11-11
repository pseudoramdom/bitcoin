// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/staletiprelayman.h>

#include <chain.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>
#include <ranges>

namespace node {

StaleTipRelayManager::StaleTipRelayManager(const StaleTipRelayOptions& opts)
    : m_opts{opts}, m_tracker{opts.chain_type}
{
}

void StaleTipRelayManager::Initialize(BlockManager& blockman, const CChain& chain)
{
    AssertLockHeld(::cs_main);
    m_tracker.Initialize(blockman, chain);
}

bool StaleTipRelayManager::BlockDisconnected(const CChain& chain, const CBlockIndex& block)
{
    AssertLockHeld(::cs_main);
    return m_tracker.AddStaleTip(chain, &block);
}

bool StaleTipRelayManager::AcceptedStaleTip(const CChain& chain, const CBlockIndex& tip)
{
    AssertLockHeld(::cs_main);
    return m_tracker.AddStaleTip(chain, &tip);
}

void StaleTipRelayManager::ConnectedPeer(NodeId peer)
{
    AssertLockHeld(::cs_main);
    const bool inserted{m_peers.try_emplace(peer).second};
    Assume(inserted);
}

void StaleTipRelayManager::DisconnectedPeer(NodeId peer)
{
    AssertLockHeld(::cs_main);
    m_peers.erase(peer);
}

bool StaleTipRelayManager::ReceivedStaleTip(NodeId peer, const CChain& chain, const CBlockIndex& tip, bool have_block)
{
    AssertLockHeld(::cs_main);
    const auto it{m_peers.find(peer)};
    if (!Assume(it != m_peers.end())) return false;
    auto& from_peer{it->second.m_staletips_from_peer};
    if (auto announced{std::ranges::find(from_peer, &tip, &StaleTipAnnouncement::tip)}; announced != from_peer.end()) {
        announced->have_block |= have_block;
        if (have_block) announced->block_fetch_timed_out = false;
    } else {
        if (from_peer.size() >= MAX_STALETIPS_FROM_PEER) from_peer.pop_front();
        from_peer.push_back({.tip = &tip, .have_block = have_block});
    }
    return m_tracker.AddStaleTip(chain, &tip);
}

bool StaleTipRelayManager::IsAnnouncedStaleBranchBlock(NodeId peer, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    const auto it{m_peers.find(peer)};
    if (it == m_peers.end()) return false;
    return std::ranges::any_of(it->second.m_staletips_from_peer, [&](const StaleTipAnnouncement& announced) {
        return announced.have_block && announced.tip->GetAncestor(block.nHeight) == &block;
    });
}

std::vector<StaleTipMessage> StaleTipRelayManager::GetStaleTipsToAnnounce(
    NodeId peer, const CChain& chain, bool peer_prefers_blocks, std::optional<int> max_serve_depth,
    const PeerHasHeaderFn& peer_has_header,
    const IsRequestedFn& is_requested)
{
    AssertLockHeld(::cs_main);
    const auto it{m_peers.find(peer)};
    if (!Assume(it != m_peers.end())) return {};
    PeerInfo& info{it->second};
    if (m_tracker.Empty()) {
        info.m_staletips_to_peer.clear();
        return {};
    }

    std::vector<StaleTipMessage> announcements;
    const bool want_blocks{m_opts.fetch_blocks && peer_prefers_blocks};
    for (const StaleFork& fork : m_tracker.GetStaleTips(chain)) {
        const CBlockIndex& stale_tip{fork.tip.get()};
        // Don't announce a tip twice.
        if (info.m_staletips_to_peer.contains(&stale_tip)) continue;
        // Don't announce a tip back to the peer that announced it to us.
        if (std::ranges::find(info.m_staletips_from_peer, &stale_tip, &StaleTipAnnouncement::tip) != info.m_staletips_from_peer.end()) continue;
        // The compressed payload reconstructs headers from the fork point, so
        // only announce tips whose fork point the peer is known to have.
        if (!peer_has_header(fork.fork_point.get())) continue;
        // Don't announce a tip to a peer that already has it (for example, as
        // its active tip).
        if (peer_has_header(stale_tip)) continue;

        // The peer fetches the branch from the fork point, so every block on it
        // must be available and shallow enough to serve. Branch blocks may be
        // downloaded out of order, so the tip having data is not enough. A
        // tracked branch may be served whatever its age (see
        // CanServeStaleBranchBlock()).
        const CBlockIndex& first_branch_block{*stale_tip.GetAncestor(fork.fork_point.get().nHeight + 1)};
        const bool have_block{(stale_tip.nStatus & BLOCK_HAVE_DATA) != 0 && stale_tip.HaveNumChainTxs() &&
                              (!max_serve_depth || chain.Height() - first_branch_block.nHeight <= *max_serve_depth)};
        // Signet stale tips can only be validated with the block data, and
        // peers may disconnect for announcements without it. Defer the
        // announcement until the block data can be served.
        if (!have_block && m_opts.chain_type == ChainType::SIGNET) continue;
        // A peer that prefers block data waits while we are downloading the
        // tip's block. If nothing is downloading it, there is nothing to wait
        // for.
        if (want_blocks && !have_block && is_requested(stale_tip.GetBlockHash())) continue;
        info.m_staletips_to_peer.insert(&stale_tip);
        announcements.emplace_back(fork, have_block);
    }
    // Forget tips only once they are dropped from the tracker. Tips that are
    // merely ineligible at the moment (for example, reorged onto the active
    // chain) are kept, so they are not re-announced to the same peer if they
    // become eligible again.
    std::erase_if(info.m_staletips_to_peer, [&](const CBlockIndex* tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) { return !m_tracker.IsTracked(tip); });
    return announcements;
}

void StaleTipRelayManager::AddStaleBranchBlocksToRequest(const CChain& chain, const CBlockIndex& tip, size_t in_flight,
                                                         const IsRequestedFn& is_requested,
                                                         std::vector<const CBlockIndex*>& blocks) const
{
    AssertLockHeld(::cs_main);
    if (in_flight + blocks.size() >= MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS) return;
    // Each branch is downloaded at most once. This stays true after the
    // branch's blocks are pruned, so they are not downloaded again.
    if (tip.HaveNumChainTxs()) return;
    if (!m_tracker.CanRequestStaleTipBlock(chain, &tip)) return;

    std::vector<const CBlockIndex*> missing_blocks;
    for (const CBlockIndex* block{&tip}; block != nullptr && !chain.Contains(*block); block = block->pprev) {
        if (block->nStatus & BLOCK_HAVE_DATA) continue;
        if (is_requested(block->GetBlockHash())) continue;
        // Branches may share blocks.
        if (std::ranges::find(blocks, block) != blocks.end()) continue;
        missing_blocks.push_back(block);
    }

    for (const CBlockIndex* block : missing_blocks | std::views::reverse) {
        if (in_flight + blocks.size() >= MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS) break;
        blocks.push_back(block);
    }
}

std::vector<const CBlockIndex*> StaleTipRelayManager::GetBlocksToRequest(
    NodeId peer, const CChain& chain, size_t in_flight,
    const IsRequestedFn& is_requested,
    const CanFetchBranchFn& can_fetch_branch) const
{
    AssertLockHeld(::cs_main);
    std::vector<const CBlockIndex*> blocks;
    if (!m_opts.fetch_blocks) return blocks;
    const auto it{m_peers.find(peer)};
    if (it == m_peers.end()) return blocks;
    for (const StaleTipAnnouncement& announced : it->second.m_staletips_from_peer) {
        if (in_flight + blocks.size() >= MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS) break;
        if (!announced.have_block || announced.block_fetch_timed_out) continue;
        if (!can_fetch_branch(*announced.tip)) continue;
        AddStaleBranchBlocksToRequest(chain, *announced.tip, in_flight, is_requested, blocks);
    }
    return blocks;
}

void StaleTipRelayManager::BlockFetchTimedOut(NodeId peer, std::span<const CBlockIndex* const> cleared)
{
    AssertLockHeld(::cs_main);
    const auto it{m_peers.find(peer)};
    if (it == m_peers.end()) return;
    for (StaleTipAnnouncement& announced : it->second.m_staletips_from_peer) {
        if (std::ranges::any_of(cleared, [&](const CBlockIndex* block) { return announced.tip->GetAncestor(block->nHeight) == block; })) {
            announced.block_fetch_timed_out = true;
        }
    }
}

bool StaleTipRelayManager::CanServeStaleBranchBlock(const CChain& chain, const CBlockIndex& block) const
{
    AssertLockHeld(::cs_main);
    return m_tracker.CanServeStaleBranchBlock(chain, &block);
}

std::vector<StaleFork> StaleTipRelayManager::GetStaleTips(const CChain& chain) const
{
    AssertLockHeld(::cs_main);
    return m_tracker.GetStaleTips(chain);
}

bool StaleTipRelayManager::PrefersBlocks() const
{
    return m_opts.fetch_blocks || m_opts.chain_type == ChainType::SIGNET;
}

void StaleTipRelayManager::CheckIsEmpty() const
{
    AssertLockHeld(::cs_main);
    assert(m_peers.empty());
}

void StaleTipRelayManager::CheckIsEmpty(NodeId peer) const
{
    AssertLockHeld(::cs_main);
    assert(!m_peers.contains(peer));
}

} // namespace node
