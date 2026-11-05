// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/staletiprelayman.h>

#include <chain.h>
#include <util/check.h>

#include <algorithm>
#include <cassert>

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

bool StaleTipRelayManager::ReceivedStaleTip(NodeId peer, const CChain& chain, const CBlockIndex& tip)
{
    AssertLockHeld(::cs_main);
    const auto it{m_peers.find(peer)};
    if (!Assume(it != m_peers.end())) return false;
    auto& from_peer{it->second.m_staletips_from_peer};
    if (std::ranges::find(from_peer, &tip) == from_peer.end()) {
        if (from_peer.size() >= MAX_STALETIPS_FROM_PEER) from_peer.pop_front();
        from_peer.push_back(&tip);
    }
    return m_tracker.AddStaleTip(chain, &tip);
}

std::vector<StaleTipMessage> StaleTipRelayManager::GetStaleTipsToAnnounce(
    NodeId peer, const CChain& chain,
    const PeerHasHeaderFn& peer_has_header,
    const CanServeBranchFn& can_serve_branch)
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
    for (const StaleFork& fork : m_tracker.GetStaleTips(chain)) {
        const CBlockIndex& stale_tip{fork.tip.get()};
        // Don't announce a tip twice.
        if (info.m_staletips_to_peer.contains(&stale_tip)) continue;
        // Don't announce a tip back to the peer that announced it to us.
        if (std::ranges::find(info.m_staletips_from_peer, &stale_tip) != info.m_staletips_from_peer.end()) continue;
        // The compressed payload reconstructs headers from the fork point, so
        // only announce tips whose fork point the peer is known to have.
        if (!peer_has_header(fork.fork_point.get())) continue;
        // Don't announce a tip to a peer that already has it (for example, as
        // its active tip).
        if (peer_has_header(stale_tip)) continue;

        const bool have_block{can_serve_branch(fork)};
        // Signet stale tips can only be validated with the block data, and
        // peers may disconnect for announcements without it. Defer the
        // announcement until the block data can be served.
        if (!have_block && m_opts.chain_type == ChainType::SIGNET) continue;
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

std::vector<StaleFork> StaleTipRelayManager::GetStaleTips(const CChain& chain) const
{
    AssertLockHeld(::cs_main);
    return m_tracker.GetStaleTips(chain);
}

bool StaleTipRelayManager::PrefersBlocks() const
{
    return m_opts.chain_type == ChainType::SIGNET;
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
