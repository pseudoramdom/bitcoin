// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/staletiprelayman.h>

namespace node {

StaleTipAnnouncementResult CheckStaleTipAnnouncement(const CBlockIndex& fork_point, size_t num_headers, const arith_uint256& claimed_work,
                                                     const CBlockIndex* active_tip, const arith_uint256& work_threshold,
                                                     int recent_window)
{
    if (active_tip != nullptr && fork_point.nHeight + static_cast<int>(num_headers) < active_tip->nHeight - recent_window) {
        return StaleTipAnnouncementResult::OUTSIDE_RECENT_WINDOW;
    }
    if (fork_point.nChainWork + claimed_work < work_threshold) return StaleTipAnnouncementResult::LOW_WORK;
    return StaleTipAnnouncementResult::OK;
}

StaleTipRelayManager::StaleTipRelayManager(const StaleTipRelayOptions& opts)
    : m_opts{opts}, m_tracker{opts.chain_type}
{
}

void StaleTipRelayManager::Initialize(BlockManager& blockman, const CChain& chain)
{
    AssertLockHeld(::cs_main);
    m_tracker.SeedFromBlockIndex(blockman, chain);
}

bool StaleTipRelayManager::BlockDisconnected(const CChain& chain, const CBlockIndex& block)
{
    AssertLockHeld(::cs_main);
    return m_tracker.AddStaleTip(chain, block);
}

bool StaleTipRelayManager::AcceptedStaleTip(const CChain& chain, const CBlockIndex& tip)
{
    AssertLockHeld(::cs_main);
    return m_tracker.AddStaleTip(chain, tip);
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

} // namespace node
