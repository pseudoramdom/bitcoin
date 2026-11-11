// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_STALETIPRELAYMAN_H
#define BITCOIN_NODE_STALETIPRELAYMAN_H

#include <kernel/cs_main.h>
#include <net.h>
#include <staletips.h>
#include <sync.h>
#include <util/chaintype.h>

#include <cstddef>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

class CBlockIndex;
class CChain;
class uint256;

namespace node {
class BlockManager;

/** Maximum number of stale tips announced by a peer that are remembered, so
 *  they are not announced back to it. Leaves room for a peer's
 *  MAX_ADVERTISED_STALETIPS previously known tips plus new ones. */
inline constexpr size_t MAX_STALETIPS_FROM_PEER{2 * MAX_ADVERTISED_STALETIPS};
/** Best-effort stale-branch blocks are only requested from a peer while fewer
 *  than this many blocks are in flight from it, so they leave room for blocks
 *  the active chain needs. Half of MAX_BLOCKS_IN_TRANSIT_PER_PEER. */
inline constexpr size_t MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS{8};

struct StaleTipRelayOptions {
    ChainType chain_type{ChainType::MAIN};
    //! Whether to download stale-branch blocks (-staletips=blocks).
    bool fetch_blocks{false};
};

/**
 * Decides which stale tips to track, announce and fetch for BIP 332 stale-tip
 * relay. Owns the StaleTipTracker and, per peer, the stale tips the peer
 * announced to us and the ones we announced to it.
 *
 * It decides but does not act: PeerManager parses and validates `staletip`
 * messages, sends them, and owns block requests, timeouts and serving.
 * Block-download state stays in PeerManager and is passed in as values, or as
 * callbacks that are only used during the call.
 *
 * Caller needs to interact with StaleTipRelayManager:
 * - ValidationInterface callbacks.
 * - When a peer connects or disconnects.
 * - When a peer announces a stale tip.
 * - When a best-effort block request times out.
 * - To get the stale tips to announce and the stale-branch blocks to request.
 *
 * This class is not thread-safe. Callers must hold cs_main.
 */
class StaleTipRelayManager
{
public:
    using PeerHasHeaderFn = std::function<bool(const CBlockIndex&)>;
    using IsRequestedFn = std::function<bool(const uint256&)>;
    using CanFetchBranchFn = std::function<bool(const CBlockIndex&)>;

    explicit StaleTipRelayManager(const StaleTipRelayOptions& opts);

    /** Seed the tracker with the eligible stale tips in the block index. */
    void Initialize(BlockManager& blockman, const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    // Responses to chain events. StaleTipRelayManager is not an actual client
    // of ValidationInterface, these are called through PeerManager.
    /** @return Whether a new stale tip is tracked, so it should be relayed. */
    bool BlockDisconnected(const CChain& chain, const CBlockIndex& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** @return Whether a new stale tip is tracked, so it should be relayed. */
    bool AcceptedStaleTip(const CChain& chain, const CBlockIndex& tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    void ConnectedPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    void DisconnectedPeer(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Remember a stale tip `peer` announced, and track it if it is eligible.
     *  The peer's offer of the branch's blocks is kept once made, and making it
     *  again clears a fetch timeout (see BlockFetchTimedOut()).
     *
     * @return Whether a new stale tip is tracked, so it should be relayed.
     */
    bool ReceivedStaleTip(NodeId peer, const CChain& chain, const CBlockIndex& tip, bool have_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Whether `block` is on a stale branch `peer` announced with have_block
     *  set, so the peer may serve the branch's blocks without having connected
     *  them. */
    bool IsAnnouncedStaleBranchBlock(NodeId peer, const CBlockIndex& block) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Build the `staletip` messages to send to `peer` now, for tracked stale
     *  tips in the order they were tracked, and remember the tips as
     *  announced.
     *
     * A tip is not announced twice, nor back to a peer that announced it to
     * us, nor to a peer that lacks its fork point or already has the tip.
     *
     * @param[in] peer_prefers_blocks Whether the peer asked for announcements
     *                                once we can serve the blocks.
     * @param[in] max_serve_depth     How far below our active tip we serve
     *                                blocks to the peer, if limited.
     * @param[in] peer_has_header     Whether the peer is known to have a header.
     * @param[in] is_requested        Whether a block is in flight from any peer.
     */
    std::vector<StaleTipMessage> GetStaleTipsToAnnounce(
        NodeId peer, const CChain& chain, bool peer_prefers_blocks, std::optional<int> max_serve_depth,
        const PeerHasHeaderFn& peer_has_header,
        const IsRequestedFn& is_requested) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Choose the missing blocks to request from `peer` on the stale branches
     *  it offered to serve, oldest offer first and parents first, without
     *  reaching MAX_IN_TRANSIT_FOR_STALE_BRANCH_REQUESTS blocks in flight from
     *  it. Offers whose requests timed out are skipped.
     *
     * @param[in] in_flight        Number of blocks in flight from the peer.
     * @param[in] is_requested     Whether a block is in flight from any peer.
     * @param[in] can_fetch_branch Whether the peer can serve the blocks of the
     *                             stale branch ending at a tip.
     */
    std::vector<const CBlockIndex*> GetBlocksToRequest(
        NodeId peer, const CChain& chain, size_t in_flight,
        const IsRequestedFn& is_requested,
        const CanFetchBranchFn& can_fetch_branch) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Stop requesting the stale branches containing `cleared` from `peer`,
     *  after a request for one of them timed out, until it announces their
     *  tips with block data again. */
    void BlockFetchTimedOut(NodeId peer, std::span<const CBlockIndex* const> cleared) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Whether `block` is stored on a tracked, still-eligible stale branch and
     *  may be served to a peer that negotiated stale-tip relay. */
    bool CanServeStaleBranchBlock(const CChain& chain, const CBlockIndex& block) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Get the tracked tips that are eligible for relay, with their fork
     *  points, in the order they were added. */
    std::vector<StaleFork> GetStaleTips(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether to ask peers to announce stale tips once they can serve the
     *  blocks. Signet stale tips can only be validated with the full block
     *  data containing the signature, so always prefer block availability
     *  there. */
    bool PrefersBlocks() const;

    /** Check that no per-peer state remains. */
    void CheckIsEmpty() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Check that no state remains for `peer`. */
    void CheckIsEmpty(NodeId peer) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

private:
    /** A stale tip a peer announced to us. */
    struct StaleTipAnnouncement {
        const CBlockIndex* tip;
        //! Whether the peer offered to serve the blocks on the tip's branch. It
        //! may not have connected them, so their scripts may be unchecked.
        bool have_block;
        //! Whether a best-effort request for the tip's branch timed out, so the
        //! branch is no longer requested from this peer until it announces the
        //! tip again.
        bool block_fetch_timed_out{false};
    };

    struct PeerInfo {
        /** Stale tips this peer announced to us, oldest first. Kept
         *  independently of our tracker, so tips we don't track (yet) are
         *  remembered too. */
        std::deque<StaleTipAnnouncement> m_staletips_from_peer;
        /** Tracked stale tips we announced to this peer. */
        std::set<const CBlockIndex*> m_staletips_to_peer;
    };

    /** Append the blocks of `tip`'s branch to request to `blocks`. */
    void AddStaleBranchBlocksToRequest(const CChain& chain, const CBlockIndex& tip, size_t in_flight,
                                       const IsRequestedFn& is_requested,
                                       std::vector<const CBlockIndex*>& blocks) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    const StaleTipRelayOptions m_opts;
    StaleTipTracker m_tracker GUARDED_BY(::cs_main);
    std::map<NodeId, PeerInfo> m_peers GUARDED_BY(::cs_main);
};

} // namespace node

#endif // BITCOIN_NODE_STALETIPRELAYMAN_H
