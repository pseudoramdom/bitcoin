// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_STALETIPTRACKER_H
#define BITCOIN_NODE_STALETIPTRACKER_H

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/cs_main.h>
#include <staletipmessage.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <cstddef>
#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace node {
class BlockManager;

/** Default number of blocks below the active tip within which a stale tip is
 *  still considered recent enough to be tracked. From BIP 332. */
inline constexpr int STALETIP_RECENT_WINDOW{1000};

/** Maximum number of stale tips StaleTipTracker retains. From BIP 332, which
 *  limits how many previously known stale tips are advertised to a peer. */
inline constexpr size_t MAX_ADVERTISED_STALETIPS{10};

/** Whether `ancestor` is an ancestor of `block`, or `block` itself. */
bool HasAncestor(const CBlockIndex& block, const CBlockIndex& ancestor);

/** A stale branch of the block tree, described by its tip and the point where
 *  it forks off the active chain. */
struct StaleFork {
    //! Last common ancestor of the stale tip and the active chain. Never null.
    const CBlockIndex* fork_point;
    //! Tip of the stale branch. Never null.
    const CBlockIndex* tip;
};

/** Build the `staletip` message announcing `fork`, compressing the headers
 *  between `fork.fork_point` (exclusive) and `fork.tip` (inclusive). */
StaleTipMessage MakeStaleTipMessage(const StaleFork& fork, bool have_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

/** Tracker of recently seen stale tips: tips of valid (or potentially valid)
 *  branches of the block tree that are not part of the active chain.
 *
 * At most MAX_ADVERTISED_STALETIPS tips are tracked for later relay to
 * peers. A tracked tip is only relayed while it is eligible: its branch forks
 * off the active chain by no more than `m_max_headers` blocks, its height is
 * within `m_recent_window` blocks of the active tip, it has no more work than
 * the active tip, and it is not known to be invalid. A tip that is ineligible
 * only for now, for example because a reorg changed its fork point, stays
 * tracked. A tip that can never become eligible again is dropped the next
 * time an eligible tip is added.
 *
 * Stricter policies apply on test networks: on signet the tip's block must
 * have been validated (the block signature cannot be verified from headers
 * alone) and block variants are deduplicated, including against the active
 * chain, while on testnet the tip must meet a minimum difficulty so that
 * min-difficulty blocks are not relayed.
 *
 * Signet blocks are variants when the data their BIP 325 signature commits
 * to is the same: the previous block, version, time and signet merkle root.
 * Anyone can turn a signed block into a variant with a different header
 * merkle root by changing its unsigned solution. The signet merkle root is
 * not in the header, so comparing it can require reading both blocks. Blocks
 * are only read when a tip is added from a validation event and in
 * RefreshSignetVariants(), never to answer a peer.
 */
class StaleTipTracker
{
public:
    /** Reads a block and returns its BIP 325 merkle root, if it can. */
    using SignetRootReader = std::function<std::optional<uint256>(const CBlockIndex&)>;
    //! Room for every tracked tip and the active block it is compared with,
    //! and as many candidates.
    static constexpr size_t MAX_CACHED_SIGNET_ROOTS{4 * MAX_ADVERTISED_STALETIPS};

private:
    struct TrackedTip {
        const CBlockIndex* index;
        //! On signet, the active chain's block at the tip's height that the
        //! tip was last compared with, and whether it is a variant of it.
        //! The active chain can change before RefreshSignetVariants() runs,
        //! so the result only holds while that block is still active.
        const CBlockIndex* compared_with{nullptr};
        bool is_variant{false};
    };
    //! Tracked stale tips in the order they were added, oldest first.
    //! Never holds more than MAX_ADVERTISED_STALETIPS entries.
    std::vector<TrackedTip> m_tips;
    //! Signet requires a validated block and tracks at most one tip with the same signed data.
    bool m_signet;
    SignetRootReader m_read_signet_root;
    //! BIP 325 merkle roots of compared blocks, least recently used first.
    //! Never holds more than MAX_CACHED_SIGNET_ROOTS entries.
    std::vector<std::pair<const CBlockIndex*, uint256>> m_signet_roots;
    //! Highest proof-of-work target a tracked tip may have, if limited. Set
    //! on testnet3 and testnet4, where minimum-difficulty blocks are cheap.
    std::optional<arith_uint256> m_max_target;
    //! Tips more than this many blocks below the active tip are not tracked.
    int m_recent_window{STALETIP_RECENT_WINDOW};
    //! Maximum stale branch length to track.
    size_t m_max_headers{MAX_STALETIP_HEADERS};

    /** Find the fork point of `stale_tip` with the active chain, checking that
     *  the tip is eligible. On signet, AddStaleTip() also requires the tip's
     *  block to have been validated, and variants are checked separately.
     *
     * @return The fork point, or nullptr if the tip is not eligible.
     */
    const CBlockIndex* GetEligibleForkPoint(const CChain& active_chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** The BIP 325 merkle root of `block`, from the cache or, if `read_blocks`
     *  is set, by reading its validated block. */
    std::optional<uint256> GetSignetRoot(const CBlockIndex& block, bool read_blocks) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether two signet blocks are variants.
     *
     * @return std::nullopt if the headers don't settle it and a signet merkle
     *         root is not available.
     */
    std::optional<bool> IsVariant(const CBlockIndex& block, const CBlockIndex& other, bool read_blocks) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `block` is a variant of the block at its height on the branch
     *  ending at `branch_tip` (see IsVariant()). */
    std::optional<bool> IsVariantOnBranch(const CBlockIndex& block, const CBlockIndex& branch_tip, bool read_blocks) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether a tracked signet tip must not be relayed because it is a
     *  variant of the active chain's block at its height, or may be one: the
     *  headers don't settle it and it was not compared with that block yet. */
    bool IsHiddenByActiveChain(const CChain& active_chain, const TrackedTip& tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `stale_tip` can never become eligible again: it is known to be
     *  invalid, or too far below the active tip. */
    bool IsExpired(const CChain& active_chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Drop tracked tips that have expired (see IsExpired()). */
    void PruneExpired(const CChain& active_chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Insert `stale_tip` into the tracker, dropping any tracked tips that it
     *  descends from. Does nothing if one of its descendants is already
     *  tracked, or if the tracker is full and no tracked tip has less work.
     *  When full, the tip with the least work is evicted, preferring to evict
     *  the least recently added among tips with equal work. A tip never
     *  evicts one with equal work, so announcing an evicted tip again cannot
     *  readmit it while the tracker stays full.
     *
     *  On signet, `stale_tip` is not added if it is a variant of a block on a
     *  tracked branch, and replaces tracked tips that are variants of a block
     *  on its own branch. A tip built on a variant of a tracked tip therefore
     *  replaces it, which BIP 332 does not require. Tips that only descend
     *  from variants of the same block, without being variants themselves,
     *  are all kept, as the BIP allows. A comparison that cannot be made
     *  keeps `stale_tip` out, but never drops a tracked tip. */
    bool Add(const CChain& active_chain, const CBlockIndex& stale_tip, bool read_blocks) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    /** Construct a tracker applying `chain_type`'s policy, with optional
     *  non-default policy parameters for tests. */
    explicit StaleTipTracker(ChainType chain_type = ChainType::MAIN,
                             int recent_window = STALETIP_RECENT_WINDOW,
                             size_t max_headers = MAX_STALETIP_HEADERS);

    /** Set how signet blocks are read to compare their BIP 325 merkle roots.
     *  Without a reader, only cached roots are compared. */
    void SetSignetRootReader(SignetRootReader reader) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Track the eligible stale tips already in the block index, as the
     *  tracker is not persisted. Scans every block index entry, so it is
     *  meant to be called once at startup. */
    void SeedFromBlockIndex(const node::BlockManager& blockman, const CChain& active_chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Compare the tracked signet tips with the blocks now on the active
     *  chain, reading blocks where needed. Until this is called after the
     *  active chain changes, a tip that may be a variant of a newly active
     *  block is not relayed. */
    void RefreshSignetVariants(const CChain& active_chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Track `stale_tip` if it is eligible (see GetEligibleForkPoint()) and can
     *  be retained under the tracker's resource limits. On signet, the tip's
     *  block must also have been validated, and it must be known not to be a
     *  variant of an active or tracked block.
     *
     * @param[in] read_blocks Whether signet blocks may be read to compare
     *                        variants. If not, only cached roots are used.
     * @return Whether the tracker was updated to track `stale_tip`.
     */
    bool AddStaleTip(const CChain& active_chain, const CBlockIndex& stale_tip, bool read_blocks = true) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether the block data for `stale_tip` may be requested from a peer.
     *  On signet, AddStaleTip() requires the block to have been validated;
     *  requesting it is allowed before then, since the signet signature can
     *  only be verified with the block data. The same goes for comparing
     *  variants, unless the headers alone show that it is one. */
    bool CanRequestStaleTipBlock(const CChain& active_chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `block` is stored on a tracked, still-eligible stale branch and
     *  may be served to a peer that negotiated stale-tip relay. */
    bool CanServeStaleBranchBlock(const CChain& active_chain, const CBlockIndex& block) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Get the tracked tips that are currently eligible, with their fork
     *  points, in the order they were added. */
    std::vector<StaleFork> GetStaleTips(const CChain& active_chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `tip` is tracked, even if it is currently ineligible. */
    bool IsTracked(const CBlockIndex& tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

} // namespace node

#endif // BITCOIN_NODE_STALETIPTRACKER_H
