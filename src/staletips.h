// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_STALETIPS_H
#define BITCOIN_STALETIPS_H

#include <chain.h>
#include <kernel/cs_main.h>
#include <serialize.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/check.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <ios>
#include <string>
#include <vector>

namespace node {
class BlockManager;
} // namespace node

/** Maximum number of compressed headers permitted in a `staletip` message. */
static constexpr size_t MAX_STALETIP_HEADERS{20};
/** Default number of blocks below the active tip within which a stale tip is
 *  still considered recent enough to be tracked and relayed. */
static constexpr int STALETIP_RECENT_WINDOW{1000};
/** Maximum number of stale tips StaleTipTracker retains, and so the maximum
 *  number of previously known stale tips advertised to a peer. */
static constexpr size_t MAX_ADVERTISED_STALETIPS{10};

/** A stale branch of the block tree, described by its tip and the point where
 *  it forks off the active chain. */
struct StaleFork {
    //! Last common ancestor of the stale tip and the active chain.
    std::reference_wrapper<const CBlockIndex> fork_point;
    //! Tip of the stale branch.
    std::reference_wrapper<const CBlockIndex> tip;
};

/** A block header without its previous block hash, as serialized in `staletip`
 *  messages. The omitted previous block hash is reconstructed from the
 *  preceding header in the message (or from the fork point for the first
 *  header), saving 32 bytes per header. */
struct StaleTipCompressedHeader {
    int32_t version{0};
    uint256 merkle_root{};
    uint32_t time{0};
    uint32_t bits{0};
    uint32_t nonce{0};

    bool operator==(const StaleTipCompressedHeader&) const = default;

    SERIALIZE_METHODS(StaleTipCompressedHeader, obj)
    {
        READWRITE(obj.version, obj.merkle_root, obj.time, obj.bits, obj.nonce);
    }
};

/** Thrown when deserializing a `staletip` payload that declares more than
 *  MAX_STALETIP_HEADERS headers. Distinguished from other deserialization
 *  failures so that such messages can be ignored without disconnecting the
 *  peer, as longer branches are valid but relayed via normal headers sync. */
class StaleTipHeadersLimitExceeded : public std::ios_base::failure
{
public:
    explicit StaleTipHeadersLimitExceeded(const std::string& message) : std::ios_base::failure{message} {}
};

/** Contents of a `staletip` P2P message: an announcement of a stale branch,
 *  consisting of the fork point hash, the compressed headers of the branch and
 *  whether the announcer has the stale tip's block data. */
struct StaleTipMessage
{
    //! Block hash of the last common ancestor of the stale tip and the
    //! announcer's active chain.
    uint256 m_fork_point{};
    //! Compressed headers from the first block after the fork point up to the
    //! stale tip, in height order.
    std::vector<StaleTipCompressedHeader> m_headers;
    //! Whether the announcer can provide the stale tip's block data on request.
    bool m_have_block{false};

    StaleTipMessage() = default;
    /** Construct an announcement for `fork`, compressing the headers between
     *  `fork.fork_point` (exclusive) and `fork.tip` (inclusive). */
    StaleTipMessage(const StaleFork& fork, bool have_block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Decompress the headers by restoring their previous-block hashes,
     *  beginning with `m_fork_point`.
     *
     *  The headers are continuous by construction, but no proof-of-work,
     *  consensus, or contextual validation has been performed. */
    std::vector<CBlockHeader> DecompressHeaders() const;

    bool operator==(const StaleTipMessage&) const = default;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        Assert(!m_headers.empty());
        Assert(m_headers.size() <= MAX_STALETIP_HEADERS);

        s << m_fork_point;
        WriteCompactSize(s, m_headers.size());
        for (const auto& header : m_headers) {
            s << header;
        }
        const uint8_t have_block{m_have_block};
        s << have_block;
    }

    /**
     * @throws StaleTipHeadersLimitExceeded if more than MAX_STALETIP_HEADERS
     *         headers are declared, std::ios_base::failure for any other
     *         malformed payload.
     */
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        s >> m_fork_point;

        const uint64_t size{ReadCompactSize(s)};
        if (size == 0) {
            throw std::ios_base::failure("staletip headers empty");
        }
        if (size > MAX_STALETIP_HEADERS) {
            throw StaleTipHeadersLimitExceeded{"staletip headers limit exceeded"};
        }

        m_headers.clear();
        m_headers.reserve(size);
        for (uint64_t i{0}; i < size; ++i) {
            m_headers.emplace_back();
            s >> m_headers.back();
        }

        uint8_t have_block{0};
        s >> have_block;
        if (have_block > 1) {
            throw std::ios_base::failure("staletip invalid bool");
        }
        m_have_block = have_block;
    }
};

/** Outcome of CheckStaleTipAnnouncement(). */
enum class StaleTipAnnouncementCheck {
    OK,
    //! The announced tip is more than STALETIP_RECENT_WINDOW blocks below the
    //! active tip.
    OUTSIDE_RECENT_WINDOW,
    //! The announced branch has less work than the anti-DoS threshold.
    LOW_WORK,
};

/** Check an announced stale branch of `num_headers` headers, forking off at
 *  `fork_point` and claiming `claimed_work`, against the active tip and the
 *  anti-DoS `work_threshold`. */
StaleTipAnnouncementCheck CheckStaleTipAnnouncement(const CBlockIndex& fork_point, size_t num_headers, const arith_uint256& claimed_work,
                                                    const CBlockIndex* active_tip, const arith_uint256& work_threshold);

/** Tracker of recently seen stale tips: tips of valid (or potentially valid)
 *  branches of the block tree that are not part of the active chain.
 *
 * At most MAX_ADVERTISED_STALETIPS tips are tracked for later relay to
 * peers. A tracked tip is only relayed while it is
 * eligible: its branch forks off the active chain by no more than
 * `m_max_headers` blocks, its height is within `m_recent_window` blocks of
 * the active tip, it has no more work than the active tip, and it is not
 * known to be invalid. A tip that is ineligible only for now, for example
 * because a reorg changed its fork point, stays tracked. A tip that can never
 * become eligible again is dropped the next time a tip is added.
 *
 * Stricter policies apply on test networks: on signet the tip's block must
 * have been validated (the block signature cannot be verified from headers
 * alone) and header variants are deduplicated, including against the active
 * chain, while on testnet the tip must meet a minimum difficulty so that
 * min-difficulty blocks are not relayed.
 */
class StaleTipTracker
{
private:
    struct Entry {
        //! Tracked stale tip, or nullptr for an unused slot.
        const CBlockIndex* tip{nullptr};
        //! Sequence number assigned when the tip was added, used as a
        //! deterministic tie-breaker for eviction.
        uint64_t seqno{0};
    };

    std::array<Entry, MAX_ADVERTISED_STALETIPS> m_tips{};
    //! Sequence number to assign to the next addition.
    uint64_t m_next_seqno{1};
    ChainType m_chain_type{ChainType::MAIN};
    //! Tips more than this many blocks below the active tip are not tracked.
    int m_recent_window{STALETIP_RECENT_WINDOW};
    //! Maximum stale branch length to track.
    size_t m_max_headers{MAX_STALETIP_HEADERS};

    /** Find the fork point of `stale_tip` with the active chain, checking that
     *  the tip is eligible for tracking. Checks on the tip's block are left to
     *  BlockValidatedIfRequired().
     *
     * @return The fork point, or nullptr if the tip is not eligible.
     */
    const CBlockIndex* GetEligibleForkPoint(const CChain& chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `stale_tip`'s block has been validated, if the network requires
     *  it before the tip is tracked. On signet the block signature cannot be
     *  verified from headers alone. Once true, this stays true, so it is only
     *  checked when a tip is added. */
    bool BlockValidatedIfRequired(const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `stale_tip` can never become eligible again: it is known to be
     *  invalid, or too far below the active tip. */
    bool IsExpired(const CChain& chain, const CBlockIndex& stale_tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Drop tracked tips that have expired (see IsExpired()). */
    void PruneExpired(const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Insert `stale_tip` into the tracker, dropping any tracked tips that it
     *  descends from. Does nothing if one of its descendants is already
     *  tracked, or if the tracker is full and no tracked tip has less work.
     *  When full, the tip with the least work is evicted, preferring to evict
     *  the least recently added among tips with equal work. A tip never
     *  evicts one with equal work, so announcing an evicted tip again cannot
     *  readmit it while the tracker stays full. On signet, tracked header
     *  variants of `stale_tip` are either kept in its place or replaced by it,
     *  whichever has the longer branch. */
    bool Add(const CBlockIndex& stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

public:
    /** Maximum target allowed for testnet stale-tip relay policy. */
    static const uint256 TESTNET_MAX_TARGET;

    StaleTipTracker() = default;
    /** Construct a tracker with a non-default chain type or policy parameters. */
    explicit StaleTipTracker(ChainType chain_type, int recent_window = STALETIP_RECENT_WINDOW, size_t max_headers = MAX_STALETIP_HEADERS)
        : m_chain_type{chain_type}, m_recent_window{recent_window}, m_max_headers{max_headers}
    {
    }

    explicit StaleTipTracker(int recent_window, size_t max_headers)
        : StaleTipTracker{ChainType::MAIN, recent_window, max_headers}
    {
    }

    /** Seed the tracker with any eligible stale tips already present in the
     *  block index, scanning all block index entries. Called at startup. */
    void Initialize(node::BlockManager& blockman, const CChain& chain) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Whether no stale tips are currently retained. */
    bool Empty() const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);

    /** Track `stale_tip` if it is eligible (see GetEligibleForkPoint() and
     *  BlockValidatedIfRequired()) and can be retained under the tracker's
     *  resource limits.
     *
     * @return Whether the tracker was updated to track `stale_tip`.
     */
    bool AddStaleTip(const CChain& chain, const CBlockIndex* stale_tip) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Get the tracked tips that are eligible for relay, with their fork
     *  points, in the order they were added. */
    std::vector<StaleFork> GetStaleTips(const CChain& chain) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    /** Whether `tip` is tracked, even if it is currently
     *  ineligible for relay. */
    bool IsTracked(const CBlockIndex* tip) const EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};

#endif // BITCOIN_STALETIPS_H
