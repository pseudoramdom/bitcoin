// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/cs_main.h>
#include <node/staletiprelayman.h>
#include <test/util/blocktree.h>
#include <test/util/setup_common.h>
#include <util/check.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(staletiprelayman_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(check_staletip_announcement)
{
    using node::CheckStaleTipAnnouncement;
    using node::StaleTipAnnouncementResult;

    LOCK(::cs_main);

    constexpr int recent_window{5};
    BlockTree tree;
    CBlockIndex* active{tree.Add(nullptr, /*active=*/true)};
    while (active->nHeight < recent_window + 10) active = tree.Add(active, /*active=*/true);
    // The lowest fork point whose one-block branch is still within the
    // recency window.
    const CBlockIndex& fork_point{*Assert(active->GetAncestor(active->nHeight - recent_window - 1))};
    const arith_uint256 claimed_work{2};
    const arith_uint256 threshold{fork_point.nChainWork + claimed_work};

    BOOST_CHECK(CheckStaleTipAnnouncement(fork_point, 1, claimed_work, active, threshold, recent_window) == StaleTipAnnouncementResult::OK);
    BOOST_CHECK(CheckStaleTipAnnouncement(*fork_point.pprev, 1, claimed_work, active, threshold, recent_window) == StaleTipAnnouncementResult::OUTSIDE_RECENT_WINDOW);
    // A longer branch from a lower fork point can still reach into the window.
    BOOST_CHECK(CheckStaleTipAnnouncement(*fork_point.pprev, 2, claimed_work, active, threshold - arith_uint256{1}, recent_window) == StaleTipAnnouncementResult::OK);

    // The branch must meet the work threshold, which still applies without an
    // active tip.
    BOOST_CHECK(CheckStaleTipAnnouncement(fork_point, 1, claimed_work - arith_uint256{1}, active, threshold, recent_window) == StaleTipAnnouncementResult::LOW_WORK);
    BOOST_CHECK(CheckStaleTipAnnouncement(*fork_point.pprev, 1, claimed_work, nullptr, threshold, recent_window) == StaleTipAnnouncementResult::LOW_WORK);
}

BOOST_AUTO_TEST_SUITE_END()
