// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <staletips.h>
#include <streams.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <ios>

FUZZ_TARGET(staletips)
{
    DataStream stream{buffer};
    StaleTipMessage data;
    try {
        stream >> data;
    } catch (const std::ios_base::failure&) {
        return;
    }

    const auto decompressed{data.DecompressHeaders()};
    assert(decompressed.size() == data.m_headers.size());
    assert(!decompressed.empty());
    assert(decompressed.front().hashPrevBlock == data.m_fork_point);

    DataStream serialized;
    serialized << data;
    DataStream roundtrip_stream{serialized};
    StaleTipMessage roundtrip;
    roundtrip_stream >> roundtrip;
    assert(roundtrip == data);
}
