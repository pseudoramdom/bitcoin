// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_BLOCKTREE_H
#define BITCOIN_TEST_UTIL_BLOCKTREE_H

#include <arith_uint256.h>
#include <chain.h>
#include <kernel/cs_main.h>
#include <primitives/block.h>
#include <sync.h>
#include <uint256.h>

#include <cstdint>
#include <deque>
#include <memory>
#include <utility>
#include <vector>

/** Block index entries linked into a tree without a BlockManager, for unit
 *  tests of code that walks the block index. */
struct BlockTree
{
    std::deque<uint256> hashes;
    std::vector<std::unique_ptr<CBlockIndex>> blocks;
    CChain active_chain;
    uint32_t next_nonce{1};

    CBlockIndex* Add(CBlockIndex* prev,
                     bool active,
                      bool have_data = false,
                      uint32_t bits = 0x1d00ffff,
                      uint256 merkle_root = uint256::ZERO) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        CBlockHeader header;
        header.nVersion = 4;
        header.hashPrevBlock = prev ? prev->GetBlockHash() : uint256::ZERO;
        header.hashMerkleRoot = merkle_root == uint256::ZERO ? uint256{static_cast<uint8_t>(next_nonce)} : merkle_root;
        header.nTime = 1'700'000'000 + next_nonce;
        header.nBits = bits;
        header.nNonce = next_nonce++;

        hashes.push_back(header.GetHash());
        auto block{std::make_unique<CBlockIndex>(header)};
        block->phashBlock = &hashes.back();
        block->pprev = prev;
        block->nHeight = prev ? prev->nHeight + 1 : 0;
        block->nChainWork = (prev ? prev->nChainWork : arith_uint256{}) + arith_uint256{1};
        block->nStatus = BLOCK_VALID_TREE;
        if (have_data) block->nStatus |= BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
        block->BuildSkip();
        CBlockIndex* ret{block.get()};
        blocks.push_back(std::move(block));
        if (active) active_chain.SetTip(*ret);
        return ret;
    }
};

#endif // BITCOIN_TEST_UTIL_BLOCKTREE_H
