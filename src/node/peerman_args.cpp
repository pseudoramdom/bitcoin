// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <node/peerman_args.h>

#include <common/args.h>
#include <net_processing.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/translation.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>

namespace node {

namespace {
std::optional<StaleTipRelayMode> ParseStaleTipRelayMode(std::string_view mode)
{
    if (mode == "none") return StaleTipRelayMode::NONE;
    if (mode == "headers") return StaleTipRelayMode::HEADERS;
    return std::nullopt;
}
} // namespace

util::Result<void> ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options)
{
    if (auto value{argsman.GetBoolArg("-txreconciliation")}) options.reconcile_txs = *value;

    if (argsman.IsArgNegated("-staletips")) {
        options.stale_tip_relay_mode = StaleTipRelayMode::NONE;
    } else if (auto value{argsman.GetArg("-staletips")}) {
        const auto mode{ParseStaleTipRelayMode(*value)};
        if (!mode) {
            return util::Error{strprintf(_("Invalid value for -staletips=<mode>: '%s'. Expected one of 'none' or 'headers'."), *value)};
        }
        options.stale_tip_relay_mode = *mode;
    }

    if (auto value{argsman.GetIntArg("-blockreconstructionextratxn")}) {
        options.max_extra_txs = uint32_t((std::clamp<int64_t>(*value, 0, std::numeric_limits<uint32_t>::max())));
    }

    if (auto value{argsman.GetBoolArg("-capturemessages")}) options.capture_messages = *value;

    if (auto value{argsman.GetBoolArg("-blocksonly")}) options.ignore_incoming_txs = *value;

    if (auto value{argsman.GetIntArg("-txsendrate")}) {
        options.tx_send_rate = uint32_t(std::clamp<int64_t>(*value, 1, 1000));
    }

    if (auto value{argsman.GetBoolArg("-privatebroadcast")}) options.private_broadcast = *value;

    return {};
}

} // namespace node

