New settings
------------

- A new `-staletips=<mode>` option tracks recent stale chain tips for
  stale-tip relay (BIP 332). The modes are `none` (the default) and
  `headers`. (#NNNNN)

Updated RPCs
------------

- `getchaintips` has a new optional `max_depth` argument that limits the
  result to tips at most that many blocks below the active tip, and it
  reports `fork_point`, the block where the branch connects to the active
  chain, for each non-active tip. (#NNNNN)

- `getchaintips` has a new `staletips_only` argument that lists only the
  recent stale tips tracked with `-staletips`. (#NNNNN)
