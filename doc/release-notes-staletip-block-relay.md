P2P and network changes
-----------------------

- With `-staletips` enabled, the node serves the blocks of the stale
  branches it tracks to peers that negotiated stale-tip relay (BIP 332).
  (#NNNNN)

- A new `-staletips=blocks` mode additionally downloads the blocks of
  announced stale branches from peers that offer them, without disconnecting
  peers that are slow to deliver them, and asks peers to announce stale tips
  once they have the blocks. (#NNNNN)
