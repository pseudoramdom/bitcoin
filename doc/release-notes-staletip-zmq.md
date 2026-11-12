New settings
------------

- A new `-zmqpubhashstaletip=<address>` option publishes the hash of each
  accepted stale header or block on the `hashstaletip` ZMQ topic. It does
  not depend on `-staletips`. (#NNNNN)
