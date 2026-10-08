# RelayApp receipt backpressure

Delivery receipts are correctness-bearing application events. Once an authenticated
ACK has removed an outbound message, losing its receipt makes the consumer wait
for an event that can never arrive.

Previously `handle_app_ack` sent directly with `try_send`. A full consumer channel
therefore discarded the receipt after the outbound message had already been
removed. This is reachable when an embedding application temporarily stops
draining SDK events, including while its own bounded output channel is full.

Receipts are now retained in FIFO order and retried from the runtime ticks until
the consumer channel has capacity. New sends are refused when the retained receipt
backlog reaches 1,024 entries; already-outbound messages may add at most the
existing bounded outbound queue before admission closes. A closed consumer clears
the retained receipts because the application handle can no longer observe them.

The regression uses a receipt channel with capacity one, acknowledges two messages
without draining it, then proves that the second receipt remains queued and is
delivered in order after capacity becomes available. It uses no timeout increase,
retry change, external network or WAN claim.
