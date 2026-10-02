# Resilient report queries

`mh_endpoint_async.py` is the async ACSN adapter based on the deployed local
adapter, preserving its existing `mh_config` and authentication imports. It is
AGPL-3.0 like this repository. It is deployed as the existing read-only
`/app/endpoint/mh_endpoint.py` override; the upstream synchronous entry point is
not replaced automatically by this branch.

The client can send `ids`, `days` (1–7), and an optional `devices` mapping of
device IDs to their public hashed query indexes. All private keys remain in HA.
The response retains `results` and adds `query` metadata:

- `status`: complete, partial, or failed; partial responses use HTTP 200 and
  preserve successful batches. Complete empty results are legitimate success.
- `devices`: coverage status and successful key counts for each requested device.
- `batch_details`: attempts, elapsed milliseconds, report counts, terminal error,
  and transient attempt errors; never includes keys, credentials or coordinates.
- `/status`: authenticated diagnostic counters and the latest query metadata.

The adapter uses batches of 100 keys, at most four concurrent requests, an
8-second request timeout, up to three attempts, and a 40-second round deadline.
Temporary HTTP errors, connections, empty bodies and invalid responses have
bounded backoff. Authentication and non-transient HTTP errors are not retried.
Long Retry-After values defer the batch to a later scheduled poll instead of
retrying before the server permits it. A failed or timed-out batch cannot
discard another batch's completed reports.

HA records successful query time only for devices whose entire key set was
covered. Partially retrieved reports can still update location and history.
HA diagnostics and entity query_status indicate incomplete retrieval.

Both `grouped` and `individual` request layouts are supported, preserving the
same key set and requested time range. The deployed default remains grouped.
The live ABBA comparison was blocked by automatic approval review because it
would submit 850 HA-derived public indexes repeatedly to Apple's gateway.
It has not been executed and no retrieval improvement from changing layouts
is claimed.

Validation: synthetic faults and a real local aiohttp HTTP server test cover
503 recovery, partial batches, authentication failure, empty/invalid bodies,
long Retry-After, deadlines, input report validation and HTTP status semantics.
Run `python -m unittest discover -s endpoint/tests -v` with aiohttp and requests.
