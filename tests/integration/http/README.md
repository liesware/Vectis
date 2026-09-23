# HTTP Integration Tests

`cases/` contains the endpoint contracts. Each `positive_*.py` or
`negative_*.py` module exports an ordered `CASES` tuple; `cases/registry.py`
is the sole place that composes their execution order.

`lib/` is private to this suite. It owns transport clients, assertions,
configuration transactions, the shared `HttpTestContext`, fixtures, and the
case runner. No shared test-helper package exists: every suite owns the helpers
it needs and must not import private modules from another suite.

## Adding a Case

1. Put the endpoint-specific contract in the appropriate `cases/positive_*.py`
   or `cases/negative_*.py` module. Split a capability into another module when
   it would make the existing module hard to scan.
2. Register `Case("capability.contract", run)` in that module's `CASES` tuple.
   A new module also needs an explicit entry in `cases/registry.py`.
3. Receive `HttpTestContext` in `run(ctx)`. Use `ctx.http` for status-preserving
   requests, `ctx.client` for successful authenticated requests, and
   `ctx.fixtures` or `ctx.artifacts` only for ordered, suite-local shared data.
4. Change signed configuration through `ctx.set_*`, `ctx.write_config()`, or
   `ctx.write_unsigned_config()`. The context transaction restores both config
   files and reloads the restored runtime state during cleanup.
5. Keep endpoint-specific assertions next to the case. Move an abstraction into
   `lib/` only when more than one HTTP capability needs it.

Run the structural guards with:

```sh
PYTHONPATH=tests/integration:tests/integration/http \
  python3 -m unittest discover -s tests/integration/http/lib -p 'test_*.py'
```
