# VDAF test vectors

Copied verbatim from the reference implementation at
`github.com/cfrg/draft-irtf-cfrg-vdaf`, tag `draft-irtf-cfrg-vdaf-22`
(`test_vec/` and `test_vec/vdaf/`), which is the draft DAP-20 references.

The vectors are generated deterministically by that repository's
`poc/gen_test_vec.py`; regenerating them at the same tag reproduces these files
byte for byte.

| File | Covers |
|---|---|
| `XofTurboShake128.json` | the XOF seed, domain tag and binder |
| `Prio3Sum_0.json`, `Prio3Sum_1.json`, `Prio3Sum_2.json` | Prio3Sum, Field64 |
| `Prio3SumVec_0.json`, `Prio3SumVec_1.json` | Prio3SumVec, Field128 |

`tests/test_mesh_vdaf.py` replays each report's operations in file order:
`shard`, both `verify_init` calls, `verifier_shares_to_message`,
`verify_next`, then aggregate and unshard.
