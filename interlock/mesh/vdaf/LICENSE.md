# Licence and provenance

The modules in this directory are a port of the reference implementation of
the VDAF specification, taken from
`github.com/cfrg/draft-irtf-cfrg-vdaf` at tag `draft-irtf-cfrg-vdaf-22`
(the draft DAP-20 references). Upstream's own `LICENSE.md` reads:

> # License
>
> See the [guidelines for contributions](https://github.com/cfrg/draft-irtf-cfrg-vdaf/blob/main/CONTRIBUTING.md).

Those guidelines state that all material in that repository is a Contribution
to the IETF Standards Process under BCP 78, BCP 79 and the IETF Trust Legal
Provisions, and that code components are subject to a Simplified BSD Licence.
That licence applies to this port:

```
Copyright (c) IETF Trust and the persons identified as authors of the code.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## What changed in this port

- Python 3.9 syntax: no `Self`, `X | Y`, `typing.override` or `TypeAlias`.
- `Cryptodome.Hash.TurboSHAKE128` replaced by `interlock/mesh/turboshake.py`
  (RFC 9861).
- Poplar1, Prio3Histogram, Prio3Multiproof and the AES-based XOF are dropped;
  `Prio3SumVec` and `Prio3Sum` remain.
- Randomness that the reference drew from `random` comes from the caller.

These changes are part of interlock and are licensed Apache-2.0 like the rest
of the project ([LICENSE](../../../LICENSE)); the upstream terms above continue
to apply to the ported material.
