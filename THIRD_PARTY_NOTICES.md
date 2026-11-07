# THIRD_PARTY_NOTICES

This document inventories the licenses of third-party components included in the runtime binary, pinned external backends that are not packaged, GitHub Actions referenced by the workflow, and preset data embedded in the binary. Runtime license texts below are reproduced from the upstream LICENSE files for the specified versions/refs.

## What the MIT License Requires

The official MIT License text states: “The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.” Thus, when an MIT-licensed component is distributed as part of the binary, its copyright notice and permission notice must be retained. The MIT License does not require a specific filename; `THIRD_PARTY_NOTICES.md` is a practical way to carry these notices. See [Open Source Initiative — MIT License](https://opensource.org/license/mit).

For the BSD licenses below, binary redistribution terms also require the copyright notice, list of conditions, and disclaimer to be retained in the documentation and/or other materials provided with the distribution. See each license text below for the exact terms.

## Go Modules Included in the Binary Dependency Graph

This inventory covers non-standard modules appearing in the executable dependency graph for `./cmd/subenum-mcp` (`go list -deps`), not modules used only by tests or tooling.

| Module | Version | Status in `go.mod` | License and official source |
|---|---:|---|---|
| `github.com/google/jsonschema-go` | `v0.4.3` | direct | [MIT LICENSE](https://raw.githubusercontent.com/google/jsonschema-go/v0.4.3/LICENSE) · [tag v0.4.3](https://github.com/google/jsonschema-go/releases/tag/v0.4.3) |
| `github.com/modelcontextprotocol/go-sdk` | `v1.8.0` | direct | Transitional license: Apache-2.0/MIT/CC-BY-4.0; [LICENSE](https://raw.githubusercontent.com/modelcontextprotocol/go-sdk/v1.8.0/LICENSE) · [tag v1.8.0](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0) |
| `golang.org/x/net` | `v0.62.0` | direct | BSD 3-Clause; [LICENSE](https://go.googlesource.com/net/+/refs/tags/v0.62.0/LICENSE) · [tag v0.62.0](https://go.googlesource.com/net/+/refs/tags/v0.62.0) |
| `github.com/segmentio/asm` | `v1.1.3` | transitive | [MIT LICENSE](https://raw.githubusercontent.com/segmentio/asm/v1.1.3/LICENSE) · [tag v1.1.3](https://github.com/segmentio/asm/releases/tag/v1.1.3) |
| `github.com/segmentio/encoding` | `v0.5.4` | transitive | [MIT LICENSE](https://raw.githubusercontent.com/segmentio/encoding/v0.5.4/LICENSE) · [tag v0.5.4](https://github.com/segmentio/encoding/releases/tag/v0.5.4) |
| `github.com/yosida95/uritemplate/v3` | `v3.0.2` | transitive | BSD-3-Clause; [LICENSE](https://raw.githubusercontent.com/yosida95/uritemplate/v3.0.2/LICENSE) · [tag v3.0.2](https://github.com/yosida95/uritemplate/releases/tag/v3.0.2) |
| `golang.org/x/oauth2` | `v0.35.0` | transitive | BSD 3-Clause; [LICENSE](https://go.googlesource.com/oauth2/+/refs/tags/v0.35.0/LICENSE) · [tag v0.35.0](https://go.googlesource.com/oauth2/+/refs/tags/v0.35.0) |
| `golang.org/x/sync` | `v0.20.0` | transitive | BSD 3-Clause; [LICENSE](https://go.googlesource.com/sync/+/refs/tags/v0.20.0/LICENSE) · [tag v0.20.0](https://go.googlesource.com/sync/+/refs/tags/v0.20.0) |
| `golang.org/x/sys` | `v0.49.0` | transitive | BSD 3-Clause based on the LICENSE text; [LICENSE](https://go.googlesource.com/sys/+/refs/tags/v0.49.0/LICENSE) · [tag v0.49.0](https://go.googlesource.com/sys/+/refs/tags/v0.49.0) |
| `golang.org/x/time` | `v0.15.0` | transitive | BSD 3-Clause; [LICENSE](https://go.googlesource.com/time/+/refs/tags/v0.15.0/LICENSE) · [tag v0.15.0](https://go.googlesource.com/time/+/refs/tags/v0.15.0) |

### Go Runtime and Standard Library — Go 1.26.8 — BSD 3-Clause

The binary uses the Go runtime and standard library from toolchain `go1.26.8`. The official upstream [Go 1.26.8 LICENSE](https://go.googlesource.com/go/+/refs/tags/go1.26.8/LICENSE) carries BSD 3-Clause terms and `Copyright 2009 The Go Authors.` The identical license text is reproduced below with the Go module notices.

The Go 1.26.8 toolchain also vendors the following modules, whose packages appear in this executable's dependency graph. Their `LICENSE` files are byte-identical to the Go distribution license above (SHA-256 `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`); the same BSD 3-Clause text is reproduced below.

| Vendored module | Version in Go 1.26.8 | Packages linked into this executable | Official license |
|---|---|---|---|
| `golang.org/x/crypto` | `v0.46.1-0.20251210140736-7dacc380ba00` | `chacha20`, `chacha20poly1305`, `cryptobyte`, `cryptobyte/asn1`, `internal/alias`, `internal/poly1305` | [LICENSE](https://go.googlesource.com/go/+/refs/tags/go1.26.8/src/vendor/golang.org/x/crypto/LICENSE) |
| `golang.org/x/net` | `v0.47.1-0.20260731170545-cb1d721f7fb3` | `dns/dnsmessage`, `http/httpguts`, `http/httpproxy`, `http2/hpack`, `idna` | [LICENSE](https://go.googlesource.com/go/+/refs/tags/go1.26.8/src/vendor/golang.org/x/net/LICENSE) |
| `golang.org/x/sys` | `v0.39.0` | `cpu` | [LICENSE](https://go.googlesource.com/go/+/refs/tags/go1.26.8/src/vendor/golang.org/x/sys/LICENSE) |
| `golang.org/x/text` | `v0.32.0` | `secure/bidirule`, `transform`, `unicode/bidi`, `unicode/norm` | [LICENSE](https://go.googlesource.com/go/+/refs/tags/go1.26.8/src/vendor/golang.org/x/text/LICENSE) |

Module versions are from the official [Go 1.26.8 vendor manifest](https://go.googlesource.com/go/+/refs/tags/go1.26.8/src/vendor/modules.txt).

### `github.com/google/jsonschema-go` — MIT

The copyright notice and permission text below are taken from the upstream LICENSE for v0.4.3:

```text
MIT License

Copyright (c) 2025 JSON Schema Go Project Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### `github.com/segmentio/asm` — MIT

```text
MIT License

Copyright (c) 2021 Segment

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### `github.com/segmentio/encoding` — MIT

```text
MIT License

Copyright (c) 2019 Segment.io, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### `github.com/yosida95/uritemplate/v3` — BSD-3-Clause

```text
Copyright (C) 2016, Kohei YOSHIDA <https://yosida95.com/>. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### `golang.org/x/net`, `golang.org/x/oauth2`, `golang.org/x/sync`, `golang.org/x/sys`, `golang.org/x/time` — BSD 3-Clause

The five LICENSE files at the pinned tags are byte-for-byte identical (SHA-256 `911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad`). Each carries the copyright notice `Copyright 2009 The Go Authors.` Refs/tags and per-module LICENSE links are listed in the table above; one copy of the identical text is reproduced below:

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### `github.com/modelcontextprotocol/go-sdk` — Transitional License

The upstream LICENSE file for v1.8.0 explains that new code and specification contributions that have been relicensed use Apache-2.0; contributions without relicensing consent remain MIT; documentation other than specifications uses CC-BY-4.0. The complete upstream file (including copyright, terms, Apache-2.0, MIT, and the CC-BY-4.0 reference) is reproduced so that this transition is not reduced to a single license:

```text
The MCP project is undergoing a licensing transition from the MIT License to the Apache License, Version 2.0 ("Apache-2.0"). All new code and specification contributions to the project are licensed under Apache-2.0. Documentation contributions (excluding specifications) are licensed under CC-BY-4.0.

Contributions for which relicensing consent has been obtained are licensed under Apache-2.0. Contributions made by authors who originally licensed their work under the MIT License and who have not yet granted explicit permission to relicense remain licensed under the MIT License.

No rights beyond those granted by the applicable original license are conveyed for such contributions.

---

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright
      owner or by an individual or Legal Entity authorized to submit on behalf
      of the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

---

MIT License

Copyright (c) 2024-2025 Model Context Protocol a Series of LF Projects, LLC.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

Creative Commons Attribution 4.0 International (CC-BY-4.0)

Documentation in this project (excluding specifications) is licensed under
CC-BY-4.0. See https://creativecommons.org/licenses/by/4.0/legalcode for
the full license text.
```

## Pinned External Backends Not Packaged by SubEnum-MCP

SubEnum-MCP adapters invoke separate executables; the server does not download or include backend binaries in its package. The notices below are an inventory and provenance links, not a claim that backend binaries are distributed with the project.

| Backend | Version/ref | Upstream license and copyright | Official source |
|---|---|---|---|
| ProjectDiscovery Subfinder | `v2.17.0` | MIT — `Copyright (c) 2021 ProjectDiscovery, Inc.` | [release](https://github.com/projectdiscovery/subfinder/releases/tag/v2.17.0) · [LICENSE.md](https://raw.githubusercontent.com/projectdiscovery/subfinder/v2.17.0/LICENSE.md) |
| ProjectDiscovery dnsx | `v1.3.1` | MIT — `Copyright (c) 2021 ProjectDiscovery, Inc.` | [release](https://github.com/projectdiscovery/dnsx/releases/tag/v1.3.1) · [LICENSE.md](https://github.com/projectdiscovery/dnsx/blob/v1.3.1/LICENSE.md) |
| ProjectDiscovery AlterX | `v0.1.0` | MIT — `Copyright (c) 2023 ProjectDiscovery` | [release](https://github.com/projectdiscovery/alterx/releases/tag/v0.1.0) · [LICENSE](https://raw.githubusercontent.com/projectdiscovery/alterx/v0.1.0/LICENSE) |

SubEnum-MCP backend versions and pins can be verified in [`internal/adapters/pins.go`](https://github.com/alfa-reza/SubEnum-MCP/blob/main/internal/adapters/pins.go). Official license files remain with each backend project.

## GitHub Actions Referenced by CI

The following actions are called by CI workflows at pinned commits; the actions and their internal dependencies are not part of the SubEnum-MCP binary or the project build archive.

| Action | Pinned commit | Upstream license and copyright | Official source |
|---|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | MIT — `Copyright (c) 2018 GitHub, Inc. and contributors` | [commit](https://github.com/actions/checkout/commit/3d3c42e5aac5ba805825da76410c181273ba90b1) · [LICENSE](https://raw.githubusercontent.com/actions/checkout/3d3c42e5aac5ba805825da76410c181273ba90b1/LICENSE) |
| `actions/setup-go` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | MIT — `Copyright (c) 2018 GitHub, Inc. and contributors` | [commit](https://github.com/actions/setup-go/commit/b7ad1dad31e06c5925ef5d2fc7ad053ef454303e) · [LICENSE](https://raw.githubusercontent.com/actions/setup-go/b7ad1dad31e06c5925ef5d2fc7ad053ef454303e/LICENSE) |
| `actions/upload-artifact` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | MIT — `Copyright (c) 2018 GitHub, Inc. and contributors` | [commit](https://github.com/actions/upload-artifact/commit/cf430e030ddbb5b0abf93d22962f4752f3646cd9) · [LICENSE](https://raw.githubusercontent.com/actions/upload-artifact/cf430e030ddbb5b0abf93d22962f4752f3646cd9/LICENSE) |

## Embedded Preset Wordlist

`internal/assets/wordlists/preset-small.txt` contains 20 generic labels: `www`, `api`, `dev`, `staging`, `mail`, `vpn`, `cdn`, `static`, `docs`, `shop`, `blog`, `sso`, `git`, `ci`, `ns1`, `status`, `intranet`, `assets`, `test`, `old`. This file is embedded by the project code and becomes runtime data in the binary. SHA-256 of the file in the audited commit: `b9812de3832a987c48187c5077e68bc3c8646fe381d3e4d2da9deaf05b6bdc18`.

No upstream wordlist source, copyright, or separate license is recorded for this file. Accordingly, this document makes no claim of third-party origin. The project is licensed under Apache-2.0; see the [project LICENSE](LICENSE). This project-level license statement does not attribute the data to an external source.

## Binary Distribution

CI binary packages will include this notice file alongside the binary and its checksum file (`SHA256SUMS`).

The project is licensed under Apache-2.0, as stated in [`LICENSE`](LICENSE). The upstream links above allow readers to inspect the audited refs and license files.
