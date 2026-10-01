# CVE-2026-53362 Amazon Linux 2023 port

Minimal source-only release of the kernelCTF IPv6 fragmentation exploit port for this exact target:

```text
6.12.92-122.166.amzn2023.x86_64
```

This is destructive security-research code. Use it only on an authorized, disposable test node. A failed run can leave stale kernel references, corrupt memory, or panic the node. Do not use it on production systems.

## Build

Build on x86-64 Amazon Linux 2023 (or a compatible static-build environment):

```sh
make
```

The output is `IPV6_FRAG_ESCAPE_amzn2023_x86_64`. Build products are intentionally ignored by Git.

## Compatibility check

The program has no default physical-memory range. It refuses execution unless explicit ranges are supplied. Run the non-triggering checks first:

```sh
./IPV6_FRAG_ESCAPE_amzn2023_x86_64 \
  --check-only \
  --phys-ranges-file ram-ranges.txt
```

Do not guess ranges or reuse ranges from another machine. Execution must not proceed unless the exact kernel, BTF layout, runtime prerequisites, and complete target RAM ranges all pass.

To see all accepted arguments:

```sh
./IPV6_FRAG_ESCAPE_amzn2023_x86_64 --help
```

## Contents

- `IPV6_FRAG_ESCAPE_amzn2023.c`: target-specific exploit and compatibility gates.
- `btfcheck.c`, `btfcheck.h`: runtime BTF layout validation.
- `Makefile`: static x86-64 build.

No binaries, object files, BTF dumps, target captures, credentials, or nested Git metadata are included.

## Provenance

Based on Google `security-research` kernelCTF PR #410, commit `3321d14796ef8d4dc581b796eb0aa1c4376128a4`, exploit `lts-6.12.85` (Apache-2.0). The port adds exact Amazon Linux release checks, BTF validation, explicit physical-range input, and one-shot/timeout safety gates. The main source file is modified from that upstream version.

The vulnerability is CVE-2026-53362. The upstream Linux fix is commit `736b380e28d0480c7bc3e022f1950f31fe53a7c5`.

## License

Apache License 2.0. See `LICENSE`.
