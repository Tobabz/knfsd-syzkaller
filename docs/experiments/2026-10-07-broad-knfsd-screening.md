# broad-knfsd 30-minute screening

Date: 2026-10-07

This is an experimental screening record, not a promotion decision. The
fixture exposed knfsd NFSv3, v4.0, v4.1, and v4.2 mounts for both clients in
each of four lanes. Ganesha was deliberately excluded from the selected
corpus and exposed profile mounts.

## Inputs and configuration

- The initial `corpus.db` contained the 11 canonical knfsd mutation seeds
  selected by `--fixture broad-knfsd`.
- `syz-manager` also generated 26 startup programs, so it initially reported
  37 programs.
- The enabled set contained 55 focused NFS/file syscalls, including the
  versioned `syz_open_nfs_lane_profile` variants.
- Four fuzzer processes ran with remote coverage enabled.
- The initial database was deterministic across two builds, with SHA-256
  `aa9ccd346bd89cc7747186f3a58916f35a16cb5026be0ab5215fd69a979a1a03`.

## Result

The first VM segment ran for 29 minutes 16.8 seconds. Its last periodic sample
reported 56,170 executions, 31 executions/second, 223 corpus programs, 22,161
coverage units, and no pending or active reproductions. A resumed segment ran
for 56.9 seconds, bringing actual VM fuzz time to 30 minutes 13.7 seconds. Its
last periodic sample reported 2,076 executions, 22 executions/second, 180
corpus programs, 21,930 coverage units, and no pending or active
reproductions. Coverage values are per manager run and are not additive.

The final minimized database passed `syz-db bench` and contained 231 programs:

| Retained property | Programs |
| --- | ---: |
| Any versioned profile open | 185 |
| `knfsd-v3` | 34 |
| `knfsd-v40` | 83 |
| `knfsd-v41` | 31 |
| `knfsd-v42` | 37 |
| Raw `syz_socket_connect_nfs` | 18 |

The manager HTTP status reported zero crash types, crashes, suppressed crashes,
and reproductions during the first segment, and no crash artifact directory was
created. The shared qcow2 SHA-256 remained
`109e8f0212ddf5cc3aee3c4bd202cea4b5aad8c08319f1e6db092bfa345e4ea7`,
confirming that QEMU snapshot protection prevented base-image writes.

## Decision

All four knfsd profiles remained reachable under mutation, so the broad fixture
is viable for further comparison. It remains experimental: this run did not
compare execution rate, signal growth, timeout rate, or profile balance against
four equally budgeted stable-profile campaigns. There is no automatic
promotion, and stable runs must continue to use a profile-specific corpus.
