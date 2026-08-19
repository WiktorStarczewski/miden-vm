---
title: "16-bit Range Checks"
sidebar_position: 4
---

# 16-bit range checks

Miden VM proves that selected field elements are 16-bit integers through a typed LogUp relation.
There is no separate range-checker execution-trace component. The table side is part of the fixed
byte-pair lookup AIR that also supports byte AND and the byte rotations used by BlakeG.

## Fixed byte-pair table

`And8LookupAir` has exactly $2^{16}$ rows. Its preprocessed columns enumerate every pair
$(a,b) \in [0,255]^2$ in row order

$$
r = 256a + b.
$$

The same row provides $a \mathbin{\&} b$ and the position-specific BlakeG rotation
contributions. For range checking, the row represents the 16-bit value $v = 256a + b$.

The main trace contains one dynamic range multiplicity $m_v$ for every fixed row. A request to
range-check a field element $x$ removes a `RangeCheck(x)` message from the relation. The fixed
table inserts `RangeCheck(v)` with multiplicity $m_v$. With challenge reduction $R(x)$, the
relation closes only when

$$
\sum_{v=0}^{65535} \frac{m_v}{R(v)}
- \sum_{x \in requests} \frac{1}{R(x)} = 0.
$$

Because the fixed table contains no value outside $[0,65535]$, a request for any other field
element cannot be matched. Multiplicities allow any table value to be requested repeatedly
without adding bridge rows or extending a VM trace.

## Request sources

Range-check requests currently come from:

- operand-stack `u32` operations, which range-check their 16-bit helper limbs;
- the memory chiplet, which range-checks sorted-access deltas and address limbs; and
- the BlakeG compression AIR, which range-checks fused message/output limbs.

The trace builder collects these counts deterministically and writes them into the range
multiplicity column of `And8LookupAir`. The relation uses its own bus identifier, so range-check
messages cannot cancel byte-AND or BlakeG-rotation messages even though they share the same fixed
rows.

## Cost and topology

The table height is always $2^{16}$ and is independent of VM program length. Its eleven
preprocessed columns are commitment-cached, while its ten main columns contain only dynamic
multiplicities. This fixed AIR replaces the former variable-height, bridge-row range-checker and
also supplies the byte operations required by the native BlakeG compression AIR.
