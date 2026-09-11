# Example East-West Traffic Assessment

> Illustrative output based entirely on synthetic flow metadata.

## Executive summary
The synthetic dataset highlights three useful segmentation-review scenarios: a user workstation directly reaching a database listener, the same workstation reaching multiple internal systems over administrative service ports, and a separate workstation performing a large unapproved transfer to a server-zone asset. Approved application and backup traffic is retained as a benign reference.

## Priority actions
1. Validate the WS-101 management and database paths against an approved application/administration flow matrix.
2. Restrict remote-administration services to approved management sources.
3. Enforce application-tier mediation for user-to-database access where required by architecture.
4. Validate the WS-205 bulk transfer and data classification before deciding whether to block, approve or redesign the path.
5. Re-test legitimate application and backup flows after segmentation changes.

## Assurance principle
Segmentation changes are not complete until both negative and positive tests succeed: the undesired path is blocked while approved business traffic continues to function.
