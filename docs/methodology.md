# East-West Traffic Analysis Methodology

## Objective
This lab demonstrates defensive analysis of synthetic internal network-flow metadata. It focuses on segmentation assurance and lateral-movement visibility without packet capture, scanning or active probing.

## Pipeline
`synthetic JSON -> schema validation -> normalized Flow -> source-centric correlation -> risk scoring -> ATT&CK context -> remediation/revalidation report`

## Analytics
Current rules identify unapproved access to sensitive zones, administrative-protocol fan-out across several hosts, direct user-zone to database-zone communication, and large internal transfers outside an approved backup path.

## Segmentation assumptions
A finding does not mean the traffic is malicious. It means the observed path conflicts with the synthetic approval context or expected zone boundary. Production use would require authoritative application dependencies, approved flow matrices, service ownership, change windows and baselines.

## ATT&CK context
Mappings include T1021 Remote Services, T1078 Valid Accounts, T1210 Exploitation of Remote Services and T1041 Exfiltration Over C2 Channel for defensive investigation context. ATT&CK labels do not prove compromise or data theft.

## Remediation validation
Each finding specifies how to verify the intended path after change. Controls should be validated from both sides: confirm the unwanted path is blocked and confirm legitimate application/service traffic still works.

## Safety
The repository contains no live scanner, packet capture, exploit automation, credential use, lateral-movement tooling or production targeting.
