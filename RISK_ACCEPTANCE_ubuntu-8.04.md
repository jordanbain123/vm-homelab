# Risk Acceptance: Metasploitable 2 running Ubuntu 8.04

| | |
|---|---|
| Asset | Metasploitable 2 VM (lab target) |
| Finding | Operating system past end of life (Ubuntu 8.04, security support ended May 9, 2013) |
| Detected by | Nessus (Canonical Ubuntu Linux SEoL, CVSS 10.0) and OpenVAS (OS End of Life Detection, CVSS 10.0) |
| Risk tier | Tier 1 |
| Decision | Accept with compensating controls |
| Requested by / risk owner | Jordan Bain |
| Date | November 5, 2026 |
| Review by | December 4, 2026 |

## The risk

Ubuntu 8.04 hasn't received security updates in over 13 years. Any vulnerability found in the OS or its bundled software since 2013 stays unpatched, and the patches that do exist are from 2010 to 2013. This single condition is the root cause of most of the host's findings: a credentialed Nessus scan reported 282 scored vulnerabilities, and one kernel update alone covered 234 of them.

The host also has issues no update would fix, including a bind shell backdoor on port 1524, a VNC password of "password," and default database credentials.

## Why it isn't being fixed

Metasploitable 2 is deliberately vulnerable. Its only purpose in this lab is to give the scanners real findings to detect and prioritize, so upgrading or hardening it would defeat that purpose.

In a production environment the usual reason is similar in shape: a legacy application that only runs on the old OS and can't be replaced yet. The controls and review process below are the same ones I'd expect there.

## Compensating controls

- Network isolation: the VM is only on UTM's shared virtual network, which isn't reachable from outside my Mac. It is never put on a bridged network.
- Limited exposure time: the VM is shut down whenever I'm not scanning it.
- No real data or credentials are stored on it, and it has no trust relationship with any other system.
- It's scanned regularly, so any change in its findings shows up.

## Residual risk

Something already on my Mac's virtual network, such as another VM, could still reach it. The only other machines on that network are my Kali scanner and a patched Windows 11 VM. The shared network also gives the VM outbound internet access through NAT, so if it were compromised it could connect out. I consider the remaining risk low for a lab, and blocking outbound access is the next control I'd add.

## Conditions that end this exception

- The VM is moved to a bridged network or exposed outside the Mac
- Any real data or credentials are placed on it
- The review date passes without a new review

At the review, the options are renew, retire the VM, or replace it with a supported target.
