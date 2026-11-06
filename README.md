# Vulnerability Management Home Lab

A home lab I built to practice the full vulnerability management cycle: scanning, triage, remediation, and checking that the fix actually worked. It runs on my MacBook (Apple Silicon) using UTM, with two scanners and two very different targets.

The prioritization script I wrote for this lab is in a separate repo: [rbvm-engine](https://github.com/jordanbain123/rbvm-engine).

## Lab setup

| VM | Role | Notes |
|---|---|---|
| Kali Linux (ARM64) | Scanner | Nessus Essentials and OpenVAS (Greenbone Community Edition) |
| Windows 11 Pro (ARM64) | Hardened target | Fully patched, Defender on |
| Metasploitable 2 (x86) | Deliberately vulnerable target | Ubuntu 8.04, emulated on ARM |

All three sit on UTM's shared virtual network, which isn't reachable from outside my Mac. Metasploitable never goes on a bridged network.

Metasploitable 2 is an Intel image, so it runs under emulation instead of virtualization. Getting it to boot meant converting the disk to qcow2 and picking hardware a 2008 kernel recognizes: an i440FX machine, an IDE disk, and an e1000 network card.

## Windows 11: one finding, fixed and verified

| Scan | Auth | Findings | Scored |
|---|---|---|---|
| Uncredentialed | Fail | 2 (Info) | 0 |
| Credentialed | Pass | 30 | 1 |
| Credentialed, after fix | Pass | 29 | 0 |

Credentialed scanning on a standalone Windows machine took more setup than I expected: a local admin account, Remote Registry set to Automatic, File and Printer Sharing allowed through the firewall, the network profile set to Private, and `LocalAccountTokenFilterPolicy = 1`. That last one matters because Windows gives local admins a filtered token over the network, so the scanner can log in and still be blocked from reading the registry.

The one real finding was CVE-2013-3900 (WinVerifyTrust signature validation). Microsoft's fix is an opt-in registry setting, so this was a missing configuration rather than a missing patch.

- CVSS 8.8, EPSS about 45%, and on CISA's KEV list
- CVSS and EPSS alone would have put it in my Tier 2 (14 days). The KEV listing made it Tier 1 (24-48 hours).
- Fix: set `EnableCertPaddingCheck = 1` under both `HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config` and the `Wow6432Node` path for 32-bit software
- An interrupted command skipped one of the two keys. I only caught it because I checked both before rebooting.
- The rescan dropped from 30 findings to 29, with nothing left above Info.

## Metasploitable 2: credentialed vs. uncredentialed (Nessus)

| Scan | Auth | Critical | High | Medium | Low | Scored |
|---|---|---|---|---|---|---|
| Uncredentialed | Fail | 10 | 7 | 26 | 9 | 52 |
| Credentialed (SSH + sudo) | Pass | 28 | 95 | 141 | 18 | 282 |

Same host, same scan template. The only change was giving Nessus an SSH login, and the scored findings went up more than five times. About 80% of the risk on this host was invisible from the network.

The credentialed scan produced 68 remediation actions in Nessus. One kernel update covered 234 findings by itself. Most of the list traces back to the OS, which has been out of support since 2013 (see the [risk acceptance memo](RISK_ACCEPTANCE_ubuntu-8.04.md)).

To SSH in at all, I had to allow old algorithms on my own client:

```bash
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa msfadmin@<target>
```

### Triage of the Criticals and Highs (uncredentialed scan)

| Finding | CVSS | EPSS | Root cause | Fix | Tier |
|---|---|---|---|---|---|
| Bind shell backdoor (1524) | 9.8 | - | Planted backdoor | Remove the service / rebuild | 1 |
| VNC password "password" | 10.0 | - | Weak config | Strong password | 1 |
| Ubuntu 8.04 end of life | 10.0 | - | Unsupported OS | Upgrade, or isolate + exception | 1 |
| SSL v2/v3 (POODLE) | 9.8 | ~1.0 | Outdated crypto | Disable old protocols | 1 |
| Debian OpenSSL RNG | 10.0 | 0.71 | Predictable keys | Regenerate keys / rebuild | 2 |
| NFS share `/` world-readable | 7.5 | - | Weak config | Restrict exports | 2-3 |
| Samba Badlock | 7.5 | 0.37 | Outdated software | Upgrade Samba | 3 |
| rsh / rlogin | 7.5 | 0.12 | Cleartext legacy services | Turn off, use SSH | 3 |

Four of these have no CVE at all, so EPSS and KEV can't help with them. I tiered those on what an attacker can actually do. Three Criticals also needed three different kinds of fix (remove a backdoor, change a setting, replace the OS), which is a good reminder that "Critical" doesn't tell you what the fix is.

I first put POODLE in Tier 2, because Nessus grouped it into a plugin with no EPSS score. My script later looked up the CVE directly and found an EPSS near 100%.

## Adding a second scanner: OpenVAS

I added OpenVAS because Nessus Essentials can't export results and its license has to be renewed about every 30 days. OpenVAS exports CSV, which my script reads.

| Run | Conditions | Duration | Errors | Critical / High / Medium / Low | Results |
|---|---|---|---|---|---|
| 1 | Kali on DHCP, lease dropping | 17:44 h | 62 timeouts | 11 / 6 / 21 / 3 | 41 |
| 2 | Static IP, 2 tests at a time | 1:15 h | 3 | 13 / 11 / 40 / 6 | 70 |

(Results are filtered to OpenVAS's Quality of Detection of 70% or higher.)

The first run said "Done," but 62 tests had timed out because Kali kept losing its network while the VM was paused. The tests that timed out were detection tests (SSL/TLS, PostgreSQL, SMTP), so the vulnerability checks that depend on them never ran. Roughly 40% of the findings were missing and nothing in the report said so. An even earlier run finished in 2 minutes with zero hosts scanned, for the same reason. I fixed it by giving Kali a static IP and limiting OpenVAS to 2 concurrent tests against the slow emulated target.

Run 2 was meant to be credentialed, but SSH authentication failed. The scanner log showed why:

```
Failed to set SSH key type 'ssh-dss': no allowed algorithm for method "server host key algo"
```

OpenVAS's SSH library won't use Metasploitable's DSA host key. Nessus could log in, so Nessus stays my credentialed source. I think this is the most realistic lesson in the lab: the oldest systems are often the ones a modern scanner can't authenticate to, so the riskiest machines end up with the shallowest scans.

Run 2 also changed three things at once (network, throttle, credentials), so I can't say how much of the jump from 41 to 70 came from each. Next time I'd change one variable at a time.

### What the two scanners found

Both found the VNC default password, the Ubuntu end-of-life issue, rlogin/rsh, the Ingreslock bind shell and SSL v2/v3.

OpenVAS confirmed several issues with active checks, meaning it exploited them instead of just reading a version number: the vsftpd 2.3.4 backdoor, Tomcat Ghostcat (CVE-2020-1938, on KEV), PHP-CGI argument injection (CVE-2012-1823, on KEV), DistCC remote code execution, MySQL root with no password, dRuby code execution, and the Samba usermap_script bug. That last one is rated Medium (6.0) even though OpenVAS made the target run a command, which is a good example of CVSS understating real risk.

Nessus's credentialed scan also reported vsftpd, Ghostcat, MySQL and the Samba bug. It didn't report DistCC, dRuby or PHP-CGI, even though OpenVAS proved code execution on all three and PHP-CGI is on CISA's KEV list. In the other direction, Nessus found the Debian OpenSSL RNG weakness, which OpenVAS didn't report.

So neither scanner caught everything, even on a host this broken. That's the main argument for running more than one.

## Prioritizing with my own script

[rbvm-engine](https://github.com/jordanbain123/rbvm-engine) reads the OpenVAS export, looks up EPSS and CISA KEV for every CVE, applies my tier rules, and groups findings that share a fix.

On the 70 OpenVAS findings it produced 45 fixes, and the 19 Tier 1 findings came down to 9 Tier 1 fixes. One TLS configuration change closed 20 findings on its own.

The first automated run also showed a limit of EPSS. Old TLS bugs with EPSS scores near 100% filled most of Tier 1, while a backdoor that gives anyone a root shell landed in Tier 3 because it has no CVE. I added manual overrides, each with a reason and a review date, so findings like that get the tier they deserve.

## Troubleshooting along the way

- Nessus wouldn't start after I closed the VM without shutting it down. The log said another instance was running, but the PID in the lock file belonged to an unrelated kernel process. Deleting the stale `nessusd.pid` fixed it, and I now shut VMs down from inside the guest.
- The OpenVAS web login kept saying "Could not connect to server" even though the password was right. I tested each layer separately: the manager answered `gvm-cli`, the web server answered `curl`, and browser DevTools showed the login request getting a 404. The web interface and web server packages were mismatched versions. Upgrading the GVM stack and migrating its database fixed it.
- Kali repeatedly lost its IP address after the VM was paused. `ping` to an IP failing before any packet left the machine pointed to a missing route, and `ip route` confirmed it. A static IP stopped it for good.

## What's next

- Build an Active Directory domain controller and scan a more realistic Windows environment
