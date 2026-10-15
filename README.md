# TOZED-ZLT-S200
Unauthenticated disclosure of LAN device inventory and network info (/cgi-bin/http.cgi)

**Target:** <REDACTED> 5G Router S200 (TOZED ZLT S200), software 2.1.13, web admin at http://192.168.1.1.
**CWE:** CWE-306 Missing Authentication for Critical Function (also CWE-287 Improper Authentication).

## Summary
The router's web API serves a set of read commands to clients that are not logged in. The API gateway `POST /cgi-bin/http.cgi` takes a JSON body with a `sessionId` field, for this set of commands the value is not validated. The most serious of them is cmd 1000, which returns the full list of connected LAN devices (MAC, IP, IPv6, hostname per client) to an unauthenticated caller, along with Wi-Fi SSIDs, the public WAN IP, and data-usage figures. Confirmed from a browser that never logged in.

Not every command is affected. Command 1001 (device info, which carries the SIM identifiers) rejects an invalid session with `success:false`. So the gap is per-command: some reads enforce the session, others do not.

## Severity
Vector: `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` Score: 4.3 (Medium). Provisional.

Reasoning for each metric, from what I verified:
- AV:A - the admin HTTP interface is on the LAN by default, the attacker needs to reach the router's network (any Wi-Fi client, including guest, or a wired host). If the management interface is also reachable over WAN (see Open items), this becomes AV:N and the score rises.
- AC:L, PR:N, UI:N - a single crafted POST, no credentials, no user interaction.
- C:L - I confirmed disclosure of the connected-device inventory, SSIDs, WAN IP and usage data (see below), which is real PII/recon but not credentials or total compromise. No Wi-Fi passphrase or admin credential was found in the exposed values, so C stays L rather than H.
- I:N, A:N - this finding covers reads only.

## Affected component
`POST /cgi-bin/http.cgi`, the single JSON API endpoint. Confirmed on command codes 1002 and 1003. Protocol is plaintext JSON over HTTP.

## How I verified it
From a browser on the LAN I sent the status read command 1002 three ways and compared the server's response:
```
POST /cgi-bin/http.cgi
{"cmd":1002,"method":"GET","sessionId":"AAAAAAAAAAAAAAAAAAAAAAAA"}  -> success:true, 131 fields
{"cmd":1002,"method":"GET","sessionId":""}                          -> success:true, 131 fields
{"cmd":1002,"method":"GET"}                                         -> success:false, error "Session"
```

Then, in one request batch (same source host, same invalid session), I compared three commands:
```
{"cmd":1001,"method":"GET","sessionId":"INVALID..."} -> success:false   (device info, protected)
{"cmd":1002,"method":"GET","sessionId":"INVALID..."} -> success:true    (WAN/signal)
{"cmd":1003,"method":"GET","sessionId":"INVALID..."} -> success:true, 102 config fields
```

Because 1001 is rejected while 1002 and 1003 are accepted in the same context, the server is genuinely evaluating the session for some commands and skipping it for others. That rules out the alternative explanation that my source IP had an active session the server was honoring.

Scope note: this is not a blanket authentication failure. A write/action command (cmd 168, the ping tool) sent with a bogus session returns `{"success":false,"message":"NO_AUTH"}`, so writes and actions are gated. The gap is a specific set of read commands, 1002, 1003, 1005 and 1008, that the firmware serves before login (the login screen reads device status), and this pre-login set over-discloses. The finding is a pre-authentication information disclosure, not a full session bypass.

A follow-up sweep of the known read commands (run by the owner, invalid session `"x"`) gave the open-vs-protected split:
```
1000 (connected devices) -> OPEN (full LAN client list)
1001 GETDEVICEINFO   -> protected (success:false)
1002 GETWANINFO      -> OPEN, 133 fields
1003 GETGLOBESTATUS  -> OPEN, 104 fields
1004 GETGMULTIAPN    -> protected (success:false)
1005 GETLOOPINFO     -> OPEN, 57 fields
1008 GETINITINFO     -> OPEN, 32 fields
1021 (traffic/usage) -> OPEN
1024 GET_ALL_WAN_STATUS -> protected (success:false)
```

So the device-identity and APN reads are gated, while the status/config reads 1000, 1002, 1003, 1005, 1008 and 1021 are reachable with no valid session.

### Full systematic sweep (2026-10-09)
A later run of `poc/preauth_sweep.py` enumerated every cmd code mapped from the UI JS bundle (137 names) and posted `{"cmd":N,"method":"GET","sessionId":""}` to each. 121 commands correctly rejected the empty session with `no_auth`. Nine returned `success:true`:
```
cmd=97    CHANGE_LANGUAGE               size=39   (current language echo)
cmd=100   LOGIN                         size=69   (expected)
cmd=232   GET_NEXT_LOGIN_TIME           size=108  (admin lockout timer)
cmd=1002  GETWANINFO                    size=2605 (5G cell data: PCI, FREQ, SINR)
cmd=1003  GETGLOBESTATUS                size=2656 (auth types, lang list, state)
cmd=1005  GETLOOPINFO                   size=1163 (WLAN switches, voice type)
cmd=1008  GETINITINFO                   size=770  (logo, language, build)
cmd=1020  NETWORKSET_MODE_ORANGE        size=165  (5G mode, flight, roaming)
cmd=1021  TRAFFIC_LIMIT_SETTING_ORANGE  size=707  (data quota config)
```

Two of these pre-auth reads add new attack value beyond the first list:
- **cmd 232 GET_NEXT_LOGIN_TIME** leaks the admin-side lockout timer to a caller with no session. An attacker on the LAN who is brute-forcing admin can poll this read to time their retries exactly against the server-side lockout window, so the 24-hour lockout no longer slows them in a quiet background attack.
- **cmd 1020 NETWORKSET_MODE_ORANGE** returns configuration fields, not just status: `networkMode`, `mode5g`, `flightMode`, `dialMode`, `roamingEnable`, `checkbox`. This is Orange-provisioned network config reachable before login.

The 121 cmds that correctly rejected the empty session include every known destructive SET target (cmd 272 VPN_CONFIG, cmd 533 NETPORT_PACKET_CAPTURE, cmd 168 NETWORK_TOOLS, cmd 239 UPGRADE_IMMEDIATELY), so the gap is strictly on reads, not writes.

## Independent confirmation from a never-authenticated client
I loaded the router in a separate, fresh browser that had never logged in. It showed the login modal ("Feature only available to administrator"), and while sitting on that modal the app made 13 `POST /cgi-bin/http.cgi` calls that all returned 200 OK with real data. That removes any doubt about a session tied to my address: this browser has no session at all and still receives data. I read the actual response bodies (the app's own pre-login calls, observed passively). What comes back without authentication:
- cmd 1000: the full connected-device list. For every LAN client: MAC address, IP, IPv6, hostname (device names such as "iPhone" and a webOS TV were visible), plus per-client Wi-Fi signal strength and tx/rx rates, and total upload/download usage.
- cmd 1003: Wi-Fi SSIDs for all four networks including the guest SSID, LAN IP, account_level, network mode, SIM lock state (pin/puk left times), PLMN.
- cmd 1005: the public WAN IP, Wi-Fi on/off state, SIM status, operator, battery, wired-link list.
- cmd 1008: board type, firmware version (2.1.13), PLMN, area ID, a domain_value hash.
- cmd 1021: data-usage counters and traffic-limit settings.

Correction to an earlier assumption: `device_msisdn` is present as a field name but its value is empty in these responses, so the subscriber phone number does not actually leak. No plaintext Wi-Fi passphrase or admin password hash appears in the values either. The real exposure is the connected-device inventory, the Wi-Fi SSIDs, the public WAN IP, and the data-usage figures.

The 102 fields returned by 1003 under an invalid session include, by field name: network mode, LAN IP, firewall switch state, Wi-Fi enabled and SSID-broadcast flags for both bands, IP-passthrough state, mesh state, parental-control state, account_level, and the pending-password flags need_change_root_pwd / need_change_user_pwd / need_change_wifi_info. I recorded field names only, I did not collect the values, and no SIM identifier or passphrase appeared among the 1003 field names.

## Impact
An unauthenticated party on the router's network can enumerate the whole LAN. The connected-device list (cmd 1000) gives every client's MAC, IP, IPv6 and hostname, so an attacker learns exactly what devices are on the network (phones, TV, laptops) and can track them by MAC and name. Combined with the Wi-Fi SSIDs, public WAN IP, and data-usage counters, this is a strong reconnaissance and privacy exposure for anyone who reaches the web port, including a guest-network client. No credentials or passphrases are exposed, so this is confidentiality-only, but the device inventory makes it more than a trivial status leak. The full set of unauthenticated-reachable commands is not fully mapped, so the confidentiality impact is a floor, not a ceiling.

This finding covers reads only. Writes and actions are not affected: cmd 168 (ping) returns NO_AUTH with a bogus session, so the session is enforced for write/action commands. Severity stays at confidentiality-only.

The pre-auth exposure of cmd 232 GET_NEXT_LOGIN_TIME is worth calling out separately: it tells an unauthenticated LAN attacker exactly when the admin lockout window ends. Combined with cleartext HTTP on the login endpoint, this makes slow background brute force practical by removing the uncertainty about when a retry will be accepted.
