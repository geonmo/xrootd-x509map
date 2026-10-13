# xrootd-x509map — GSI/VOMS local and pool account mapping plugins

> 한국어: [README.ko.md](README.ko.md)

Two XRootD plugins that map X509/VOMS users to Unix accounts, so that
[xrootd-multiuser](https://github.com/opensciencegrid/xrootd-multiuser) writes
files with the user's own uid (site users) or with a pool account chosen by
VOMS role (everyone else). They work for xroot and HTTPS, and coexist with
SciTokens and Macaroons, so a site can serve X509 and token users at the same
time and move users to tokens step by step.

Tested with XRootD 5.9 and xrootd-multiuser 2.2 on EL9 (Lustre back end).

| Library | Directive | Role |
|---|---|---|
| `libXrdAccX509Map-5.so` | `ofs.authlib ++` | **Enforcement point**. Shared by xroot and HTTPS. Maps the account on every request and sets `request.name`. Denies the request if no rule matches |
| `libXrdSecEntityX509Map-5.so` | `sec.entitylib` | Replaces `name` with the mapped account right after xroot login (for logging and monitoring). **Never denies a login** |

---

## 1. Overview

### What it does

```
X509 request (xroot gsi / HTTPS certificate)
  │
  ├─ 1. gridmap exception: name mapped by gsi -gridmap or http.gridmap (gridmap.name=1)
  │      → that account if account validation passes (on failure, warn and go to 2)
  │      ※ the sample configuration uses no grid-mapfile, so this step never applies
  ├─ 2. Local DN map (localmap=): exact / glob / regex, first match wins
  │      → rules whose account fails validation are skipped and the next rule is tried
  ├─ 3. VOMS map (vomsmap=): FQANs in VOMS order (primary first), first match wins
  └─ 4. Deny (XrdAccPriv_None)
```

"Account validation" requires all of the following:
- The name consists only of `[A-Za-z0-9_.@-]` characters and does not start with `-`
- The account exists according to `getpwnam_r`
- `uid >= minuid`, `gid >= mingid`

Requests that carry a valid SciToken or macaroon are decided before this
plugin (see 3.4); requests without any X509 identity are left to the authdb.

### Why plugins instead of the gsi hooks

- **The built-in gsi hooks cannot be chained.** `-gmapfun`/`-vomsfun`/`-authzfun` each accept only one library, and the call order is fixed: gridmap → VOMS → authz. So you cannot build combinations such as "local users get their own account, everyone else gets a pool account per VOMS role".
- **`-authzfun` (for example `libXrdSecgsiAUTHZVO.so`) stores its result in a key cache.** On a cache hit, only the string fields are restored. The extended attributes (`gridmap.name`, `request.name`) are lost, so from the second connection on, the same user may be treated as "not mapped" by multiuser.
- **gsi hooks only cover xroot.** HTTPS needs the same mapping; an authorization plugin sees both protocols.
- **Fail-closed with multiuser.** xrootd-multiuser checks `request.name` first and falls back to `name`. If a gsi client has neither `vorg` nor `gridmap.name=1`, multiuser **treats it as anonymous and runs with the daemon uid**. This plugin always sets `request.name` when mapping succeeds, and denies the request at the OFS stage when it fails, so an X509 client never reaches multiuser unmapped.

---

## 2. Installation

### Build dependencies (EL9)

```bash
dnf install cmake gcc-c++ xrootd-server-devel gtest-devel   # xrootd-server-devel must be 5.x, 5.4 or later
```

Even if an XRootD of a different major version is also installed (for example in `/usr/local`), the build looks for `/usr/include/xrootd` (5.x) first.
To use a 5.x installation in another location, set `-DXROOTD_DIR=/opt/xrootd`.
If the version is not 5.x, or is older than 5.4, cmake stops with an error.

### Building from source

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build                 # unit tests
sudo cmake --install build             # installs the files listed below
```

### Building the RPM

```bash
mkdir -p ~/rpmbuild/SOURCES
git archive --prefix=xrootd-x509map-1.0.0/ -o ~/rpmbuild/SOURCES/xrootd-x509map-1.0.0.tar.gz HEAD
rpmbuild -ba rpm/xrootd-x509map.spec       # unit tests run in %check
dnf install ~/rpmbuild/RPMS/x86_64/xrootd-x509map-1.0.0-1.*.x86_64.rpm
```

The RPM requires `xrootd-server` 5.x (≥ 5.4) and `xrootd-voms`, and recommends `xrootd-multiuser`.

### Installed files

| Path | Content |
|---|---|
| `/usr/lib64/libXrdSecEntityX509Map-5.so` | `sec.entitylib` plugin |
| `/usr/lib64/libXrdAccX509Map-5.so` | `ofs.authlib ++` plugin |
| `/etc/xrootd/x509map-local.map` | Local DN map, examples only (`%config(noreplace)`) |
| `/etc/xrootd/x509map-voms.map` | VOMS map for CMS (`%config(noreplace)`) |
| `/etc/xrootd/x509map-authdb` | Example authdb (`%config(noreplace)`) |
| `/etc/xrootd/xrootd-multiuser-x509map.cfg` | Complete sample server configuration (`%config(noreplace)`, chapter 3) |
| `/usr/share/doc/xrootd-x509map/` | This document (English and Korean) |

In the configuration you can omit `-5` and write `libXrdAccX509Map.so`. XRootD appends the `-5` suffix automatically when it looks for the library.

---

## 3. Setting up a server

### 3.1 Prerequisites

| Item | Notes |
|---|---|
| Packages | `xrootd-server`, `xrootd-voms`, `xrootd-multiuser`, `xrootd-scitokens` (for tokens), this package |
| Host certificate | `/etc/grid-security/hostcert.pem`/`hostkey.pem` for gsi, and a copy readable by the xrootd user for TLS/HTTPS (the sample uses `/etc/grid-security/xrd/xrdcert.pem`/`xrdkey.pem`) |
| CA certificates and CRLs | `/etc/grid-security/certificates` (e.g. IGTF distribution + fetch-crl) |
| VOMS trust | `/etc/grid-security/vomsdir/<vo>/*.lsc` for every VO you map (e.g. the OSG `vo-client` package) |
| Accounts | Site users and pool accounts (e.g. `cms`, `cmsprod`, `cmspilot`) resolvable through passwd/sssd, with uid/gid ≥ `minuid`/`mingid` |
| Macaroon secret | `openssl rand -base64 -out /etc/xrootd/macaroon-secret 64`, owner `xrootd`, mode `0600` |
| SciTokens | `/etc/xrootd/scitokens.cfg` with your issuers (see the XrdSciTokens documentation) |

### 3.2 Configuration files

Start from the sample configuration `/etc/xrootd/xrootd-multiuser-x509map.cfg`
(source: `configs/xrootd-multiuser-x509map.sample.cfg`). Lines to adapt are
marked `SITE:` — at least `all.sitename` (example value `T3_XX_Example`), the
exported path, ports, certificate paths, and the cmsd/redirector block.

Mapping information lives in two files, both read by the plugins:

| File | Content |
|---|---|
| `localmap=/etc/xrootd/x509map-local.map` | Site users mapped to their own accounts by DN. `"DN" account` lines use the grid-mapfile format (one account per line), and glob/regex rules are available (chapter 5.1) |
| `vomsmap=/etc/xrootd/x509map-voms.map` | Everyone else, mapped to pool accounts by VOMS FQAN, in voms-mapfile syntax (chapter 5.2). An existing `/etc/grid-security/voms-mapfile` can be used directly instead |

Both files **must be readable by the xrootd user**, because the plugins re-read them with xrootd privileges while the server runs.

Finally, adapt `/etc/xrootd/x509map-authdb` to your namespace (chapter 3.6) and start the server:

```bash
systemctl enable --now xrootd-privileged@multiuser-x509map
systemctl enable --now cmsd-privileged@multiuser-x509map    # only if you run a cmsd
```

xrootd-multiuser requires the `*-privileged@` units. Logs go to `/var/log/xrootd/multiuser-x509map/`.

The x509map-related parts of the sample, collected together:

```
# --- gsi ---------------------------------------------------------------------
sec.protparm gsi -vomsfun:libXrdSecgsiVOMS.so -vomsfunparms:dbg
sec.protocol /usr/lib64 gsi -cert:/etc/grid-security/hostcert.pem -key:/etc/grid-security/hostkey.pem \
    -dlgpxy:1 -exppxy:=creds -ca:1 -crl:3 \
    -gmapopt:10 -moninfo

if exec xrootd
    sec.protocol ztn
    sec.entitylib /usr/lib64/libXrdSecEntityX509Map.so localmap=/etc/xrootd/x509map-local.map vomsmap=/etc/xrootd/x509map-voms.map minuid=1000 mingid=1000 cacheto=600
    ...
    http.secxtractor libXrdVoms.so
    http.header2cgi Authorization authz
    http.exthandler xrdmacaroons libXrdMacaroons.so
fi

ofs.authorize
acc.authdb /etc/xrootd/x509map-authdb
ofs.authlib ++ /usr/lib64/libXrdAccX509Map.so localmap=/etc/xrootd/x509map-local.map vomsmap=/etc/xrootd/x509map-voms.map minuid=1000 mingid=1000 cacheto=600
ofs.authlib ++ libXrdMacaroons.so
ofs.authlib ++ libXrdAccSciTokens.so config=/etc/xrootd/scitokens.cfg
ofs.osslib ++ libXrdMultiuser.so
multiuser.minuid 1000
multiuser.mingid 1000
```

### 3.3 `sec.protocol gsi`

| Setting | | Reason |
|---|---|---|
| `-vomsfun:libXrdSecgsiVOMS.so` | **Required** | Extracts VOMS attributes. `endorsements` receives all FQANs, joined with commas. |
| `-gmapopt:10` | **Recommended** | 0 = do not use a grid-mapfile (nomap), +10 = put the DN in `name` instead of a hash. Every DN with a valid certificate can log in, and x509map decides per request. |
| `-moninfo` | Recommended | Also stores the DN in `moninfo`. The plugins can then find the DN even after `name` has been changed. |
| `grpopt=usefirst` in `-vomsfunparms:` | **Do not set** | With `usefirst`, `endorsements` receives only the first FQAN. A proxy with primary `/cms` and secondary `/cms/Role=production` could then not be mapped by its role. Keep the default, `useall`. |
| `-gmapopt:usemap` (2) | **Do not use** | DNs that are not in the grid-mapfile fail at login, so the local map, the VOMS map and tokens never get a chance to apply. |
| `-gridmap:` | **Not needed** | For a DN mapped by a gridmap, x509map uses that account as it is and skips both maps. Everything a gridmap can express ("this DN always gets this account") can be written in `x509map-local.map`, which is applied before the VOMS map. If you must keep a grid-mapfile, use `-gmapopt:11` (trymap) and list only exceptions in it — a grid-mapfile that maps all VO members to one account hides every VOMS role mapping. |
| `-authzfun:` | **Do not use** | `libXrdSecgsiAUTHZVO.so` overwrites `name` with the VO name, and extended attributes are lost on a cache hit (see chapter 1). |

### 3.4 `ofs.authlib ++` ordering rules

`ofs.authlib ++` wraps the authorizer from the previous line. **The last line is the outermost, so it is called first.**

```
ofs.authlib ++ libXrdAccX509Map.so …       # 1st line = innermost (directly above authdb)
ofs.authlib ++ libXrdMacaroons.so          # 2nd
ofs.authlib ++ libXrdAccSciTokens.so …     # last line = outermost = called first
```

The call order is **SciTokens → Macaroons → x509map → authdb**.
- If there is a valid SciToken or macaroon, the outer plugin grants access right there. The request never reaches x509map.
- If there is no token, or the token is invalid, the request goes down the chain to x509map. x509map maps the X509 identity or denies. In other words, an invalid token naturally falls back to X509.

Symptoms of a wrong order:

| Wrong placement | Symptom |
|---|---|
| x509map on the last line (outermost) | Clients that send both a certificate and a valid token (HTTP-TPC, certificate + Bearer) are handled as the X509 account, not the token account. A certificate without a mapping is **denied** even with a valid token |
| `ofs.authlib libXrdAccX509Map.so` without `++` | Startup fails: `libXrdAccX509Map must be stacked with 'ofs.authlib ++'` |
| `ofs.authorize` missing | No authlib is called at all → no mapping → multiuser treats gsi users as anonymous |

### 3.5 `sec.entitylib` (optional, recommended)

- Called once, right after xroot gsi login. When mapping succeeds, it sets `name`, `request.name` and `gridmap.name=1`. The account name then appears in logs, monitoring, `acc.audit` and macaroon issuance.
- **It never denies a login.** An unmapped client may still send a token with each request (`authz` CGI). Denial happens only in the authlib.
- It keeps the original DN and the gridmap result in the `x509map.dn` and `x509map.gridmap` attributes. This lets the authlib recompute the mapping on every request.
- **Always place it inside `if exec xrootd`.** cmsd reads the same configuration file and also calls `sec.entitylib`.
- Configure it **together with `ofs.authlib ++ libXrdAccX509Map.so`, using the same options**. This plugin alone cannot enforce the mapping. Conversely, with only the authlib, xroot requests work correctly, but the raw DN shows up as `name` in the logs.

### 3.6 authdb

The authdb still decides which paths an account may use; x509map only chooses the account.

- authdb `u <name>` rules check `request.name` first (`XrdAccAccess.cc`). So rules such as `u cmsprod …` and `u = /xrd/store/user/@=/ …` work on the mapped account. `g /cms` rules keep working on the VOMS groups (`grps`).
- **Do not add `u *` with write privileges.** It also matches HTTPS clients without a certificate, which xrootd-multiuser runs as the daemon uid.

### 3.7 HTTPS

- `sec.entitylib` is not called for HTTP, so **the authlib handles everything**.
- If `http.secxtractor libXrdVoms.so` extracts VOMS attributes successfully, `prot="gsi"`. If extraction fails or there is no VOMS, `prot="https"`. The DN is always put in `moninfo`, and `name` holds the subject hash (or the `http.gridmap` result). The plugin handles both `gsi` and `https`.
- **HTTPS without a certificate** (token-only clients, macaroon TPC, and so on) is passed through by x509map, and authdb decides.
- **Do not configure `http.gridmap`**, for the same reason as the gsi `-gridmap`. If you do, DNs mapped there (`gridmap.name=1`) become the first-priority exception.
- Keep `http.header2cgi Authorization authz`. SciTokens/Macaroons need it to read HTTP Bearer tokens.
- **Macaroon issuance** (`http.exthandler xrdmacaroons`): the `name:` caveat of a macaroon is built from `SecEntity.name`. x509map also replaces `name` with the mapped account on HTTP requests. So a macaroon obtained with a certificate and then used without a certificate still runs under the same account in multiuser. This always applies for HTTPS (`prot=https`). For HTTPS with VOMS (`prot=gsi`), it applies only when `sec.entitylib` is also configured, because the plugin uses a marker left by `sec.entitylib` to tell xroot and HTTP entities apart.

### 3.8 Relationship with xrootd-multiuser

- When mapping succeeds, the authlib sets `request.name=<account>` **on every request**. multiuser uses this value first and calls `setfsuid`. `XrdOfs::rename` clears `request.name` after the first permission check, and x509map sets it again on the next check (cache hit).
- On xroot, `sec.entitylib` also sets `gridmap.name=1`. So local users without VOMS also pass multiuser's `IsGsiUserMapped`.
- **Set `minuid=`/`mingid=` to the same values** as `multiuser.minuid`/`multiuser.mingid` (multiuser default 500). If the plugin allows a request and multiuser then denies it, the cause is hard to see from the client side.

---

## 4. Plugin option reference

Both directives (`sec.entitylib`, `ofs.authlib ++`) take the same options. Options are separated by spaces. An unknown option causes startup to fail.

| Option | Default | Allowed range | Meaning |
|---|---|---|---|
| `localmap=<path>` | (none) | Absolute path | Local DN map file. At least one of `localmap` and `vomsmap` is required |
| `vomsmap=<path>` | (none) | Absolute path | VOMS map file (voms-mapfile syntax) |
| `minuid=<n>` | `500` | 0 – 2³¹-1 | If the uid of the mapped account is lower than this, the rule is treated as invalid |
| `mingid=<n>` | `500` | 0 – 2³¹-1 | The same rule, applied to the primary gid |
| `cacheto=<sec>` | `600` | 0 – 86400 | Cache TTL for successful mappings and successful passwd lookups. 0 disables caching. 60 or more is recommended to reduce sssd/LDAP load |
| `negcacheto=<sec>` | `60` | 0 – 86400 | Cache TTL for denials and "account does not exist" lookups. A newly created account takes effect within this time. Transient lookup errors are not cached |
| `reloadsec=<sec>` | `30` | 0 – 86400 | Interval for checking map files for changes. 0 disables reloading |
| `debug` (or `debug=1`) | off | — | Writes per-rule matching and fall-through reasons to the Debug log |

- If a map file cannot be opened at startup, **the daemon refuses to start with a configuration error**.
- After startup, every `reloadsec`, the plugin checks `stat()` (inode/size/mtime/ctime) while processing a request. If something changed, it switches to the new rule set (generation increases, mapping cache is invalidated). There is no separate thread.
- If a file cannot be opened during a reload, **the previous rules are kept** and an error is logged.
- It is recommended to replace files atomically with `mv` (rename).
- Each of the two `.so` files has its own mapper instance (cache, reload state). Changes take effect in both within `reloadsec`.

---

## 5. Map file syntax

### 5.1 Local DN map (`localmap=`)

One rule per line. Everything from a `#` outside quotes to the end of the line is a comment. **The first matching rule wins.**

```
"<exact DN>"                  <account>
glob  "<DN glob>"             <account or template>
regex "<ECMAScript regex>"    <account or template>
```

- **exact**: the DN string must match exactly. The DN may contain spaces. This is the grid-mapfile line format (with a single account).
- **glob**: `*` = any string, `?` = any single character, `( … )` = capture group. All other characters are compared literally (including `.`). The pattern must start with `/`, and there must be at least one `/X=` attribute before the first wildcard. So overly broad globs such as `"*…"` and `"(*)"` are rejected.
- **regex**: an ECMAScript regular expression. It is automatically anchored as `^(?: … )$`, so it must match the whole DN.
- **Templates**: `$1`–`$9`, `${n}` = the n-th capture group, `$$` = a literal `$`. `$0` (the whole DN) is not allowed. A reference to a group that does not exist in the pattern makes that line a parse error.
- **Escapes inside quotes**: `\"` `\'` `\/` `\t` `\n` `\r` `\f` `\\`. These rules are the same as in voms-mapfile. On regex lines, other escapes (`\.`, `\d`, and so on) are kept as they are for the regex. On exact/glob lines, other escapes are an error.
- **Validation and fall-through**: if the expanded template is an unsafe name, the account does not exist, or it is below `minuid`/`mingid`, **the plugin moves on to the next rule instead of denying.** If no rule matches by the end, the VOMS map is tried. So non-local users caught by a `CN=(*)` glob (`CN=Jane Doe` → contains a space, `CN=jdoe` → no such account) naturally get mapped through VOMS.
- **Parse errors**: a malformed line is skipped with a `file:line: reason; line ignored` Warning.

Examples:

```
# 1) exact — DN containing spaces
"/DC=org/DC=example/OU=People/CN=12345678 Alice Kim"     alice

# 2) exact — DN containing quotes
"/DC=org/DC=example/CN=Kim \"Robot\" Test"              kimtest

# 3) glob — in the site CA namespace, the CN is the account name
glob  "/DC=org/DC=example/OU=Site/CN=(*)"                 $1

# 4) glob — prefix + capture, ignore the rest
glob  "/DC=org/DC=example/OU=Site/OU=Users/CN=(*)/CN=*"   $1

# 5) regex — robot certificate "CN=Robot: <account>-<anything>"
regex "/DC=org/DC=example/OU=Site/CN=Robot: ([a-z0-9]+)-.*"   $1

# 6) regex — only specific CERN users to local accounts, with a prefix
regex "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=(jdoe|asmith)/CN=[0-9]+/CN=.*"  kr_$1
```

Every successful local match is logged at Info level (`… -> alice (local, local map line N)`), so it can be used for auditing.
Restrict glob/regex rules to the site CA namespace (`/DC=org/DC=example/…`).

### 5.2 VOMS map (`vomsmap=`)

Same syntax as the XRootD `voms-mapfile`. The parser and matcher are ports of `ParseLine`/`Compare` from `XrdVomsMapfile`.

```
"/cms/Role=production/Capability=NULL"  cmsprod
"/cms/Role=pilot/Capability=NULL"       cmspilot
"/cms/*"                                cms
"/alice/*"                              alice
```

- The client's FQANs are tried one by one **in VOMS order (primary first)**. For each FQAN, rules are checked from the top, and **the first match wins.** So put specific Roles above wildcards.
- `*` globbing applies per path element (for example `Role=*`). If the last element is `*`, it matches all deeper groups, Roles and Capabilities.
- **A specific rule does not match a more general FQAN.** For example, `"/cms/uscms/Role=NULL/Capability=NULL"` does not match `/cms/Role=NULL/Capability=NULL`.
- The FQAN format is `/<group…>/Role=<role>/Capability=<cap>`. A missing Role is normalized to `Role=NULL`, and a missing Capability to `Capability=NULL`, before comparison.
- If a rule matches but account validation fails, the next rule is tried.
- Only whitespace and a `#` comment may follow the target account. This is stricter than the original.
- FQAN source: `endorsements` (comma-separated) is used first. If it is missing, FQANs are synthesized by pairing `vorg`/`grps`/`role` word by word. In that case, a group whose first element differs from the VO name is ignored (same as `XrdVomsMapfile::Apply`).

---

## 6. Behaviour rules

### 6.1 DN/FQAN source per protocol

| Connection type | `prot` | DN source | FQAN source | x509map handling |
|---|---|---|---|---|
| xroot gsi + VOMS proxy | `gsi` | `moninfo` (`-moninfo`) or `name` (`-gmapopt:10`/`11`) | `endorsements` | Map or deny |
| xroot gsi, no VOMS | `gsi` | Same as above | None | Only the local map (and a gridmap, if configured) applies, everything else is denied |
| HTTPS + VOMS proxy | `gsi` (secxtractor) | `moninfo` | `endorsements` | Map or deny |
| HTTPS, certificate only | `https` | `moninfo` | None | Only the local map (and a gridmap, if configured) applies, everything else is denied |
| HTTPS, no certificate | `https` | None | — | **Pass through** → authdb decides |
| xroot ztn (token) | `ztn` | — | — | **Pass through** (handled by SciTokens) |
| SciTokens mapping-only entity | `""` | — | — | **Pass through** |
| unix / sss / host | corresponding value | — | — | **Pass through** |

### 6.2 Priority relative to tokens and macaroons

1. Valid SciToken (scope matches) → SciTokens grants access immediately. x509map is not called.
2. Valid macaroon → Macaroons sets `request.name` and grants access immediately. x509map is not called.
3. No token, or an invalid token → x509map maps the X509 identity or denies.
4. No X509 either → authdb decides.

### 6.3 Message the client sees on denial

`XrdAccAuthorize::Access()` in XRootD 5.9 has no interface for returning an error string (it exists from 6.x). So the client only receives a generic permission error.

- xroot: `[3010] Unable to open /xrd/…; permission denied`
- HTTPS: `HTTP 403`

The reason for the denial is recorded in the server log.

```
x509mapacc_Map: map dn=/DC=ch/DC=cern/OU=Users/CN=jdoe fqan=<none> -> DENY (DN not local and no VOMS attributes)
x509mapacc_Access: denying b9d386bb.4:29@host path=/xrd/store/x: x509map: DN not local and no VOMS attributes
```

Denial reasons:

| Reason | Meaning |
|---|---|
| `DN not local and no VOMS attributes` | Not in the local map, and no VOMS attributes (`grid-proxy-init` proxy, plain certificate) |
| `DN not local and no VOMS mapping` | VOMS attributes are present, but no VOMS rule matches, or the accounts of all matching rules are invalid |
| `no subject DN (need -gmapopt:10 or -moninfo)` | The DN cannot be obtained with the current gsi configuration |
| `… (gridmap: account 'x' does not exist)` | The gridmap mapping result was invalid and was ignored (appended at the end) |

---

## 7. Logs and troubleshooting

Log prefixes are `x509mappin_` (entitylib) and `x509mapacc_` (authlib).

```
x509mappin_Config: loaded 12 local / 4 voms rules (generation 1)
x509mapacc_Config: loaded 12 local / 4 voms rules (generation 1)
x509mapacc_Map: map dn=/DC=org/DC=example/OU=Site/CN=Alice Kim fqan=<none> -> alice (local, local map line 1)
x509mapacc_Map: map dn=/DC=ch/…/CN=jdoe fqan=/cms/Role=production/Capability=NULL,/cms/Role=NULL/Capability=NULL -> cmsprod (voms, VOMS map line 1 fqan /cms/Role=production/Capability=NULL)
x509mapacc_Reload: reloaded local map (generation 2): 13 local / 4 voms rules
x509mappin_Process: <tident> unmapped at login, deferring to authlib: DN not local and no VOMS attributes   # debug
x509mapacc_Map: local rule line 3 matched dn=… but account 'jdoe' does not exist; trying next rule      # debug
```

The `Map` Info log is written **only on a cache miss** (once per identity during `cacheto`).
If you also enable `acc.audit deny` (or `deny grant`), the result of the authdb stage is logged as well.

| Symptom | Cause / action |
|---|---|
| Startup fails with `x509mapacc_Config: configuration failed: cannot open local map …` | Typo in the map path, or the xrootd user has no read permission. On SELinux systems, keep the file under `/etc/xrootd` |
| Startup fails with `cannot open local map …` / `cannot open VOMS map …` (Permission denied) | The map file is not readable by xrootd (for example `root:root 0640`) — `chgrp xrootd`, then `0640` |
| Startup fails with `libXrdAccX509Map must be stacked with 'ofs.authlib ++'` | `++` is missing |
| `Unable to load … libXrdAccX509Map-5.so` | The `-5` suffixed file is not in `/usr/lib64`, or the XRootD major version does not match (6.x requires a rebuild) |
| Log shows `-> DENY (… account 'x' does not exist)` | The account in the map does not exist in passwd/sssd/LDAP. Check with `getent passwd x` |
| `uid N < minuid M` | It is a system account, or `minuid` is too high |
| Unknown DNs **fail already at login** | gsi uses `-gmapopt:usemap` (2) — use `-gmapopt:10` |
| Users with a VOMS role are mapped to the generic VO account | The role line is missing or below the `/vo/*` wildcard in the VOMS map; a `-gridmap`/`http.gridmap` maps the DN first (gridmap has first priority); or `grpopt=usefirst` drops the secondary FQAN |
| VOMS users are denied with `no VOMS mapping` although the map is right | The VO's `.lsc` file is missing under `/etc/grid-security/vomsdir`, so no FQANs were extracted (check with debug) |
| x509map denies even though there is a valid token | Wrong `ofs.authlib ++` order — x509map must be the first line |
| multiuser log `Anonymous GSI client; cannot change FS UIDs` | multiuser writes this for requests whose mapping failed. x509map denies the same request, so no file is created. If you see it for a mapped user, check whether `ofs.authorize` is missing |
| Map was edited but the change does not take effect | Wait for `reloadsec`. Denials may remain cached until `negcacheto`. A gsi/HTTP grid-mapfile, if used, is cached by XRootD itself (restart, or `-gmapto`) |
| Mapping succeeds but multiuser denies | `multiuser.minuid/mingid` is greater than the plugin's `minuid/mingid` — make the values match |

---

## 8. Verification procedure

Start the server with the `debug` option on both plugin lines (or `-d`) and check the following.
The examples assume the sample ports (xroot 1094, HTTPS 2880) and the `/xrd` namespace.

1. The startup log shows `x509mappin_Config: loaded N local / M voms rules` and `x509mapacc_Config: …`.
2. Local user: after `voms-proxy-init -voms cms`, `xrdcp f root://host:1094//xrd/store/user/<id>/f` → succeeds, the log shows `-> <account> (local…)`, and `ls -l` on the storage shows the user as owner.
3. Non-local user with `/cms/Role=production` → owner `cmsprod`; with only `-voms cms` → `cms`.
4. Non-local, no VOMS (`grid-proxy-init`) → login succeeds and `xrdcp` must fail with `permission denied`. The log must show `x509map: DN not local and no VOMS attributes`, and no file must be created.
5. HTTPS: repeat 2–4 with `curl --cert $X509_USER_PROXY --key $X509_USER_PROXY --capath /etc/grid-security/certificates -T f https://host:2880/xrd/store/…`. Case 4 must return HTTP 403.
6. Check that the owner is kept after `xrdfs host:1094 mv a b` (rename).
7. Token coexistence:
   - (i) ztn `xrdcp` with `BEARER_TOKEN` → handled as the scitokens account, with no x509map log
   - (ii) `curl -H "Authorization: Bearer …"` without a certificate → same
   - (iii) Valid X509 + invalid token → x509map maps via X509 (fallback)
   - (iv) Obtain a macaroon with a certificate (`curl -X POST -H 'Content-Type: application/macaroon-request' …`), then use it without a certificate → files are created owned by the user's own account
   - (v) Non-local, no VOMS, no token → denied on the first request
8. Add a line to `x509map-local.map` and check that it takes effect after `reloadsec`, without a restart (`reloaded local map (generation N)`).
9. Start with a map path that does not exist, and check that both plugins refuse to start with a clear message.

During development, scenarios 1–6, 7-iii–7-v, 8 and 9 were verified on XRootD 5.9.7 (+ multiuser, SciTokens and Macaroons) with a test CA. The valid SciToken cases (7-i, 7-ii) need a real token issuer.

---

## 9. Limitations / moving to SciTokens

- **Only the authlib applies to HTTP.** `sec.entitylib` is xroot-only. On HTTP, the authlib replaces `name` at request time.
- **The two `.so` files have separate caches.** Map changes take effect in both within `reloadsec`, but the timing may differ by a few seconds.
- **The denial reason is not sent to the client** (5.9 interface limitation). Check the server log.
- **A gridmap mapping has first priority.** If a grid-mapfile is configured, the local map and the VOMS map do not apply to its DNs. The sample configuration uses none.
- **Avoid overly broad rules.** With a rule such as `glob "/DC=org/DC=example/(*)"`, a DN issued by the site CA may accidentally be mapped to an account with the same name.
- **A rebuild is required for XRootD 6.** The plugin symbols are tied to the major version (`-5`). On 6.x, the error-string version of `Access()` can also be implemented.
- **Moving to SciTokens**: XrdSciTokens passes the account to multiuser the same way (`request.name`). So users can be moved to tokens step by step, without changes on the OSS or authdb side. Once no X509 users are left, remove the `ofs.authlib ++ libXrdAccX509Map.so` and `sec.entitylib` lines and the gsi configuration.

---

## License

Copyright 2026 KISTI-GSDC

Apache License 2.0. The full text is in the `LICENSE` file, and the copyright notice is in the `NOTICE` file. The RPM installs them in `/usr/share/licenses/xrootd-x509map/`.
