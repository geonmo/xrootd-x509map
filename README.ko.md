# xrootd-x509map — GSI/VOMS 로컬·풀 계정 매핑 플러그인

> English: [README.md](README.md)

X509/VOMS 사용자를 Unix 계정으로 매핑하는 XRootD 플러그인 2개입니다.
[xrootd-multiuser](https://github.com/opensciencegrid/xrootd-multiuser)가
사용자 본인의 uid(사이트 사용자) 또는 VOMS 역할에 따라 고른 풀 계정(그 밖의 모든 사용자)으로
파일을 쓰게 합니다. xroot와 HTTPS 모두에서 동작하고 SciTokens, Macaroons와 함께 쓸 수 있으므로,
사이트는 X509 사용자와 토큰 사용자를 동시에 받으면서 사용자를 단계적으로 토큰으로 옮길 수 있습니다.

EL9(Lustre 백엔드)의 XRootD 5.9, xrootd-multiuser 2.2에서 테스트했습니다.

| 라이브러리 | 디렉티브 | 역할 |
|---|---|---|
| `libXrdAccX509Map-5.so` | `ofs.authlib ++` | **강제 지점**. xroot와 HTTPS 공통. 요청마다 계정을 매핑해 `request.name`을 설정하고, 맞는 규칙이 없으면 거부 |
| `libXrdSecEntityX509Map-5.so` | `sec.entitylib` | xroot 로그인 직후 `name`을 매핑된 계정으로 바꿈 (로그·모니터링용). **로그인을 거부하지 않음** |

---

## 1. 개요

### 하는 일

```
X509 요청 (xroot gsi / HTTPS 인증서)
  │
  ├─ 1. gridmap 예외: gsi -gridmap 또는 http.gridmap 에서 매핑된 이름 (gridmap.name=1)
  │      → 계정 검증 통과 시 그 계정 (검증 실패 시 경고 후 2 로)
  │      ※ 샘플 설정은 grid-mapfile 을 쓰지 않으므로 이 단계는 적용되지 않음
  ├─ 2. 로컬 DN 맵 (localmap=): exact / glob / regex, 첫 매칭 우선
  │      → 계정 검증 실패한 규칙은 건너뛰고 다음 규칙 시도
  ├─ 3. VOMS 맵 (vomsmap=): FQAN 을 VOMS 순서(primary 먼저)로, 첫 매칭 우선
  └─ 4. 거부 (XrdAccPriv_None)
```

"계정 검증"은 다음을 모두 통과해야 합니다.
- 이름이 `[A-Za-z0-9_.@-]` 문자로만 되어 있고 `-`로 시작하지 않음
- `getpwnam_r`로 계정이 존재함
- `uid >= minuid`, `gid >= mingid`

유효한 SciToken이나 macaroon이 있는 요청은 이 플러그인보다 먼저 결정됩니다(3.4 참조).
X509 신원이 전혀 없는 요청은 authdb에 맡깁니다.

### gsi 훅 대신 플러그인을 쓰는 이유

- **gsi 기본 훅은 체이닝이 안 됩니다.** `-gmapfun`/`-vomsfun`/`-authzfun`은 각각 라이브러리를 하나만 받고, 호출 순서도 gridmap → VOMS → authz로 고정입니다. 그래서 "로컬 사용자는 본인 계정, 나머지는 VOMS 역할별 풀 계정" 같은 조합을 만들 수 없습니다.
- **`-authzfun`(예: `libXrdSecgsiAUTHZVO.so`)은 결과를 키 캐시에 저장합니다.** 캐시 히트 시 문자열 필드만 복원되고 확장 속성(`gridmap.name`, `request.name`)은 사라집니다. 그러면 같은 사용자가 두 번째 접속부터 multiuser에서 "매핑 안 됨"으로 처리될 수 있습니다.
- **gsi 훅은 xroot만 다룹니다.** HTTPS에도 같은 매핑이 필요한데, 권한 부여(authorization) 플러그인은 두 프로토콜을 모두 봅니다.
- **multiuser와 함께 fail-closed로 동작합니다.** xrootd-multiuser는 `request.name`을 가장 먼저 보고, 없으면 `name`을 씁니다. gsi 클라이언트인데 `vorg`도 `gridmap.name=1`도 없으면 multiuser는 **anonymous로 간주해 데몬 uid로 실행**합니다. 이 플러그인은 매핑에 성공하면 반드시 `request.name`을 설정하고, 실패하면 OFS 단계에서 요청을 거부합니다. 그래서 X509 클라이언트가 매핑되지 않은 채 multiuser에 도달하는 일은 없습니다.

---

## 2. 설치

### 빌드 의존성 (EL9)

```bash
dnf install cmake gcc-c++ xrootd-server-devel gtest-devel   # xrootd-server-devel 은 5.4 이상 5.x
```

`/usr/local` 등에 다른 major 버전의 XRootD가 함께 설치돼 있어도, `/usr/include/xrootd`(5.x)를 먼저 찾습니다.
다른 경로의 5.x를 쓰려면 `-DXROOTD_DIR=/opt/xrootd`를 지정하세요.
5.x가 아니거나 5.4 미만이면 cmake 단계에서 중단됩니다.

### 소스 빌드

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build                 # 단위 테스트
sudo cmake --install build             # 아래 파일 설치
```

### RPM 빌드

```bash
mkdir -p ~/rpmbuild/SOURCES
git archive --prefix=xrootd-x509map-1.0.0/ -o ~/rpmbuild/SOURCES/xrootd-x509map-1.0.0.tar.gz HEAD
rpmbuild -ba rpm/xrootd-x509map.spec       # %check 에서 단위 테스트 실행
dnf install ~/rpmbuild/RPMS/x86_64/xrootd-x509map-1.0.0-1.*.x86_64.rpm
```

RPM은 `xrootd-server` 5.x(≥ 5.4)와 `xrootd-voms`를 필요로 하고, `xrootd-multiuser`를 권장합니다.

### 설치되는 파일

| 경로 | 내용 |
|---|---|
| `/usr/lib64/libXrdSecEntityX509Map-5.so` | `sec.entitylib` 플러그인 |
| `/usr/lib64/libXrdAccX509Map-5.so` | `ofs.authlib ++` 플러그인 |
| `/etc/xrootd/x509map-local.map` | 로컬 DN 맵, 예시만 들어 있음 (`%config(noreplace)`) |
| `/etc/xrootd/x509map-voms.map` | CMS용 VOMS 맵 (`%config(noreplace)`) |
| `/etc/xrootd/x509map-authdb` | authdb 예시 (`%config(noreplace)`) |
| `/etc/xrootd/xrootd-multiuser-x509map.cfg` | 완전한 서버 설정 샘플 (`%config(noreplace)`, 3장) |
| `/usr/share/doc/xrootd-x509map/` | 이 문서 (영어, 한국어) |

설정에는 `libXrdAccX509Map.so`처럼 `-5` 없이 써도 됩니다. XRootD가 `-5` 접미사를 자동으로 붙여 찾습니다.

---

## 3. 서버 구성

### 3.1 사전 준비

| 항목 | 비고 |
|---|---|
| 패키지 | `xrootd-server`, `xrootd-voms`, `xrootd-multiuser`, `xrootd-scitokens`(토큰용), 이 패키지 |
| 호스트 인증서 | gsi용 `/etc/grid-security/hostcert.pem`/`hostkey.pem`, 그리고 TLS/HTTPS용으로 xrootd 사용자가 읽을 수 있는 사본 (샘플은 `/etc/grid-security/xrd/xrdcert.pem`/`xrdkey.pem` 사용) |
| CA 인증서와 CRL | `/etc/grid-security/certificates` (예: IGTF 배포본 + fetch-crl) |
| VOMS 신뢰 | 매핑하는 모든 VO에 대한 `/etc/grid-security/vomsdir/<vo>/*.lsc` (예: OSG `vo-client` 패키지) |
| 계정 | passwd/sssd로 조회되는 사이트 사용자와 풀 계정(예: `cms`, `cmsprod`, `cmspilot`). uid/gid는 `minuid`/`mingid` 이상 |
| Macaroon 비밀키 | `openssl rand -base64 -out /etc/xrootd/macaroon-secret 64`, 소유자 `xrootd`, 모드 `0600` |
| SciTokens | issuer를 설정한 `/etc/xrootd/scitokens.cfg` (XrdSciTokens 문서 참조) |

### 3.2 설정 파일

샘플 설정 `/etc/xrootd/xrootd-multiuser-x509map.cfg`
(소스는 `configs/xrootd-multiuser-x509map.sample.cfg`)에서 시작하세요. 사이트에 맞게 바꿔야 할 줄에는
`SITE:` 표시가 있습니다. 최소한 `all.sitename`(예시값 `T3_XX_Example`),
export 경로, 포트, 인증서 경로, cmsd/redirector 블록은 바꿔야 합니다.

매핑 정보는 두 파일에 두며, 플러그인이 둘 다 읽습니다.

| 파일 | 내용 |
|---|---|
| `localmap=/etc/xrootd/x509map-local.map` | DN으로 본인 계정에 매핑되는 사이트 사용자. `"DN" 계정` 줄은 grid-mapfile 형식(계정은 한 줄에 하나)이고, glob/regex 규칙도 쓸 수 있습니다(5.1장) |
| `vomsmap=/etc/xrootd/x509map-voms.map` | 그 밖의 모든 사용자. VOMS FQAN으로 풀 계정에 매핑되며 voms-mapfile 문법을 씁니다(5.2장). 대신 기존 `/etc/grid-security/voms-mapfile`을 그대로 써도 됩니다 |

두 파일 모두 **xrootd 사용자가 읽을 수 있어야** 합니다. 서버가 동작하는 동안 플러그인이 xrootd 권한으로 다시 읽기 때문입니다.

마지막으로 `/etc/xrootd/x509map-authdb`를 네임스페이스에 맞게 고치고(3.6장) 서버를 시작합니다.

```bash
systemctl enable --now xrootd-privileged@multiuser-x509map
systemctl enable --now cmsd-privileged@multiuser-x509map    # cmsd 를 쓰는 경우에만
```

xrootd-multiuser에는 `*-privileged@` 유닛이 필요합니다. 로그는 `/var/log/xrootd/multiuser-x509map/`에 남습니다.

샘플에서 x509map과 관련된 부분만 모으면 다음과 같습니다.

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
    http.exthandler xrdtpc libXrdHttpTPC.so
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

| 설정 | | 이유 |
|---|---|---|
| `-vomsfun:libXrdSecgsiVOMS.so` | **필수** | VOMS 속성을 추출합니다. `endorsements`에 FQAN 전체가 쉼표로 이어져 들어갑니다. |
| `-gmapopt:10` | **권장** | 0 = grid-mapfile을 쓰지 않음(nomap), +10 = `name`에 해시 대신 DN을 넣음. 유효한 인증서를 가진 모든 DN이 로그인할 수 있고, 요청마다 x509map이 결정합니다. |
| `-moninfo` | 권장 | DN을 `moninfo`에도 남깁니다. `name`이 바뀐 뒤에도 플러그인이 DN을 알 수 있습니다. |
| `-vomsfunparms:` 의 `grpopt=usefirst` | **설정 금지** | `usefirst`면 `endorsements`에도 첫 FQAN 하나만 들어갑니다. 그러면 primary가 `/cms`이고 secondary가 `/cms/Role=production`인 프록시를 역할로 매핑할 수 없습니다. 기본값 `useall`을 유지하세요. |
| `-gmapopt:usemap` (2) | **사용 금지** | grid-mapfile에 없는 DN은 로그인 단계에서 실패하므로, 로컬 맵·VOMS 맵·토큰 어느 것도 적용될 기회가 없습니다. |
| `-gridmap:` | **불필요** | gridmap에서 매핑된 DN은 x509map이 그 계정을 그대로 쓰고, 두 맵을 모두 건너뜁니다. gridmap으로 표현할 수 있는 것("이 DN은 항상 이 계정")은 모두 VOMS 맵보다 먼저 적용되는 `x509map-local.map`에 쓸 수 있습니다. grid-mapfile을 꼭 유지해야 하면 `-gmapopt:11`(trymap)을 쓰고 예외만 넣으세요. VO 구성원 전체를 한 계정으로 매핑하는 grid-mapfile은 VOMS 역할 매핑을 모두 가려 버립니다. |
| `-authzfun:` | **사용 금지** | `libXrdSecgsiAUTHZVO.so`는 `name`을 VO 이름으로 덮어쓰고, 캐시 히트 시 확장 속성이 사라집니다(1장 참조). |

### 3.4 `ofs.authlib ++` 순서 규칙

`ofs.authlib ++`는 앞 줄의 authorizer를 감쌉니다. **마지막 줄이 가장 바깥이라 가장 먼저 호출됩니다.**

```
ofs.authlib ++ libXrdAccX509Map.so …       # 1번째 줄 = 가장 안쪽 (authdb 바로 위)
ofs.authlib ++ libXrdMacaroons.so          # 2번째
ofs.authlib ++ libXrdAccSciTokens.so …     # 마지막 줄 = 가장 바깥 = 가장 먼저 호출
```

호출 순서는 **SciTokens → Macaroons → x509map → authdb**입니다.
- 유효한 SciToken이나 macaroon이 있으면 바깥 플러그인이 그 자리에서 허용합니다. 요청은 x509map까지 오지 않습니다.
- 토큰이 없거나 무효면 체인을 따라 x509map까지 내려옵니다. x509map은 X509 신원으로 매핑하거나 거부합니다. 즉 무효 토큰은 X509로 자연스럽게 fallback됩니다.

순서를 잘못 두었을 때 생기는 증상:

| 잘못된 배치 | 증상 |
|---|---|
| x509map을 마지막 줄(가장 바깥)에 둠 | 인증서와 유효 토큰을 함께 보내는 클라이언트(HTTP-TPC, 인증서 + Bearer)가 토큰 계정이 아니라 X509 계정으로 처리됨. 매핑이 없는 인증서는 유효 토큰이 있어도 **거부됨** |
| `++` 없이 `ofs.authlib libXrdAccX509Map.so` | 기동 실패: `libXrdAccX509Map must be stacked with 'ofs.authlib ++'` |
| `ofs.authorize` 누락 | authlib 전체가 호출되지 않음 → 매핑 안 됨 → multiuser가 gsi 사용자를 anonymous로 처리 |

### 3.5 `sec.entitylib` (선택, 권장)

- xroot gsi 로그인 직후 한 번 호출됩니다. 매핑에 성공하면 `name`, `request.name`, `gridmap.name=1`을 설정합니다. 그러면 로그·모니터링·`acc.audit`·macaroon 발급에 계정명이 남습니다.
- **로그인은 절대 거부하지 않습니다.** 매핑이 안 된 클라이언트도 토큰을 요청마다(`authz` CGI) 보낼 수 있기 때문입니다. 거부는 authlib에서만 합니다.
- 원래 DN과 gridmap 결과를 `x509map.dn`, `x509map.gridmap` 속성에 보존합니다. 그래서 authlib가 매 요청마다 매핑을 다시 계산할 수 있습니다.
- **반드시 `if exec xrootd` 안에 두세요.** cmsd도 같은 설정 파일을 읽고 `sec.entitylib`를 호출합니다.
- `ofs.authlib ++ libXrdAccX509Map.so`와 **같은 옵션으로 함께** 설정하세요. 이 플러그인만 있으면 매핑을 강제할 수 없습니다. 반대로 authlib만 있으면 xroot 요청은 정상 동작하지만, 로그의 `name`에 DN이 그대로 보입니다.

### 3.6 authdb

어떤 계정이 어떤 경로를 쓸 수 있는지는 여전히 authdb가 결정합니다. x509map은 계정만 고릅니다.

- authdb의 `u <이름>` 규칙은 `request.name`을 먼저 봅니다(`XrdAccAccess.cc`). 그래서 `u cmsprod …`, `u = /xrd/store/user/@=/ …` 규칙이 매핑된 계정 기준으로 동작합니다. `g /cms` 규칙은 VOMS 그룹(`grps`)으로 그대로 동작합니다.
- **쓰기 권한이 있는 `u *`를 추가하지 마세요.** 이 규칙은 인증서 없는 HTTPS 클라이언트에도 매칭되는데, xrootd-multiuser는 이런 클라이언트를 데몬 uid로 실행합니다.

### 3.7 HTTPS

- HTTP에서는 `sec.entitylib`가 호출되지 않으므로 **authlib가 모두 처리**합니다.
- `http.secxtractor libXrdVoms.so`가 VOMS 추출에 성공하면 `prot="gsi"`가 됩니다. 실패하거나 VOMS가 없으면 `prot="https"`입니다. DN은 항상 `moninfo`에 들어가고, `name`에는 subject hash(또는 `http.gridmap` 결과)가 들어갑니다. 플러그인은 `gsi`와 `https` 둘 다 처리합니다.
- **인증서 없는 HTTPS**(토큰 전용 클라이언트, macaroon TPC 등)는 x509map이 그대로 통과시키고 authdb가 결정합니다.
- gsi `-gridmap`과 같은 이유로 **`http.gridmap`은 설정하지 마세요.** 설정하면 여기서 매핑된 DN(`gridmap.name=1`)이 1순위 예외가 됩니다.
- `http.header2cgi Authorization authz`는 그대로 둡니다. SciTokens/Macaroons가 HTTP Bearer 토큰을 읽는 데 필요합니다.
- FTS/Rucio가 이 서버로 데이터를 전송한다면 `http.exthandler xrdtpc libXrdHttpTPC.so`를 그대로 두세요. FTS는 HTTP(WebDAV) `COPY` 요청을 보내고, 보통 macaroon이나 토큰으로 인증합니다. 이 핸들러가 없으면 요청이 처리되지 않고 끊겨 전송이 실패합니다. x509map은 TPC 인가 방식을 바꾸지 않습니다.
- **macaroon 발급**(`http.exthandler xrdmacaroons`): macaroon의 `name:` caveat는 `SecEntity.name`에서 만들어집니다. x509map은 HTTP 요청에서도 `name`을 매핑된 계정으로 바꿉니다. 그래서 인증서로 받은 macaroon을 인증서 없이 써도 같은 계정으로 multiuser가 동작합니다. 이 동작은 HTTPS(`prot=https`)에서는 항상 적용됩니다. VOMS가 있는 HTTPS(`prot=gsi`)에서는 `sec.entitylib`도 설정된 경우에만 적용됩니다. 플러그인이 xroot와 HTTP 엔티티를 구분하는 데 `sec.entitylib`가 남기는 표시를 쓰기 때문입니다.

### 3.8 xrootd-multiuser와의 관계

- 매핑에 성공하면 authlib가 **요청마다** `request.name=<계정>`을 설정합니다. multiuser는 이 값을 가장 먼저 사용해 `setfsuid`합니다. `XrdOfs::rename`은 첫 권한 검사 후 `request.name`을 비우는데, 다음 검사에서 x509map이 다시 설정합니다(캐시 히트).
- xroot에서는 `sec.entitylib`가 `gridmap.name=1`도 설정합니다. 그래서 VOMS가 없는 로컬 사용자도 multiuser의 `IsGsiUserMapped`를 통과합니다.
- `minuid=`/`mingid=`는 `multiuser.minuid`/`multiuser.mingid`와 **같은 값으로 맞추세요**(multiuser 기본값 500). 플러그인이 허용했는데 multiuser가 거부하면, 클라이언트 입장에서는 원인을 알기 어렵습니다.

---

## 4. 플러그인 옵션 레퍼런스

두 디렉티브(`sec.entitylib`, `ofs.authlib ++`)에 같은 옵션을 씁니다. 옵션은 공백으로 구분합니다. 알 수 없는 옵션이 있으면 기동을 거부합니다.

| 옵션 | 기본값 | 허용 범위 | 의미 |
|---|---|---|---|
| `localmap=<경로>` | (없음) | 절대 경로 | 로컬 DN 맵 파일. `localmap`과 `vomsmap` 중 최소 하나는 필요 |
| `vomsmap=<경로>` | (없음) | 절대 경로 | VOMS 맵 파일 (voms-mapfile 문법) |
| `minuid=<n>` | `500` | 0 – 2³¹-1 | 매핑 결과 계정의 uid가 이보다 작으면 그 규칙을 무효로 처리 |
| `mingid=<n>` | `500` | 0 – 2³¹-1 | 같은 규칙을 기본 gid에 적용 |
| `cacheto=<초>` | `600` | 0 – 86400 | 매핑 성공 결과와 passwd 조회 성공 결과의 캐시 TTL. 0이면 캐시 안 함. sssd/LDAP 부하를 줄이려면 60 이상 권장 |
| `negcacheto=<초>` | `60` | 0 – 86400 | 거부 결과와 "계정 없음" 조회의 캐시 TTL. 새 계정을 만든 뒤 이 시간 안에 반영됨. 일시적 조회 오류는 캐시하지 않음 |
| `reloadsec=<초>` | `30` | 0 – 86400 | 맵 파일 변경 검사 주기. 0이면 재로드 안 함 |
| `debug` (또는 `debug=1`) | 꺼짐 | — | 규칙별 매칭·fall-through 사유를 Debug 로그로 출력 |

- 맵 파일은 기동 시 열 수 없으면 **설정 오류로 데몬 기동을 거부**합니다.
- 기동 후에는 `reloadsec`마다 요청 처리 중에 `stat()`(inode/크기/mtime/ctime)을 확인합니다. 변경이 있으면 새 규칙셋으로 교체합니다(generation 증가, 매핑 캐시 무효화). 별도 스레드는 없습니다.
- 재로드 중 파일을 열지 못하면 **이전 규칙을 유지**하고 오류를 로그에 남깁니다.
- 파일 교체는 `mv`(rename)로 원자적으로 하길 권장합니다.
- 두 `.so`는 각자 매퍼 인스턴스(캐시, 재로드 상태)를 가집니다. 변경은 `reloadsec` 이내에 양쪽 모두 반영됩니다.

---

## 5. 맵 파일 문법

### 5.1 로컬 DN 맵 (`localmap=`)

한 줄에 규칙 하나를 씁니다. 따옴표 밖의 `#`부터 줄 끝까지는 주석입니다. **첫 번째로 매칭되는 규칙이 이깁니다.**

```
"<정확한 DN>"                  <계정>
glob  "<DN glob>"             <계정 또는 템플릿>
regex "<ECMAScript 정규식>"    <계정 또는 템플릿>
```

- **exact**: DN 문자열이 완전히 같아야 합니다. DN에 공백이 있어도 됩니다. grid-mapfile의 줄 형식(계정 하나)과 같습니다.
- **glob**: `*` = 임의 문자열, `?` = 임의 한 글자, `( … )` = 캡처 그룹입니다. 그 밖의 문자는 문자 그대로 비교합니다(`.`도 그대로). 패턴은 반드시 `/`로 시작하고, 첫 와일드카드 앞에 최소 한 개의 `/X=` 속성이 있어야 합니다. 그래서 `"*…"`, `"(*)"`처럼 너무 넓은 glob은 거부됩니다.
- **regex**: ECMAScript 정규식입니다. 자동으로 `^(?: … )$`로 앵커되어 DN 전체와 매칭해야 합니다.
- **템플릿**: `$1`–`$9`, `${n}` = n번째 캡처 그룹, `$$` = 문자 `$`. `$0`(DN 전체)은 허용하지 않습니다. 패턴에 없는 그룹을 참조하면 해당 줄을 파싱 오류로 처리합니다.
- **따옴표 안 이스케이프**: `\"` `\'` `\/` `\t` `\n` `\r` `\f` `\\`. 이 규칙은 voms-mapfile과 같습니다. regex 줄에서는 그 밖의 이스케이프(`\.`, `\d` 등)를 정규식용으로 그대로 둡니다. exact/glob 줄에서 그 밖의 이스케이프를 쓰면 오류입니다.
- **검증과 fall-through**: 템플릿을 전개한 결과가 안전하지 않은 이름이거나, 계정이 없거나, `minuid`/`mingid` 미만이면 **거부가 아니라 다음 규칙으로 넘어갑니다.** 끝까지 맞는 규칙이 없으면 VOMS 맵으로 넘어갑니다. 그래서 `CN=(*)` glob에 걸린 비로컬 사용자(`CN=Jane Doe` → 공백 포함, `CN=jdoe` → 계정 없음)는 자연스럽게 VOMS로 매핑됩니다.
- **파싱 오류**: 형식이 틀린 줄은 `file:line: reason; line ignored` Warning을 남기고 건너뜁니다.

예시:

```
# 1) exact — 공백 포함 DN
"/DC=org/DC=example/OU=People/CN=12345678 Alice Kim"     alice

# 2) exact — 따옴표가 들어간 DN
"/DC=org/DC=example/CN=Kim \"Robot\" Test"              kimtest

# 3) glob — 사이트 CA 네임스페이스에서 CN 이 곧 계정명
glob  "/DC=org/DC=example/OU=Site/CN=(*)"                 $1

# 4) glob — 접두어 + 캡처, 뒤는 무시
glob  "/DC=org/DC=example/OU=Site/OU=Users/CN=(*)/CN=*"   $1

# 5) regex — 로봇 인증서 "CN=Robot: <계정>-<아무거나>"
regex "/DC=org/DC=example/OU=Site/CN=Robot: ([a-z0-9]+)-.*"   $1

# 6) regex — 특정 CERN 사용자만 로컬 계정으로, 접두어 붙이기
regex "/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=(jdoe|asmith)/CN=[0-9]+/CN=.*"  kr_$1
```

모든 로컬 매칭(성공)은 Info 로그(`… -> alice (local, local map line N)`)로 남으므로 감사에 쓸 수 있습니다.
glob/regex 규칙은 사이트 CA 네임스페이스(`/DC=org/DC=example/…`)로 한정하세요.

### 5.2 VOMS 맵 (`vomsmap=`)

XRootD `voms-mapfile`과 같은 문법입니다. 파서와 매처는 `XrdVomsMapfile`의 `ParseLine`/`Compare`를 이식한 것입니다.

```
"/cms/Role=production/Capability=NULL"  cmsprod
"/cms/Role=pilot/Capability=NULL"       cmspilot
"/cms/*"                                cms
"/alice/*"                              alice
```

- 클라이언트 FQAN을 **VOMS 순서(primary 먼저)** 로 하나씩 시도합니다. FQAN마다 규칙을 위에서부터 보고, **첫 매칭이 이깁니다.** 따라서 구체적인 Role을 와일드카드보다 위에 쓰세요.
- 경로 요소마다 `*` 글로브가 적용됩니다(예: `Role=*`). 마지막 요소가 `*`면 그보다 깊은 그룹·Role·Capability까지 모두 매칭합니다.
- **구체적인 규칙은 더 일반적인 FQAN에 매칭되지 않습니다.** 예: `"/cms/uscms/Role=NULL/Capability=NULL"`은 `/cms/Role=NULL/Capability=NULL`에 매칭되지 않습니다.
- FQAN 표기는 `/<그룹…>/Role=<role>/Capability=<cap>`입니다. Role이 없으면 `Role=NULL`, Capability가 없으면 `Capability=NULL`로 정규화해서 비교합니다.
- 규칙이 매칭됐는데 계정 검증에 실패하면 다음 규칙으로 넘어갑니다.
- 대상 계정 뒤에는 공백과 `#` 주석만 올 수 있습니다. 이 점은 원본보다 엄격합니다.
- FQAN 출처: `endorsements`(쉼표 구분)를 우선 사용합니다. 없으면 `vorg`/`grps`/`role`을 공백 단위로 짝지어 합성합니다. 이때 그룹의 첫 요소가 VO 이름과 다르면 무시합니다(`XrdVomsMapfile::Apply`와 같음).

---

## 6. 동작 규칙

### 6.1 프로토콜별 DN/FQAN 출처

| 접속 형태 | `prot` | DN 출처 | FQAN 출처 | x509map 처리 |
|---|---|---|---|---|
| xroot gsi + VOMS 프록시 | `gsi` | `moninfo`(`-moninfo`) 또는 `name`(`-gmapopt:10`/`11`) | `endorsements` | 매핑 또는 거부 |
| xroot gsi, VOMS 없음 | `gsi` | 위와 같음 | 없음 | 로컬 맵(gridmap을 설정했다면 gridmap도)만 적용, 나머지는 거부 |
| HTTPS + VOMS 프록시 | `gsi` (secxtractor) | `moninfo` | `endorsements` | 매핑 또는 거부 |
| HTTPS, 인증서만 | `https` | `moninfo` | 없음 | 로컬 맵(gridmap을 설정했다면 gridmap도)만 적용, 나머지는 거부 |
| HTTPS, 인증서 없음 | `https` | 없음 | — | **통과** → authdb가 결정 |
| xroot ztn (토큰) | `ztn` | — | — | **통과** (SciTokens가 처리) |
| SciTokens 매핑 전용 엔티티 | `""` | — | — | **통과** |
| unix / sss / host | 해당 값 | — | — | **통과** |

### 6.2 토큰·macaroon과의 우선순위

1. 유효한 SciToken(scope 일치) → SciTokens가 바로 허용합니다. x509map은 호출되지 않습니다.
2. 유효한 macaroon → Macaroons가 `request.name`을 설정하고 바로 허용합니다. x509map은 호출되지 않습니다.
3. 토큰이 없거나 무효 → x509map이 X509 신원으로 매핑하거나 거부합니다.
4. X509도 없음 → authdb가 결정합니다.

### 6.3 거부 시 클라이언트가 보는 메시지

XRootD 5.9의 `XrdAccAuthorize::Access()`는 오류 문자열을 돌려주는 인터페이스가 없습니다(6.x부터 있음). 그래서 클라이언트는 일반 권한 오류만 받습니다.

- xroot: `[3010] Unable to open /xrd/…; permission denied`
- HTTPS: `HTTP 403`

거부 사유는 서버 로그에 남습니다.

```
x509mapacc_Map: map dn=/DC=ch/DC=cern/OU=Users/CN=jdoe fqan=<none> -> DENY (DN not local and no VOMS attributes)
x509mapacc_Access: denying b9d386bb.4:29@host path=/xrd/store/x: x509map: DN not local and no VOMS attributes
```

거부 사유 목록:

| 사유 | 의미 |
|---|---|
| `DN not local and no VOMS attributes` | 로컬 맵에 없고, VOMS 속성도 없음 (`grid-proxy-init` 프록시, 일반 인증서) |
| `DN not local and no VOMS mapping` | VOMS 속성은 있으나 맞는 VOMS 규칙이 없거나, 매칭된 규칙의 계정이 모두 무효 |
| `no subject DN (need -gmapopt:10 or -moninfo)` | 현재 gsi 설정으로는 DN을 얻을 수 없음 |
| `… (gridmap: account 'x' does not exist)` | gridmap 매핑 결과가 무효라서 무시했음 (꼬리에 덧붙음) |

---

## 7. 로그와 트러블슈팅

로그 접두어는 `x509mappin_`(entitylib), `x509mapacc_`(authlib)입니다.

```
x509mappin_Config: loaded 12 local / 4 voms rules (generation 1)
x509mapacc_Config: loaded 12 local / 4 voms rules (generation 1)
x509mapacc_Map: map dn=/DC=org/DC=example/OU=Site/CN=Alice Kim fqan=<none> -> alice (local, local map line 1)
x509mapacc_Map: map dn=/DC=ch/…/CN=jdoe fqan=/cms/Role=production/Capability=NULL,/cms/Role=NULL/Capability=NULL -> cmsprod (voms, VOMS map line 1 fqan /cms/Role=production/Capability=NULL)
x509mapacc_Reload: reloaded local map (generation 2): 13 local / 4 voms rules
x509mappin_Process: <tident> unmapped at login, deferring to authlib: DN not local and no VOMS attributes   # debug
x509mapacc_Map: local rule line 3 matched dn=… but account 'jdoe' does not exist; trying next rule      # debug
```

`Map` Info 로그는 **캐시 미스 때만** 찍힙니다(같은 신원은 `cacheto` 동안 한 번).
`acc.audit deny`(또는 `deny grant`)를 함께 켜면 authdb 단계의 결과도 남습니다.

| 증상 | 원인 / 조치 |
|---|---|
| 기동 실패 `x509mapacc_Config: configuration failed: cannot open local map …` | 맵 경로 오타 또는 xrootd 사용자 읽기 권한 없음. SELinux 환경이면 `/etc/xrootd` 아래에 두세요 |
| 기동 실패 `cannot open local map …` / `cannot open VOMS map …` (Permission denied) | 맵 파일을 xrootd가 읽을 수 없음(예: `root:root 0640`) — `chgrp xrootd` 후 `0640` |
| 기동 실패 `libXrdAccX509Map must be stacked with 'ofs.authlib ++'` | `++` 누락 |
| `Unable to load … libXrdAccX509Map-5.so` | `-5` 접미사 파일이 `/usr/lib64`에 없음, 또는 XRootD major 버전 불일치 (6.x에서는 재빌드 필요) |
| 로그에 `-> DENY (… account 'x' does not exist)` | 맵의 계정이 passwd/sssd/LDAP에 없음. `getent passwd x` 확인 |
| `uid N < minuid M` | 시스템 계정이거나 `minuid`가 너무 큼 |
| 알 수 없는 DN이 **로그인부터 실패** | gsi가 `-gmapopt:usemap`(2)을 씀 — `-gmapopt:10`을 쓰세요 |
| VOMS 역할이 있는 사용자가 VO 공통 계정으로 매핑됨 | VOMS 맵에 해당 역할 줄이 없거나 `/vo/*` 와일드카드보다 아래에 있음, `-gridmap`/`http.gridmap`이 DN을 먼저 매핑함 (gridmap 1순위), 또는 `grpopt=usefirst`로 secondary FQAN이 빠짐 |
| 맵이 맞는데도 VOMS 사용자가 `no VOMS mapping`으로 거부됨 | `/etc/grid-security/vomsdir` 아래에 해당 VO의 `.lsc` 파일이 없어서 FQAN이 추출되지 않음 (debug로 확인) |
| 유효 토큰이 있는데 x509map이 거부 | `ofs.authlib ++` 순서 오류 — x509map이 첫 줄이어야 함 |
| HTTPS 클라이언트에 대해 multiuser 로그 `Multiuser denying access: XRootD mapped request to username that does not exist: <hash>.0` | 무시해도 됩니다. XrdHttp는 요청을 인가하기 전에 인증서 subject hash 이름으로 클라이언트를 로그인시키고, multiuser가 그 로그인에 대해 이 로그를 남깁니다. 실제 요청은 x509map, SciTokens, Macaroons가 정한 계정으로 실행됩니다. `http.gridmap`이 DN을 매핑하는 경우에는 보이지 않는데, 샘플 설정은 `http.gridmap`을 쓰지 않습니다 |
| multiuser 로그 `Anonymous GSI client; cannot change FS UIDs` | 매핑 실패한 요청에서 multiuser가 남기는 로그입니다. x509map이 같은 요청을 거부하므로 파일은 생기지 않습니다. 매핑된 사용자에게서 보이면 `ofs.authorize` 누락 여부를 확인하세요 |
| 맵을 고쳤는데 반영 안 됨 | `reloadsec` 대기. 거부 결과는 `negcacheto`까지 남을 수 있음. gsi/HTTP grid-mapfile을 쓴다면 그것은 XRootD가 따로 캐시함 (재시작 또는 `-gmapto`) |
| 매핑은 성공했는데 multiuser가 거부 | `multiuser.minuid/mingid`가 플러그인 `minuid/mingid`보다 큼 — 값을 맞추세요 |

---

## 8. 검증 절차

두 플러그인 줄에 `debug` 옵션을 넣고(또는 `-d`로) 서버를 기동한 뒤 다음을 확인합니다.
예시는 샘플 포트(xroot 1094, HTTPS 2880)와 `/xrd` 네임스페이스를 전제로 합니다.

1. 기동 로그에 `x509mappin_Config: loaded N local / M voms rules`, `x509mapacc_Config: …`가 나오는지 확인합니다.
2. 로컬 사용자: `voms-proxy-init -voms cms` 후 `xrdcp f root://host:1094//xrd/store/user/<id>/f` → 성공, 로그 `-> <계정> (local…)`, 스토리지에서 `ls -l` 소유자가 본인이어야 합니다.
3. 비로컬 사용자 `/cms/Role=production` → 소유자 `cmsprod`, `-voms cms`만 쓰면 → `cms`.
4. 비로컬 + VOMS 없음(`grid-proxy-init`) → 로그인은 성공하고 `xrdcp`가 `permission denied`로 실패해야 합니다. 로그에 `x509map: DN not local and no VOMS attributes`가 남고, 파일은 생기지 않아야 합니다.
5. HTTPS: `curl --cert $X509_USER_PROXY --key $X509_USER_PROXY --capath /etc/grid-security/certificates -T f https://host:2880/xrd/store/…`로 2–4를 반복합니다. 4는 HTTP 403이어야 합니다.
6. `xrdfs host:1094 mv a b`(rename) 후에도 소유자가 유지되는지 확인합니다.
7. 토큰 공존:
   - (i) `BEARER_TOKEN`으로 ztn `xrdcp` → x509map 로그 없이 scitokens 계정으로 처리
   - (ii) 인증서 없이 `curl -H "Authorization: Bearer …"` → 동일
   - (iii) 유효 X509 + 무효 토큰 → x509map이 X509로 매핑 (fallback)
   - (iv) 인증서로 macaroon 발급(`curl -X POST -H 'Content-Type: application/macaroon-request' …`) 후 인증서 없이 사용 → 본인 계정 소유로 파일 생성
   - (v) 비로컬·VOMS 없음·토큰 없음 → 첫 요청에서 거부
8. `x509map-local.map`에 줄을 추가하고 `reloadsec` 뒤에 재시작 없이 반영되는지 확인합니다(`reloaded local map (generation N)`).
9. 존재하지 않는 맵 경로로 기동하면 두 플러그인 모두 명확한 메시지와 함께 기동을 거부하는지 확인합니다.

개발 중에 시나리오 1–6, 7-iii–7-v, 8, 9를 XRootD 5.9.7(+multiuser, SciTokens, Macaroons)과 테스트 CA로 검증했습니다. 유효 SciToken 경우(7-i, 7-ii)는 실제 토큰 issuer가 필요합니다.

---

## 9. 제한 사항 / SciTokens로 전환

- **HTTP에는 authlib만 적용됩니다.** `sec.entitylib`는 xroot 전용입니다. HTTP에서 `name` 교체는 authlib가 요청 시점에 합니다.
- **두 `.so`는 캐시가 따로입니다.** 맵 변경은 `reloadsec` 안에 양쪽 모두 반영되지만, 시점은 수 초 차이가 날 수 있습니다.
- **거부 사유는 클라이언트에 전달되지 않습니다**(5.9 인터페이스 제약). 서버 로그를 보세요.
- **gridmap 매핑이 1순위입니다.** grid-mapfile을 설정하면 그 DN에는 로컬 맵·VOMS 맵이 적용되지 않습니다. 샘플 설정은 grid-mapfile을 쓰지 않습니다.
- **너무 넓은 규칙은 피하세요.** `glob "/DC=org/DC=example/(*)"`처럼 쓰면, 사이트 CA가 발급한 DN이 우연히 같은 이름의 계정으로 매핑될 수 있습니다.
- **XRootD 6에서는 재빌드가 필요합니다.** 플러그인 심볼이 major 버전(`-5`)에 고정돼 있습니다. 6.x에서는 `Access()`의 오류 문자열 버전도 구현할 수 있습니다.
- **SciTokens로 전환**: XrdSciTokens도 같은 방식(`request.name`)으로 multiuser에 계정을 전달합니다. 그래서 OSS·authdb 쪽 변경 없이 사용자를 단계적으로 토큰으로 옮길 수 있습니다. X509 사용자가 남지 않으면 `ofs.authlib ++ libXrdAccX509Map.so`와 `sec.entitylib` 줄, 그리고 gsi 설정을 지우면 됩니다.

---

## 라이선스

Copyright 2026 KISTI-GSDC

Apache License 2.0. 전문은 `LICENSE`, 저작권 고지는 `NOTICE` 파일에 있습니다. RPM에서는 `/usr/share/licenses/xrootd-x509map/`에 설치됩니다.
