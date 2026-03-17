# DNScurse

A traceroute for DNS. DNScurse performs iterative resolution from the root servers, showing every delegation step so you can see exactly how a domain name gets resolved.

Unlike `dig +trace`, DNScurse walks the chain itself with `RD=0` (Recursion Desired off), so the output reflects the real path a resolver takes — including glue records, CNAME restarts, and SERVFAIL failovers.

![demo](docs/demo.gif)

Each delegation hop gets its own color. Labels introduced at the same hop share a color, so the hierarchy is immediately visible — the color in the domain header matches the color of the corresponding tree node in compact mode.

---

## Installation

DNScurse is not published to PyPI. Install from source:

```sh
git clone https://github.com/c0dev0id/DNScurse
cd DNScurse
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Or with pipx for an isolated install (no venv management needed):

```sh
git clone https://github.com/c0dev0id/DNScurse
cd DNScurse
pipx install .
```

Requires Python ≥ 3.10 and [dnspython](https://www.dnspython.org/) ≥ 2.6 (installed automatically).

---

## Usage

```
dnscurse [-t TYPE] [--timeout SECONDS] [-c] domain
```

| Option | Default | Description |
|---|---|---|
| `-t`, `--type` | `A` | Record type: `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `MX`, `TXT`, `PTR` |
| `--timeout` | `5.0` | Per-query UDP timeout in seconds |
| `-c`, `--compact` | off | Compact delegation tree view (see below) |

---

## Examples

### Basic A record lookup

```
$ dnscurse example.com

example.com
  server  a.root-servers.net (198.41.0.4)
  rcode   NOERROR
  result  referral → a.gtld-servers.net., b.gtld-servers.net.
  time    12.4ms

example.com
  server  a.gtld-servers.net (192.5.6.30)
  rcode   NOERROR
  result  referral → a.iana-servers.net., b.iana-servers.net.
  time    18.7ms

example.com
  server  a.iana-servers.net (199.43.135.53)
  rcode   NOERROR
  result  A 93.184.216.34
  time    9.1ms

  Answer:
    example.com.  3600  A  93.184.216.34

  3 steps, 40.2ms total
```

### AAAA record

```
$ dnscurse -t AAAA google.com

google.com
  server  a.root-servers.net (198.41.0.4)
  rcode   NOERROR
  result  referral → a.gtld-servers.net., b.gtld-servers.net.
  time    11.3ms

google.com
  server  a.gtld-servers.net (192.5.6.30)
  rcode   NOERROR
  result  referral → ns1.google.com., ns2.google.com., ns3.google.com., ns4.google.com.
  time    15.9ms

google.com
  server  ns1.google.com (216.239.32.10)
  rcode   NOERROR
  result  AAAA 2607:f8b0:4004:c1b::65
  time    8.2ms

  Answer:
    google.com.  300  AAAA  2607:f8b0:4004:c1b::65

  3 steps, 35.4ms total
```

### CNAME chain

When a name is an alias, DNScurse follows the chain and restarts resolution from root for the target — just like a real resolver does.

```
$ dnscurse www.github.com

www.github.com
  server  a.root-servers.net (198.41.0.4)
  rcode   NOERROR
  result  referral → a.gtld-servers.net., b.gtld-servers.net.
  time    10.8ms

www.github.com
  server  a.gtld-servers.net (192.5.6.30)
  rcode   NOERROR
  result  referral → ns-1707.awsdns-21.co.uk., ns-421.awsdns-52.com.
  time    14.2ms

www.github.com
  server  ns-421.awsdns-52.com (205.251.196.165)
  rcode   NOERROR
  result  cname → github.com
  time    9.6ms

github.com
  server  a.root-servers.net (198.41.0.4)
  rcode   NOERROR
  result  referral → a.gtld-servers.net., b.gtld-servers.net.
  time    11.1ms

github.com
  server  a.gtld-servers.net (192.5.6.30)
  rcode   NOERROR
  result  referral → ns-1707.awsdns-21.co.uk., ns-421.awsdns-52.com.
  time    13.7ms

github.com
  server  ns-421.awsdns-52.com (205.251.196.165)
  rcode   NOERROR
  result  A 140.82.114.4
  time    8.9ms

  Answer:
    github.com.  60  A  140.82.114.4

  6 steps, 68.3ms total
```

### NXDOMAIN — domain does not exist

```
$ dnscurse nope.invalid

nope.invalid
  server  a.root-servers.net (198.41.0.4)
  rcode   NOERROR
  result  referral → a.nic.invalid., b.nic.invalid.
  time    13.2ms

nope.invalid
  server  a.nic.invalid (185.24.64.42)
  rcode   NXDOMAIN
  result  NXDOMAIN
  time    21.4ms

  NXDOMAIN

  2 steps, 34.6ms total
```

### Compact mode

Delegation tree — shows the full resolution hierarchy at a glance:

```
$ dnscurse --compact example.com

example.com A
  . (a.root-servers.net)
    └── com. (a.gtld-servers.net)
        └── example.com. (a.iana-servers.net)
            └── A 93.184.216.34
```

### MX records

```
$ dnscurse -t MX gmail.com

gmail.com
  server  a.root-servers.net (198.41.0.4)
  rcode   NOERROR
  result  referral → a.gtld-servers.net., b.gtld-servers.net.
  time    10.1ms

gmail.com
  server  a.gtld-servers.net (192.5.6.30)
  rcode   NOERROR
  result  referral → ns1.google.com., ns2.google.com., ns3.google.com., ns4.google.com.
  time    16.3ms

gmail.com
  server  ns1.google.com (216.239.32.10)
  rcode   NOERROR
  result  MX 5 gmail-smtp-in.l.google.com., MX 10 alt1.gmail-smtp-in.l.google.com.
  time    7.8ms

  Answer:
    gmail.com.  3600  MX  5 gmail-smtp-in.l.google.com.
    gmail.com.  3600  MX  10 alt1.gmail-smtp-in.l.google.com.
    gmail.com.  3600  MX  20 alt2.gmail-smtp-in.l.google.com.
    gmail.com.  3600  MX  30 alt3.gmail-smtp-in.l.google.com.
    gmail.com.  3600  MX  40 alt4.gmail-smtp-in.l.google.com.

  3 steps, 34.2ms total
```

---

## How it works

DNS resolution is iterative: no single server knows the address for every domain. Instead, the resolution starts at a root server and follows a chain of referrals down the hierarchy until an authoritative server provides the final answer.

```
Client          Root server           .com TLD             example.com NS
  |                  |                    |                      |
  |-- example.com? ->|                    |                      |
  |<- referral: ask .com TLD -------------|                      |
  |                  |-- example.com? --->|                      |
  |                  |<- referral: ask example.com NS ------------|
  |                  |                    |-- example.com? ------>|
  |                  |                    |<- A 93.184.216.34 ----|
```

DNScurse makes each of these hops visible. At every step it records the server queried, the response code, what the server said, and how long it took.

**Referral steps** show which nameservers the current server is delegating to. The zone highlighted in the header is the one being handed off.

**Glue records** are A/AAAA records in the additional section of a referral response, providing the IP addresses of the next nameservers so the resolver doesn't need a separate lookup to continue. DNScurse uses them automatically.

**SERVFAIL failover**: if a nameserver returns SERVFAIL or REFUSED, DNScurse tries the next nameserver from the same referral — the same behaviour as production resolvers.

---

## Development

```sh
# Set up venv and install with dev dependencies
make build

# Run unit tests (no network required)
make test

# Run integration tests against live root servers
make test-net

# View the man page
make man
```

Dependencies: [dnspython](https://www.dnspython.org/) ≥ 2.6, Python ≥ 3.10.

---

## See also

- `dig +trace example.com` — similar output but delegates recursion to the server
- `man dnscurse` — full option reference
- [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034) — Domain Names: Concepts and Facilities
- [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) — Domain Names: Implementation and Specification
