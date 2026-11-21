# deliverability-audit

Check a cold email sending domain from the command line. The CLI tests DNS, blocklist status, domain age and website availability, then prints a prioritized fix list.

```bash
python3 audit.py yourdomain.com
```

## Checks

| Area | What the CLI reports |
| --- | --- |
| MX | Mail-server records and the provider behind them |
| SPF | Record count, the 10-lookup limit and ending policy (`~all` or `-all`) |
| DKIM | Published key on common selectors |
| DMARC | Policy, reporting address and quarantine or reject setting |
| MTA-STS, TLS-RPT, BIMI | Presence or absence |
| Blocklists | Domain against Spamhaus DBL, SURBL and URIBL; mail-server IPs against Spamhaus ZEN, Barracuda and SpamCop |
| Domain age | Registration date via RDAP; flags domains under 30 days |
| Website | Whether the sending domain serves a live site |

Use `--json` for machine-readable output. Requires Python 3.8+ and `dig` (`dnsutils` or `bind-tools`). No API keys.

Some blocklists reject queries from large public DNS resolvers. The CLI reports these as **could not query**, never as clean.

## Need a full audit?

The CLI covers DNS and reputation. A [Steiner Revenue deliverability audit](https://steinerrevenue.com/deliverability-audit) also includes live inbox placement across major providers, sending volume and ramp review, and list quality.

MIT License
