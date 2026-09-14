# Bundled key coverage

Retrieved: 2026-09-11T18:25:06.995Z. Requested history starts 2021-09-11.

**Coverage is not complete.** These are the available archive records for the explicit domains below, including older records. This is not every key used by every major provider since 2021-09-11. Customer-owned domains, regional domains, missing selectors, and unarchived rotations are not covered. A missing key means the message cannot be checked with this bundle.

Each record in [keys.json](keys.json) links its exact domain/selector lookup, archive record ID, and an untouched local JSON response with its SHA-256 digest. Public DNS keys are public factual data. The source is the [ZK Email DKIM Archive](https://archive.zk.email/); its [provenance documentation](https://github.com/zkemail/archive/blob/aeff0fa5002d0e3b5f51d3edb54ec8c15cc575a0/docs/signed-observations.md) explains the distinctions below.

- DNS dates: the archive reports observing that TXT value in DNS. These are the archive's claims, not independently timestamped proofs, and the first/last observations do not prove uninterrupted publication.
- Recovered dates: dates on submitted email signatures used to reconstruct a key. The archive does not authenticate those submissions. Recovery alone does not establish that the domain published the key or sent the messages.
- An empty public-key field (`p=`) records revocation. Retaining an older key permits a mathematical check but does not override revocation or prove historical authorization.
- Selector names containing years are names, not evidence of when keys were used. Earliest dates below describe any record for that domain; they do not establish five-year coverage for every key.

Nonempty-key counts include historical weak keys. In this snapshot, `qq.com` selector `s0907` has a 768-bit RSA key, which must not be accepted for DKIM verification. It is retained so the source history remains auditable.

| Provider | Exact signing domain | Nonempty keys | Revocations | Earliest reported DNS observation | Earliest recovered message date |
| --- | --- | ---: | ---: | --- | --- |
| Google / Gmail | gmail.com | 6 | 3 | 2024-01-31 | 2014-04-23 |
| Google / Gmail | googlemail.com | 5 | 3 | 2024-01-31 | 2010-03-11 |
| Google / Gmail | google.com | 8 | 4 | 2024-01-31 | 2012-01-11 |
| Google / Gmail | 1e100.net | 2 | 0 | 2024-04-12 | — |
| Microsoft / Outlook | outlook.com | 2 | 0 | 2024-01-23 | — |
| Microsoft / Outlook | hotmail.com | 1 | 0 | 2024-01-31 | — |
| Microsoft / Outlook | live.com | 1 | 0 | 2024-02-25 | — |
| Microsoft / Outlook | microsoft.com | 7 | 0 | 2024-02-07 | — |
| Yahoo / AOL | yahoo.com | 3 | 0 | 2014-02-07 | — |
| Yahoo / AOL | ymail.com | 2 | 0 | 2024-04-10 | — |
| Yahoo / AOL | aol.com | 2 | 0 | 2024-02-16 | — |
| Apple iCloud | icloud.com | 2 | 1 | 2024-02-16 | — |
| Apple iCloud | me.com | 2 | 1 | 2024-01-31 | — |
| Apple iCloud | mac.com | 2 | 1 | 2024-02-24 | — |
| Proton | proton.me | 10 | 0 | 2024-02-19 | — |
| Proton | protonmail.com | 2 | 0 | 2024-02-19 | — |
| Proton | protonmail.ch | 1 | 0 | 2024-02-25 | — |
| Proton | pm.me | 1 | 0 | 2024-02-16 | — |
| Fastmail | fastmail.com | 12 | 3 | 2024-04-09 | — |
| Fastmail | messagingengine.com | 16 | 3 | 2024-03-19 | — |
| Zoho | zoho.com | 1 | 0 | 2024-04-09 | — |
| Zoho | zohomail.com | 1 | 0 | 2024-05-02 | — |
| GMX / Web.de | gmx.com | 1 | 0 | 2024-04-09 | — |
| GMX / Web.de | gmx.net | 2 | 0 | 2024-02-16 | — |
| GMX / Web.de | web.de | 2 | 0 | 2024-02-18 | — |
| Yandex | yandex.ru | 1 | 0 | 2024-02-21 | — |
| Yandex | yandex.com | 1 | 0 | 2024-04-09 | — |
| Mail.ru | mail.ru | 2 | 0 | 2024-02-22 | — |
| Mail.ru | inbox.ru | 2 | 0 | 2024-04-25 | — |
| Mail.ru | bk.ru | 2 | 0 | 2024-02-22 | — |
| Mail.ru | list.ru | 2 | 0 | 2024-03-20 | — |
| Tencent QQ | qq.com | 2 | 0 | 2011-07-27 | — |
| Tencent QQ | foxmail.com | 1 | 0 | 2024-03-21 | — |
| NetEase | 163.com | 1 | 0 | 2024-01-31 | — |
| NetEase | 126.com | 1 | 0 | 2024-03-18 | — |
| Amazon SES | amazonses.com | 61 | 0 | 2024-01-31 | 2014-11-01 |
| SendGrid | sendgrid.net | 8 | 0 | 2024-01-23 | — |
| Mailgun | mailgun.org | 3 | 0 | 2024-01-31 | 2020-07-06 |
| Mailchimp Transactional | mandrillapp.com | 2 | 0 | 2024-01-31 | — |

Refresh from this directory with `node scripts/update-keys.mjs 2>&1 | tee /tmp/dkim-keys-refresh.log`. Node 20+ is required. The script queries public domain names only, paces requests to respect the archive's ten-per-minute allowance, retains previously bundled keys, and saves new timestamped source snapshots. It does not read any email files. Review the changes and run `npm test` before serving an updated bundle.
