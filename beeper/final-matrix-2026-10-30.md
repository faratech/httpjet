# HTTPJet final matrix — 2026-10-30

Candidate C (`6ac…`, stock rustls) against the exact shipped **v0.1.10-11** and the separately rebuilt native-source baseline.

**Matrix evidence status: complete.** 40/40 planned cells have complete evidence. This reports observations without an overall winner or a claim that the wider integration goal is complete.

All **96,000,000 measured responses** and **4,800,000 warmup responses** validated. The [per-arm CSV](../docs/evidence/final-c-20261030/arms.csv) retains all 480 arms.

Related: [continuation and decisions](continuation-2026-10-30.md); [H3 scheduler fairness](h3-scheduler-fairness-20261030.md).

The candidate and native-source control use Rust 1.99.1, native CPU code generation, frame pointers, thin LTO, one codegen unit and no PGO. The source control is `46be2c2e`, whose runtime source matches released `5ea86753`; its default features are retained. Candidate C includes the experimental H1/H2 kernel features. The exact shipped archive is a separate comparator; its build differences must not be credited entirely to Beeper.

Each cell uses three ABBA cycles, 200,000 measured requests and 10,000 warmup requests per arm, one server worker on CPU 8, and six client threads on CPUs 0,2,4,6,12,14. There are 32 connections; H1 is sequential on each connection, while H2/H3 use four concurrent streams. This measures per-worker loopback capacity, not maximum multicore or production-site throughput. Process affinity does not constrain kernel IRQ/softirq or psock workers to that CPU; a throughput gain is not, by itself, evidence of lower whole-system CPU per response.

Recorded network profile: `true-lo`; server `127.0.0.2`, client bind `127.0.0.2`. Results from different profiles must remain separate.

Both arms enable and warm their existing caches. Cached static and origin page-cache hits are separate fixtures. The page-cache fixture uses generated static content routed through the origin page cache, with PHP disabled. The release's H3 shared static-body cache is not a cache-disabled baseline. Candidate flags and actual kernel-hit coverage are retained in the source summary; native TLS/H3 gains must not be labeled in-kernel parsing gains.

B → C means baseline → candidate. Table values are medians of the complete planned arms; Δ is `100 × (C/B − 1)`. Positive p99/CPU deltas mean higher cost or latency. Per-cycle RPS ranges are the observed minimum–maximum of each role's two ABBA arms, not confidence intervals. Failed or incomplete cells show no aggregate performance values; their statuses remain visible.

RPS and p99 cover measured requests only, at fixed concurrency. These are saturation completion latencies, not scheduled offered-load latency. Process CPU is server/descendant **user + system** time. PMU instructions/cycles count **user mode only**, excluding kernel, IRQ and hypervisor work. CPU/PMU denominators include requested + warmup responses across the whole client span, including handshake, output and teardown. VM busy is all Linux VM CPUs (user + nice + system + IRQ + softIRQ), including clients and unrelated work; it is not server-owned CPU. VM units remain ticks/response because the summary does not supply a conversion timebase. None of these scopes alone establishes total-server CPU savings.

## Artifact and build identity

The release comparison includes shipped-build versus candidate-build differences. The source comparison establishes build-recipe parity only to the extent documented by its build receipts. Neither native code generation nor PGO status is inferred from filenames.

| Artifact | Recorded path | SHA-256 |
| --- | --- | --- |
| release | /var/tmp/httpjet-continuation/baselines/v0.1.10-11/httpjet | `3b1ecbe1b5fd7a32e89547007d00628878b6135dc255b74811688cccca0858ec` |
| native_baseline | /var/tmp/httpjet-continuation/baselines/46be2c2e/httpjet | `f18f6299cf5d91429df589870d6d5021b1d592f5aa93fdf986be528f2428b2e9` |
| candidate | /var/tmp/httpjet-continuation/h2-oversize-c-ed7a4fda/bin/httpjet | `6ac144f2449750d6063963c0994f30c933c11df8e8dbfa548b1a7b4a71e51e8f` |
| helper | /var/tmp/httpjet-continuation/tls-stack-study-v1/bin-base/httpjet-beeper-h1 | `6208c5cc8402468481aeba015e6b0bafed961c078e34cef6eba9320c6ad5180a` |
| http_client | /var/tmp/hjc/httpjet-http-load-bind | `e5c21fa94ea72c965cd4cfea950977c2bb771a4a5842a58499a5b1355c758b8f` |
| h3_client | /var/tmp/httpjet-continuation/h3-bind-client-20261030/bin/httpjet-h3-load-bind | `afee4fd337ce7289c3a3122abba27fd3fa47605535d50f9b43aa4dff22e33a77` |
| python | /usr/bin/python3.14 | `6afce98b1e5ce89dc1c5dfca9672276a9486bc318855c7554cbe6da62d073e10` |

| Build receipt | Recorded path | SHA-256 |
| --- | --- | --- |
| candidate_receipt | /var/tmp/httpjet-continuation/final-c-matrix-true-lo-v1/receipts/candidate_receipt | `8cbd4770a916c1724da13d53e97d6e296af57f8a4289bcdc1871dac93c081fca` |
| native_baseline_receipt | /var/tmp/httpjet-continuation/final-c-matrix-true-lo-v1/receipts/native_baseline_receipt | `3e883994c5d29d1dd0eda8491bcd1791c9a8954c9171d9a0f984faeac8d099db` |
| release_receipt | /var/tmp/httpjet-continuation/final-c-matrix-true-lo-v1/receipts/release_receipt | `10e5d72892bd9171690964dbde01d8523cd90212d5d16e899b99f1bc277e6d51` |

Source summary SHA-256: `7ff1d17a46ddb8ed404bd456c29bcb07a24e24a9d21961cf22a1ec475ec1a21f`. Input: `/var/tmp/httpjet-continuation/final-c-matrix-true-lo-v1/summary.json`.

## Exact shipped v0.1.10-11 comparison

### 1 KiB

| Protocol | Fixture | Status / arms | RPS B → C | Δ RPS | p99 ms B → C | Δ p99 | RPS range per cycle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H1 | static | complete (12/12) | 79,875 → 159,628 | +99.85% | 0.676 → 0.659 | -2.53% | 1: B 64,928–82,986; C 146,621–161,028<br>2: B 79,801–80,648; C 149,714–162,405<br>3: B 67,732–79,948; C 159,562–159,694 |
| H1 | pagecache | complete (12/12) | 50,462 → 166,570 | +230.09% | 0.914 → 0.630 | -31.10% | 1: B 50,161–50,886; C 166,649–169,614<br>2: B 46,166–50,762; C 159,642–170,083<br>3: B 49,084–51,083; C 163,855–166,492 |
| H1 TLS | static | complete (12/12) | 63,209 → 60,762 | -3.87% | 0.925 → 1.206 | +30.34% | 1: B 63,995–64,986; C 30,318–76,085<br>2: B 23,015–62,423; C 54,034–67,489<br>3: B 15,654–68,652; C 40,739–68,469 |
| H1 TLS | pagecache | complete (12/12) | 40,107 → 73,567 | +83.43% | 1.449 → 0.725 | -49.93% | 1: B 38,725–39,487; C 60,650–66,894<br>2: B 40,727–41,223; C 73,467–74,883<br>3: B 37,003–42,966; C 73,667–74,375 |
| H2c | static | complete (12/12) | 117,313 → 170,671 | +45.48% | 1.902 → 4.612 | +142.47% | 1: B 104,813–109,135; C 129,047–162,375<br>2: B 118,384–118,663; C 171,229–187,149<br>3: B 116,242–120,411; C 170,113–180,681 |
| H2c | pagecache | complete (12/12) | 59,381 → 157,493 | +165.22% | 3.835 → 4.818 | +25.61% | 1: B 60,168–61,347; C 156,378–158,607<br>2: B 57,899–59,902; C 148,659–175,569<br>3: B 54,576–58,860; C 156,353–183,722 |
| H2 TLS | static | complete (12/12) | 65,228 → 65,389 | +0.25% | 3.445 → 4.066 | +18.02% | 1: B 65,556–68,408; C 60,467–71,970<br>2: B 63,576–71,021; C 70,311–74,890<br>3: B 56,593–64,900; C 45,212–54,502 |
| H2 TLS | pagecache | complete (12/12) | 33,193 → 55,807 | +68.13% | 7.927 → 5.477 | -30.91% | 1: B 26,557–29,800; C 48,334–55,830<br>2: B 27,138–36,780; C 46,942–60,626<br>3: B 36,586–36,738; C 55,784–59,763 |
| H3 | static | complete (12/12) | 13,648 → 38,797 | +184.27% | 19.048 → 7.397 | -61.16% | 1: B 13,546–14,920; C 34,486–40,004<br>2: B 12,780–12,794; C 40,304–40,681<br>3: B 13,750–16,211; C 22,951–37,591 |
| H3 | pagecache | complete (12/12) | 22,816 → 37,971 | +66.42% | 10.803 → 6.944 | -35.72% | 1: B 22,609–23,023; C 37,388–38,554<br>2: B 24,446–25,203; C 42,158–42,764<br>3: B 7,259–16,031; C 33,643–35,581 |

| Protocol / fixture | Process CPU µs/R B → C (Δ) | User instructions/R B → C (Δ) | User cycles/R B → C (Δ) | VM busy ticks/R B → C (Δ) | Kernel hit % B → C |
| --- | --- | --- | --- | --- | --- |
| H1 / static | 12.50 → 1.57 (-87.43%) | 27,564 → 6,496 (-76.43%) | 26,335 → 3,890 (-85.23%) | 0.00422 → 0.00387 (-8.29%) | n/a → 99.98 |
| H1 / pagecache | 19.74 → 1.36 (-93.12%) | 61,604 → 6,514 (-89.43%) | 60,607 → 3,336 (-94.50%) | 0.00553 → 0.00366 (-33.74%) | n/a → 99.92 |
| H1 TLS / static | 15.88 → 16.60 (+4.50%) | 36,730 → 34,778 (-5.32%) | 40,697 → 39,283 (-3.47%) | 0.00551 → 0.00589 (+6.87%) | n/a → 0.00 |
| H1 TLS / pagecache | 24.81 → 13.55 (-45.39%) | 71,876 → 36,294 (-49.50%) | 81,601 → 32,049 (-60.72%) | 0.00699 → 0.00487 (-30.32%) | n/a → 0.00 |
| H2c / static | 8.52 → 5.38 (-36.87%) | 32,239 → 13,288 (-58.78%) | 26,297 → 10,797 (-58.94%) | 0.00321 → 0.00367 (+14.24%) | n/a → 82.08 |
| H2c / pagecache | 16.79 → 5.83 (-65.25%) | 67,107 → 13,714 (-79.56%) | 62,167 → 11,265 (-81.88%) | 0.00475 → 0.00385 (-18.93%) | n/a → 81.75 |
| H2 TLS / static | 15.36 → 15.55 (+1.24%) | 36,966 → 34,891 (-5.61%) | 42,103 → 41,459 (-1.53%) | 0.00628 → 0.00637 (+1.56%) | n/a → 0.00 |
| H2 TLS / pagecache | 30.52 → 17.90 (-41.34%) | 72,346 → 36,508 (-49.54%) | 97,496 → 47,712 (-51.06%) | 0.00997 → 0.00715 (-28.21%) | n/a → 0.00 |
| H3 / static | 73.31 → 26.17 (-64.31%) | 127,078 → 60,690 (-52.24%) | 201,141 → 85,751 (-57.37%) | 0.01831 → 0.01063 (-41.95%) | n/a → n/a |
| H3 / pagecache | 43.79 → 26.45 (-39.59%) | 121,558 → 63,147 (-48.05%) | 140,238 → 88,253 (-37.07%) | 0.01271 → 0.01096 (-13.75%) | n/a → n/a |

### 32 KiB

| Protocol | Fixture | Status / arms | RPS B → C | Δ RPS | p99 ms B → C | Δ p99 | RPS range per cycle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H1 | static | complete (12/12) | 49,345 → 47,483 | -3.77% | 2.091 → 2.315 | +10.71% | 1: B 46,816–55,758; C 48,324–53,136<br>2: B 42,607–51,874; C 42,126–52,803<br>3: B 44,639–53,438; C 40,648–46,641 |
| H1 | pagecache | complete (12/12) | 33,325 → 47,567 | +42.74% | 3.415 → 2.654 | -22.28% | 1: B 34,015–36,503; C 44,238–49,166<br>2: B 27,540–37,020; C 45,968–54,633<br>3: B 32,033–32,635; C 44,958–52,645 |
| H1 TLS | static | complete (12/12) | 26,742 → 24,799 | -7.27% | 3.688 → 4.172 | +13.14% | 1: B 26,699–27,059; C 26,949–28,681<br>2: B 24,648–27,998; C 22,168–24,760<br>3: B 26,171–26,785; C 24,411–24,837 |
| H1 TLS | pagecache | complete (12/12) | 15,629 → 26,473 | +69.38% | 5.412 → 3.894 | -28.04% | 1: B 16,572–16,750; C 25,332–28,244<br>2: B 8,239–11,065; C 24,354–25,340<br>3: B 15,536–15,722; C 27,606–28,240 |
| H2c | static | complete (12/12) | 63,682 → 60,976 | -4.25% | 5.249 → 5.389 | +2.66% | 1: B 63,872–66,748; C 59,015–60,718<br>2: B 63,493–66,613; C 51,802–61,234<br>3: B 61,862–62,188; C 64,428–64,688 |
| H2c | pagecache | complete (12/12) | 37,209 → 60,592 | +62.84% | 8.702 → 5.594 | -35.72% | 1: B 43,731–46,495; C 62,012–70,101<br>2: B 30,687–45,837; C 59,172–62,247<br>3: B 26,184–29,289; C 33,116–51,624 |
| H2 TLS | static | complete (12/12) | 24,862 → 23,728 | -4.56% | 9.379 → 11.798 | +25.79% | 1: B 7,986–27,187; C 20,898–23,203<br>2: B 22,439–26,568; C 24,253–24,750<br>3: B 24,255–25,468; C 20,805–24,662 |
| H2 TLS | pagecache | complete (12/12) | 20,762 → 24,309 | +17.09% | 10.874 → 9.885 | -9.09% | 1: B 19,910–20,875; C 24,366–24,638<br>2: B 21,258–21,446; C 22,430–25,028<br>3: B 20,216–20,648; C 23,789–24,252 |
| H3 | static | complete (12/12) | 8,107 → 15,242 | +88.02% | 27.014 → 14.505 | -46.31% | 1: B 8,161–8,275; C 14,572–15,665<br>2: B 7,752–7,779; C 15,229–15,255<br>3: B 8,052–8,215; C 14,496–15,397 |
| H3 | pagecache | complete (12/12) | 9,303 → 15,555 | +67.21% | 25.237 → 13.845 | -45.14% | 1: B 9,279–9,523; C 13,940–15,365<br>2: B 8,449–9,327; C 12,059–16,175<br>3: B 8,565–9,479; C 15,745–16,076 |

| Protocol / fixture | Process CPU µs/R B → C (Δ) | User instructions/R B → C (Δ) | User cycles/R B → C (Δ) | VM busy ticks/R B → C (Δ) | Kernel hit % B → C |
| --- | --- | --- | --- | --- | --- |
| H1 / static | 20.10 → 20.88 (+3.91%) | 27,628 → 29,554 (+6.97%) | 31,873 → 32,694 (+2.58%) | 0.00653 → 0.00688 (+5.36%) | n/a → 0.00 |
| H1 / pagecache | 30.05 → 20.98 (-30.19%) | 61,729 → 30,577 (-50.47%) | 73,537 → 33,089 (-55.00%) | 0.00835 → 0.00700 (-16.09%) | n/a → 0.00 |
| H1 TLS / static | 37.26 → 40.12 (+7.67%) | 110,431 → 108,402 (-1.84%) | 90,920 → 93,469 (+2.80%) | 0.01078 → 0.01142 (+5.92%) | n/a → 0.00 |
| H1 TLS / pagecache | 63.45 → 37.98 (-40.15%) | 145,660 → 109,766 (-24.64%) | 160,983 → 89,846 (-44.19%) | 0.01344 → 0.01075 (-19.98%) | n/a → 0.00 |
| H2c / static | 15.67 → 16.29 (+3.95%) | 32,850 → 33,140 (+0.88%) | 29,511 → 30,766 (+4.25%) | 0.00634 → 0.00695 (+9.69%) | n/a → 0.00 |
| H2c / pagecache | 28.14 → 16.43 (-41.62%) | 67,774 → 34,741 (-48.74%) | 72,777 → 31,476 (-56.75%) | 0.00881 → 0.00665 (-24.51%) | n/a → 0.00 |
| H2 TLS / static | 40.26 → 42.10 (+4.55%) | 113,610 → 111,407 (-1.94%) | 87,650 → 88,032 (+0.44%) | 0.01500 → 0.01552 (+3.44%) | n/a → 0.00 |
| H2 TLS / pagecache | 48.21 → 41.07 (-14.81%) | 148,924 → 112,992 (-24.13%) | 127,743 → 88,349 (-30.84%) | 0.01625 → 0.01501 (-7.61%) | n/a → 0.00 |
| H3 / static | 123.60 → 66.00 (-46.60%) | 330,873 → 261,072 (-21.10%) | 330,465 → 198,675 (-39.88%) | 0.03759 → 0.02473 (-34.22%) | n/a → n/a |
| H3 / pagecache | 107.24 → 64.45 (-39.90%) | 324,065 → 263,306 (-18.75%) | 301,696 → 195,353 (-35.25%) | 0.03339 → 0.02446 (-26.75%) | n/a → n/a |

## Rebuilt native-source baseline comparison

### 1 KiB

| Protocol | Fixture | Status / arms | RPS B → C | Δ RPS | p99 ms B → C | Δ p99 | RPS range per cycle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H1 | static | complete (12/12) | 76,122 → 124,342 | +63.35% | 0.977 → 0.943 | -3.50% | 1: B 71,541–78,018; C 122,168–135,736<br>2: B 75,561–79,172; C 117,504–126,633<br>3: B 75,746–76,499; C 121,055–126,516 |
| H1 | pagecache | complete (12/12) | 42,761 → 118,886 | +178.02% | 2.448 → 1.028 | -57.98% | 1: B 37,880–48,270; C 114,454–139,208<br>2: B 41,046–46,366; C 118,624–121,962<br>3: B 40,399–44,477; C 115,962–119,148 |
| H1 TLS | static | complete (12/12) | 62,001 → 62,444 | +0.72% | 1.485 → 1.301 | -12.35% | 1: B 59,931–62,178; C 62,885–68,703<br>2: B 61,824–68,397; C 57,749–62,004<br>3: B 58,172–63,315; C 58,647–64,569 |
| H1 TLS | pagecache | complete (12/12) | 37,681 → 58,699 | +55.78% | 2.687 → 1.553 | -42.20% | 1: B 35,675–37,221; C 54,626–57,485<br>2: B 34,681–42,010; C 58,194–64,811<br>3: B 38,141–42,153; C 59,204–62,042 |
| H2c | static | complete (12/12) | 117,224 → 171,522 | +46.32% | 3.863 → 6.084 | +57.48% | 1: B 112,936–118,502; C 154,824–173,484<br>2: B 111,537–126,650; C 171,599–179,953<br>3: B 115,946–130,922; C 160,093–171,444 |
| H2c | pagecache | complete (12/12) | 53,806 → 139,647 | +159.54% | 5.941 → 6.862 | +15.49% | 1: B 46,899–61,130; C 165,622–176,083<br>2: B 30,941–50,615; C 77,388–140,881<br>3: B 56,997–60,414; C 131,909–138,414 |
| H2 TLS | static | complete (12/12) | 63,363 → 61,938 | -2.25% | 5.744 → 5.548 | -3.41% | 1: B 16,426–55,222; C 47,772–55,872<br>2: B 71,503–75,585; C 62,503–68,669<br>3: B 54,900–72,173; C 61,373–69,332 |
| H2 TLS | pagecache | complete (12/12) | 41,396 → 64,192 | +55.07% | 6.684 → 5.253 | -21.41% | 1: B 40,913–43,377; C 65,486–69,261<br>2: B 40,282–41,878; C 58,500–59,738<br>3: B 34,922–42,413; C 62,897–67,669 |
| H3 | static | complete (12/12) | 15,786 → 39,634 | +151.07% | 15.830 → 7.393 | -53.30% | 1: B 15,915–16,031; C 38,563–39,724<br>2: B 15,657–16,093; C 42,976–43,305<br>3: B 14,887–15,140; C 38,275–39,544 |
| H3 | pagecache | complete (12/12) | 25,735 → 42,663 | +65.78% | 10.467 → 6.959 | -33.51% | 1: B 22,413–25,992; C 39,654–40,644<br>2: B 25,479–26,876; C 42,656–42,671<br>3: B 24,239–27,345; C 44,756–46,700 |

| Protocol / fixture | Process CPU µs/R B → C (Δ) | User instructions/R B → C (Δ) | User cycles/R B → C (Δ) | VM busy ticks/R B → C (Δ) | Kernel hit % B → C |
| --- | --- | --- | --- | --- | --- |
| H1 / static | 12.98 → 2.29 (-82.39%) | 24,663 → 6,530 (-73.52%) | 23,181 → 5,228 (-77.45%) | 0.00457 → 0.00484 (+5.89%) | n/a → 99.98 |
| H1 / pagecache | 23.19 → 2.40 (-89.63%) | 57,065 → 6,573 (-88.48%) | 62,978 → 5,581 (-91.14%) | 0.00676 → 0.00505 (-25.39%) | n/a → 99.88 |
| H1 TLS / static | 15.90 → 16.00 (+0.60%) | 34,129 → 34,780 (+1.91%) | 36,127 → 36,795 (+1.85%) | 0.00565 → 0.00555 (-1.64%) | n/a → 0.00 |
| H1 TLS / pagecache | 26.43 → 16.98 (-35.77%) | 67,546 → 36,295 (-46.27%) | 80,797 → 38,418 (-52.45%) | 0.00769 → 0.00570 (-25.87%) | n/a → 0.00 |
| H2c / static | 8.33 → 5.52 (-33.71%) | 29,768 → 11,667 (-60.81%) | 22,354 → 9,396 (-57.97%) | 0.00311 → 0.00367 (+17.90%) | n/a → 86.37 |
| H2c / pagecache | 18.67 → 6.57 (-64.80%) | 62,691 → 11,794 (-81.19%) | 63,609 → 11,373 (-82.12%) | 0.00538 → 0.00444 (-17.51%) | n/a → 86.66 |
| H2 TLS / static | 16.00 → 16.12 (+0.74%) | 34,586 → 34,883 (+0.86%) | 40,171 → 41,763 (+3.96%) | 0.00653 → 0.00658 (+0.69%) | n/a → 0.00 |
| H2 TLS / pagecache | 24.10 → 15.45 (-35.87%) | 68,072 → 36,511 (-46.36%) | 73,926 → 40,262 (-45.54%) | 0.00806 → 0.00619 (-23.24%) | n/a → 0.00 |
| H3 / static | 63.36 → 25.33 (-60.02%) | 123,341 → 59,025 (-52.14%) | 162,414 → 81,298 (-49.94%) | 0.01566 → 0.01045 (-33.27%) | n/a → n/a |
| H3 / pagecache | 38.98 → 23.52 (-39.65%) | 117,333 → 60,791 (-48.19%) | 117,847 → 75,980 (-35.53%) | 0.01132 → 0.01006 (-11.16%) | n/a → n/a |

### 32 KiB

| Protocol | Fixture | Status / arms | RPS B → C | Δ RPS | p99 ms B → C | Δ p99 | RPS range per cycle |
| --- | --- | --- | --- | --- | --- | --- | --- |
| H1 | static | complete (12/12) | 57,969 → 56,733 | -2.13% | 1.468 → 1.392 | -5.18% | 1: B 55,533–61,158; C 55,421–56,211<br>2: B 49,192–58,095; C 52,919–57,255<br>3: B 57,844–58,485; C 58,715–60,752 |
| H1 | pagecache | complete (12/12) | 41,217 → 54,500 | +32.23% | 1.997 → 1.576 | -21.09% | 1: B 40,166–42,944; C 50,065–51,058<br>2: B 42,268–43,747; C 55,830–56,973<br>3: B 35,061–40,041; C 53,371–55,629 |
| H1 TLS | static | complete (12/12) | 26,506 → 26,529 | +0.09% | 3.853 → 3.957 | +2.71% | 1: B 25,460–26,327; C 26,668–27,019<br>2: B 26,684–26,706; C 26,391–26,908<br>3: B 22,528–26,696; C 22,774–26,279 |
| H1 TLS | pagecache | complete (12/12) | 16,638 → 23,678 | +42.31% | 5.284 → 4.450 | -15.79% | 1: B 16,841–17,634; C 23,475–26,966<br>2: B 15,125–17,021; C 21,610–24,045<br>3: B 16,095–16,435; C 22,379–23,880 |
| H2c | static | complete (12/12) | 60,024 → 56,134 | -6.48% | 6.054 → 5.903 | -2.50% | 1: B 62,116–66,837; C 45,624–54,798<br>2: B 57,932–62,830; C 42,951–63,664<br>3: B 46,655–54,043; C 57,470–58,076 |
| H2c | pagecache | complete (12/12) | 45,315 → 56,772 | +25.28% | 6.385 → 5.675 | -11.12% | 1: B 37,660–43,076; C 54,739–56,136<br>2: B 43,798–47,330; C 56,342–57,202<br>3: B 46,833–46,895; C 59,639–61,375 |
| H2 TLS | static | complete (12/12) | 24,500 → 24,612 | +0.46% | 10.463 → 9.791 | -6.42% | 1: B 24,764–26,977; C 24,320–24,905<br>2: B 24,236–26,120; C 25,193–25,537<br>3: B 19,293–23,376; C 17,275–21,678 |
| H2 TLS | pagecache | complete (12/12) | 20,396 → 24,372 | +19.49% | 11.821 → 9.891 | -16.33% | 1: B 14,648–17,476; C 18,939–20,755<br>2: B 20,282–21,046; C 24,237–24,507<br>3: B 20,511–21,463; C 25,268–25,385 |
| H3 | static | complete (12/12) | 7,643 → 13,171 | +72.33% | 29.412 → 18.549 | -36.93% | 1: B 7,454–7,727; C 12,975–13,368<br>2: B 7,571–7,716; C 12,537–13,508<br>3: B 7,334–7,743; C 11,556–13,707 |
| H3 | pagecache | complete (12/12) | 8,049 → 11,041 | +37.17% | 29.310 → 25.917 | -11.57% | 1: B 7,968–8,059; C 10,846–11,236<br>2: B 8,039–9,424; C 11,343–14,813<br>3: B 7,780–8,074; C 8,876–9,283 |

| Protocol / fixture | Process CPU µs/R B → C (Δ) | User instructions/R B → C (Δ) | User cycles/R B → C (Δ) | VM busy ticks/R B → C (Δ) | Kernel hit % B → C |
| --- | --- | --- | --- | --- | --- |
| H1 / static | 17.55 → 17.26 (-1.63%) | 24,725 → 29,554 (+19.53%) | 24,102 → 26,635 (+10.51%) | 0.00602 → 0.00570 (-5.26%) | n/a → 0.00 |
| H1 / pagecache | 24.14 → 18.14 (-24.85%) | 57,168 → 30,575 (-46.52%) | 55,887 → 28,073 (-49.77%) | 0.00710 → 0.00625 (-12.00%) | n/a → 0.00 |
| H1 TLS / static | 37.48 → 37.57 (+0.25%) | 107,761 → 108,405 (+0.60%) | 88,907 → 88,910 (+0.00%) | 0.01118 → 0.01091 (-2.43%) | n/a → 0.00 |
| H1 TLS / pagecache | 59.64 → 42.29 (-29.10%) | 141,405 → 109,767 (-22.37%) | 153,177 → 98,205 (-35.89%) | 0.01321 → 0.01237 (-6.38%) | n/a → 0.00 |
| H2c / static | 16.52 → 17.74 (+7.35%) | 30,388 → 33,140 (+9.06%) | 27,496 → 31,797 (+15.64%) | 0.00719 → 0.00732 (+1.79%) | n/a → 0.00 |
| H2c / pagecache | 21.98 → 17.33 (-21.13%) | 63,409 → 34,758 (-45.19%) | 57,129 → 32,973 (-42.28%) | 0.00750 → 0.00720 (-4.00%) | n/a → 0.00 |
| H2 TLS / static | 40.62 → 40.45 (-0.41%) | 111,123 → 111,409 (+0.26%) | 85,213 → 86,532 (+1.55%) | 0.01522 → 0.01499 (-1.52%) | n/a → 0.00 |
| H2 TLS / pagecache | 48.86 → 41.26 (-15.55%) | 144,636 → 112,998 (-21.87%) | 124,915 → 88,696 (-29.00%) | 0.01679 → 0.01516 (-9.71%) | n/a → 0.00 |
| H3 / static | 131.14 → 76.36 (-41.78%) | 328,716 → 261,058 (-20.58%) | 343,230 → 225,261 (-34.37%) | 0.03932 → 0.02783 (-29.23%) | n/a → n/a |
| H3 / pagecache | 124.43 → 90.95 (-26.90%) | 322,541 → 263,241 (-18.39%) | 340,180 → 268,053 (-21.20%) | 0.03824 → 0.03242 (-15.21%) | n/a → n/a |

## Failure and missing-evidence ledger

No failed or missing cells are recorded. The matrix status above still governs whether completion evidence is present.
