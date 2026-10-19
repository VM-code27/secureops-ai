"""Build SecureOps_AI_Documentation.pdf (plain-language guide) from the latest measured results.

    python docs/build_documentation.py

Needs Playwright with Microsoft Edge or Chromium installed (pip install playwright).
"""
from __future__ import annotations

import base64
import html
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "SecureOps_AI_Documentation.pdf"
M = json.loads((ROOT / "reports" / "metrics.json").read_text())
T = M["test"]
DET, RULES, ANOM = T["detection_combined"], T["detection_rules_only"], T["detection_anomaly_only"]
COR, PRI = T["correlation"], T["prioritisation"]
LLM = M.get("llm_reliability") or {}

BLUE, ORANGE, GREEN, RED, GOLD, INK, INK2, MUTED, GRID = (
    "#2a78d6", "#eb6834", "#1baf7a", "#d03b3b", "#c98500", "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1")


def img(name: str) -> str:
    data = base64.b64encode((ROOT / "docs" / name).read_bytes()).decode()
    return f"data:image/png;base64,{data}"


def pct(x: float, d: int = 0) -> str:
    return f"{x * 100:.{d}f}%"


def bars(rows: list[tuple[str, float, str]], unit: str = "%") -> str:
    out = []
    for label, val, note in rows:
        out.append(f"<div class='brow'><div class='blab'>{html.escape(label)}</div><div class='btrack'>"
                   f"<div class='bfill' style='width:{max(val, 0.5):.1f}%'></div></div>"
                   f"<div class='bval'>{val:.0f}{unit}</div><div class='bnote'>{html.escape(note)}</div></div>")
    return "<div class='bars'>" + "".join(out) + "</div>"


PIPELINE = f"""
<svg viewBox="0 0 980 190" width="100%" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial" font-size="13">
  <defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
  <path d="M0 0L10 5L0 10z" fill="{MUTED}"/></marker></defs>
  {''.join(f'''<g transform="translate({20 + i * 137},40)">
    <rect width="118" height="96" rx="14" fill="{bg}" stroke="{c}" stroke-width="1.5"/>
    <text x="59" y="30" text-anchor="middle" font-weight="700" fill="{c}" font-size="22">{n}</text>
    <text x="59" y="56" text-anchor="middle" font-weight="600" fill="{INK}">{t1}</text>
    <text x="59" y="74" text-anchor="middle" fill="{INK2}" font-size="11.5">{t2}</text>
    </g>''' + (f'<line x1="{140 + i * 137}" y1="88" x2="{155 + i * 137}" y2="88" stroke="{MUTED}" stroke-width="2" marker-end="url(#a)"/>' if i < 6 else '')
    for i, (n, t1, t2, c, bg) in enumerate([
        ("1", "Collect", "network events", BLUE, "#eef4fc"), ("2", "Map", "your computers", BLUE, "#eef4fc"),
        ("3", "Detect", "rules + AI model", ORANGE, "#fdeee6"), ("4", "Group", "alerts → cases", ORANGE, "#fdeee6"),
        ("5", "Rank", "by real risk", GOLD, "#fdf5e3"), ("6", "Explain", "plain English", GREEN, "#e8f7f0"),
        ("7", "Respond", "analyst decides", GREEN, "#e8f7f0")]))}
  <text x="490" y="170" text-anchor="middle" fill="{MUTED}" font-size="12">Steps 1-6 run automatically every few seconds; step 7 always stays with a human.</text>
</svg>"""

FUNNEL = f"""
<svg viewBox="0 0 640 170" width="100%" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial" font-size="13">
  <rect x="20" y="20" width="600" height="38" rx="8" fill="#eef4fc" stroke="{BLUE}"/>
  <text x="320" y="44" text-anchor="middle" fill="{INK}"><tspan font-weight="700">{T['data']['events']:,}</tspan> network events in 13 days</text>
  <rect x="120" y="70" width="400" height="38" rx="8" fill="#fdeee6" stroke="{ORANGE}"/>
  <text x="320" y="94" text-anchor="middle" fill="{INK}"><tspan font-weight="700">{COR['alerts']:,}</tspan> alerts raised</text>
  <rect x="220" y="120" width="200" height="38" rx="8" fill="#e8f7f0" stroke="{GREEN}"/>
  <text x="320" y="144" text-anchor="middle" fill="{INK}"><tspan font-weight="700">{COR['incidents']}</tspan> cases to review</text>
</svg>"""

pt = {p["tactic"]: p for p in T["per_tactic"]}
TACTIC_ROWS = [(t, 100 * pt[t]["windows_detected"], f"{pt[t]['events']:,} attack connections")
               for t in ["Credential Access", "Initial Access", "Reconnaissance", "Persistence", "Exfiltration"] if t in pt]

GLOSSARY = [
    ("Alert", "A single warning raised by one detection rule or the AI model, for example 'too many login attempts in 5 minutes'."),
    ("Incident / case", "A group of related alerts that together describe one attack or event. This is what a person reviews."),
    ("Zeek", "Free, widely used network-monitoring software. It writes one line for every connection: who talked to whom, on which port, how much data."),
    ("Suricata", "Free intrusion-detection software. It compares traffic with tens of thousands of known attack patterns ('signatures')."),
    ("MITRE ATT&CK", "A public encyclopedia of attacker behaviour (e.g. 'Brute Force', 'Reconnaissance') used worldwide to label attacks."),
    ("CVE", "A public ID for a known software weakness, e.g. CVE-2021-41773."),
    ("CVSS", "A 0-10 severity score for a CVE."),
    ("CISA KEV", "The US government's list of weaknesses that criminals are known to be exploiting right now."),
    ("EPSS", "A probability (0-100%) that a weakness will be exploited in the next 30 days."),
    ("Threat intelligence", "Public lists of addresses known to be malicious, such as botnet control servers."),
    ("Isolation Forest", "A machine-learning method that spots behaviour which is unusual compared with everything else it has seen."),
    ("Precision", "When the system raises an alarm, how often it is a real attack."),
    ("Recall", "Of all the real attacks, how many the system noticed."),
    ("False positive", "An alarm about something harmless."),
    ("SLA", "The deadline for handling a case, set by its severity (e.g. Critical within 1 hour)."),
    ("LLM", "Large language model - the AI that writes plain-English explanations (here: a free Groq-hosted model)."),
    ("Sensor", "A small computer running Zeek and Suricata that watches a network and sends what it sees to SecureOps AI."),
]

page = f"""<!doctype html><html><head><meta charset="utf-8"><title>SecureOps AI - Documentation</title>
<style>
@page {{ size: A4; margin: 16mm 15mm 16mm 15mm; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; color:{INK}; font-size: 10.6pt; line-height: 1.55; }}
h1 {{ font-size: 25pt; margin: 0 0 4px; }} h2 {{ font-size: 16pt; margin: 0 0 8px; color:{INK}; border-bottom: 2px solid {GRID}; padding-bottom: 4px; }}
h3 {{ font-size: 12pt; margin: 16px 0 4px; }} p {{ margin: 6px 0; }} .muted {{ color:{MUTED}; }} .ink2 {{ color:{INK2}; }}
section {{ page-break-after: always; }} section:last-child {{ page-break-after: auto; }}
.cover {{ display:flex; flex-direction:column; justify-content:center; min-height: 240mm; }}
.lead {{ font-size: 13pt; color:{INK2}; max-width: 150mm; }}
.box {{ border:1px solid {GRID}; border-radius: 10px; padding: 10px 14px; margin: 10px 0; background: #fafaf9; }}
.callout {{ border-left: 4px solid {BLUE}; background:#eef4fc; padding: 8px 12px; border-radius: 6px; margin: 10px 0; }}
.warn {{ border-left: 4px solid {GOLD}; background:#fdf5e3; padding: 8px 12px; border-radius: 6px; margin: 10px 0; }}
.grid {{ display:grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 10px 0; }}
.kpi {{ border:1px solid {GRID}; border-radius: 10px; padding: 8px 10px; }}
.kpi b {{ display:block; font-size: 19pt; line-height:1.2; }} .kpi span {{ color:{INK2}; font-size: 9pt; }}
table {{ border-collapse: collapse; width:100%; margin: 8px 0; font-size: 9.6pt; }}
th, td {{ text-align:left; padding: 5px 7px; border-bottom: 1px solid {GRID}; vertical-align: top; }}
th {{ background:#f6f7f9; font-weight:600; }}
img.shot {{ width:100%; max-height:102mm; object-fit:cover; object-position:top; border:1px solid {GRID}; border-radius: 8px; margin: 6px 0; }}
.bars {{ margin: 8px 0; }} .brow {{ display:grid; grid-template-columns: 34mm 1fr 14mm 46mm; gap:8px; align-items:center; margin:5px 0; }}
.blab {{ font-size:9.5pt; }} .btrack {{ height:10px; background:{GRID}; border-radius:6px; overflow:hidden; }}
.bfill {{ height:100%; background:{BLUE}; border-radius:6px; }} .bval {{ font-weight:600; font-size:9.5pt; }} .bnote {{ color:{MUTED}; font-size:8.8pt; }}
.chat {{ border:1px solid {GRID}; border-radius:10px; padding:8px 12px; margin:6px 0; }}
.q {{ font-weight:600; }} .tag {{ display:inline-block; font-size:8.5pt; padding:0 7px; border-radius:999px; border:1px solid currentColor; }}
.two {{ display:grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
ul {{ margin: 4px 0 6px 18px; padding:0; }} li {{ margin: 2px 0; }}
</style></head><body>

<section class="cover">
  <svg width="64" height="64" viewBox="0 0 24 24"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="{BLUE}"/>
  <path d="M8.5 12.2l2.3 2.3 4.7-4.9" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
  <h1>SecureOps AI</h1>
  <p class="lead">Intelligent threat detection and response - explained in plain language.</p>
  <p class="lead" style="margin-top:18px">A guide to what the system does, where its data comes from, how its AI models decide
  what is dangerous, how well it actually performs on real attack data, and where it falls short.</p>
  <div class="box" style="max-width:150mm; margin-top:22px">
    <b>In one sentence:</b> SecureOps AI watches network traffic, spots attacks with rules and a machine-learning
    model, groups hundreds of warnings into a few cases, ranks them by real risk, explains each one in plain English
    with proof attached, and lets a human decide what to do.
  </div>
  <p class="muted" style="margin-top:30px">Author: Vimala Mehrotra · Version {date.today():%B %Y} · Results generated {M['generated_at'][:10]}</p>
</section>

<section>
  <h2>1. The problem it solves</h2>
  <p>Every company network produces an enormous number of events - every web page, every login, every device checking
  in. Security tools raise warnings on the suspicious ones, but they raise <b>so many</b> that analysts cannot read
  them all. Real attacks get lost in the noise, and people burn out.</p>
  <p>SecureOps AI tackles this in three ways:</p>
  <ul>
    <li><b>Fewer, better items to read.</b> Related warnings are merged into a single case, so one attack becomes one
    case instead of hundreds of alerts.</li>
    <li><b>Most dangerous first.</b> Each case gets a 0-100 risk score that combines how sure we are it is an attack,
    how important the affected computer is, and whether it has known weaknesses that criminals are exploiting today.</li>
    <li><b>Explained, with proof.</b> An AI assistant writes a short explanation in plain English. Every sentence
    points to the exact log lines it is based on, and a checker rejects anything that is not backed by evidence.</li>
  </ul>
  <h3>On real attack data, over 13 days the system had never seen:</h3>
  {FUNNEL}
  <div class="grid">
    <div class="kpi"><b>{pct(DET['precision'])}</b><span>of alarms were real attacks</span></div>
    <div class="kpi"><b>{pct(COR['alert_reduction'])}</b><span>fewer items for an analyst to read</span></div>
    <div class="kpi"><b>{pct(DET['false_positive_rate'], 1)}</b><span>of normal activity wrongly flagged</span></div>
    <div class="kpi"><b>{pct(LLM.get('sentence_support_rate', 0))}</b><span>of AI sentences backed by evidence ({LLM.get('sentences', 0)} checked)</span></div>
  </div>
  <div class="warn"><b>Honest headline:</b> it is very accurate when it raises an alarm, but it notices about
  {pct(DET['recall'])} of attack activity. Password-guessing attacks are caught well; quiet, single-connection
  attacks are mostly missed. Section 7 explains why.</div>
</section>

<section>
  <h2>2. How it works - the seven steps</h2>
  {PIPELINE}
  <table>
    <tr><th style="width:24mm">Step</th><th>What happens, in plain words</th></tr>
    <tr><td><b>1 Collect</b></td><td>Network events arrive continuously. Each event says which computer talked to which,
      on which "door" (port), for how long and how much data moved.</td></tr>
    <tr><td><b>2 Map</b></td><td>The system learns which computers exist, what services they offer (web, file sharing,
      email...) and how many others depend on them. Busy, widely used servers are treated as more important. Owners can
      correct this with an inventory file.</td></tr>
    <tr><td><b>3 Detect</b></td><td>Eight detection rules look for known attack patterns, and an AI model looks for
      anything unusual. Each produces <i>alerts</i> (section 4).</td></tr>
    <tr><td><b>4 Group</b></td><td>Alerts that involve the same computer within two hours are joined into one
      <i>incident</i>, like puzzle pieces forming one picture. A scan, followed by a break-in attempt, followed by
      data theft from the same machine becomes one story.</td></tr>
    <tr><td><b>5 Rank</b></td><td>Each incident gets a 0-100 score and a severity (Critical / High / Medium / Low) with a
      deadline: Critical 1 hour, High 4 hours, Medium 1 day, Low 3 days (section 5).</td></tr>
    <tr><td><b>6 Explain</b></td><td>The AI assistant writes what happened, why it matters, what to check next and what
      is still unknown - citing the evidence for every sentence (section 6).</td></tr>
    <tr><td><b>7 Respond</b></td><td>An analyst assigns an owner, approves actions (block an address, isolate a computer,
      mark as harmless) and closes the case. Every click is recorded in an audit trail. <b>Nothing is blocked
      automatically.</b></td></tr>
  </table>
</section>

<section>
  <h2>3. Where the data comes from</h2>
  <p>Nothing in the system is made up. Every input is real and most of it is fetched live from public sources.</p>
  <table>
    <tr><th>Source</th><th>What it is</th><th>Is it your network?</th></tr>
    <tr><td><b>Dataset replay</b><br><span class="muted">UWF-ZeekData24</span></td><td>Real network recordings made by the
      University of West Florida, who attacked their own test network and labelled every attack. About 191,000
      connections over 18 days, replayed as if happening now.</td><td>No - their 2024 lab network
      (addresses 143.88.x.x). It guarantees real attacks to detect and lets us measure accuracy.</td></tr>
    <tr><td><b>Live sensor</b></td><td>Zeek + Suricata running on a computer you control, sending what they see to the
      system every few seconds.</td><td>Only the network the sensor is connected to. In the current test setup it runs
      inside Docker on the laptop, so it sees container traffic only, not the home Wi-Fi.</td></tr>
    <tr><td><b>Threat intelligence</b></td><td>abuse.ch Feodo Tracker (botnet servers), abuse.ch URLhaus (malware
      sites) and Spamhaus DROP (criminal networks), refreshed every 6 hours.</td><td>Public lists</td></tr>
    <tr><td><b>Vulnerabilities</b></td><td>US National Vulnerability Database, CISA "known exploited" list and FIRST
      EPSS exploit probabilities.</td><td>Public lists</td></tr>
    <tr><td><b>Attack knowledge</b></td><td>MITRE ATT&amp;CK - the standard catalogue of 700+ attacker techniques.</td>
      <td>Public</td></tr>
  </table>
  <div class="callout"><b>Is my network being attacked?</b> Incidents tagged <i>replay</i> are recorded attacks on
  someone else's lab. Incidents tagged <i>live</i> come from your sensor. To watch a real home or office network, the
  sensor must sit where the traffic passes - for example a Raspberry Pi connected to a router port that copies all
  traffic.</div>
  <p class="ink2">The replay's attack days and normal days were recorded in different weeks, so the system overlays
  them day by day (keeping each one's real time of day). This is stated wherever results are reported.</p>
</section>

<section>
  <h2>4. The detection models</h2>
  <h3>Rules - known attack patterns</h3>
  <table>
    <tr><th style="width:44mm">Rule</th><th>Fires when...</th><th style="width:30mm">Attack type</th></tr>
    <tr><td>Repeated connection attempts</td><td>one computer opens 10+ sessions to the same login service within 5 minutes
      (password guessing)</td><td>Credential Access</td></tr>
    <tr><td>SSH login failures / success after failures</td><td>5+ failed remote logins, or a success right after many
      failures (a guessed password)</td><td>Credential Access / Initial Access</td></tr>
    <tr><td>Port scan / host sweep</td><td>one computer probes 15+ doors on a machine or 25+ machines within 5 minutes
      (attackers mapping the network)</td><td>Reconnaissance</td></tr>
    <tr><td>Lateral movement</td><td>one inside computer suddenly logs into 10+ other inside computers using admin tools</td>
      <td>Lateral Movement</td></tr>
    <tr><td>Large outbound transfer</td><td>more than 100 MB leaves for the internet in one connection</td><td>Exfiltration</td></tr>
    <tr><td>Threat-intel match</td><td>any traffic to or from an address on a live blocklist</td><td>Command and Control</td></tr>
    <tr><td>IDS signature</td><td>Suricata recognises a known attack pattern (it ships with ~53,000 of them)</td>
      <td>Initial Access</td></tr>
  </table>
  <h3>The AI anomaly model - "this looks unusual"</h3>
  <p>Rules only catch what someone thought of in advance. The anomaly model (an <i>Isolation Forest</i>) learns, without
  being told what attacks look like, what normal behaviour is for each kind of computer during its first 48 hours. After
  that it scores every computer every hour. Imagine sorting a crowd by asking yes/no questions: a person who can be
  singled out in very few questions ("the only one wearing a red hat") is unusual. Computers that are easy to isolate in
  the same way - contacting far more machines or doors than usual, many failed connections, unusual amounts of data -
  get flagged, with the reasons spelled out (e.g. "distinct destinations = 6, typical 1").</p>
  <p class="ink2">All thresholds (10 attempts, 5 minutes, 100 MB...) are settings in <code>config.yaml</code>, not
  fixed in the code. They follow widely used defaults (fail2ban for password guessing, Zeek's scan policy for scans).</p>
</section>

<section>
  <h2>5. How cases are grouped and ranked</h2>
  <h3>Grouping</h3>
  <p>Two alerts belong to the same case when they involve the same computer or address and happen within two hours of
  each other. Chains are followed: if A links to B and B links to C, all three are one case. Shared infrastructure that
  everyone talks to (like the company's name server) is deliberately ignored for linking, so unrelated alerts are not
  glued together. New alerts keep joining an open case while the attack continues.</p>
  <h3>The risk score (0-100)</h3>
  <table>
    <tr><th style="width:38mm">Ingredient</th><th style="width:16mm">Weight</th><th>Meaning</th></tr>
    <tr><td>Threat confidence</td><td>45%</td><td>How sure the rules and model are. Several different kinds of evidence
      add up; three or more attack stages add a bonus.</td></tr>
    <tr><td>Asset importance</td><td>25%</td><td>How critical the affected computer is (1-5), learned from traffic or set
      in the inventory.</td></tr>
    <tr><td>Vulnerability exposure</td><td>20%</td><td>Whether the computer has known weaknesses, weighted by real-world
      exploitation (CISA list, EPSS). An attack signature matching a weakness the target really has counts as
      "confirmed exploitable".</td></tr>
    <tr><td>Spread</td><td>10%</td><td>How many of your computers are involved.</td></tr>
  </table>
  <p>Score 80+ is <b style="color:{RED}">Critical</b>, 60+ <b style="color:#ec835a">High</b>, 40+
  <b style="color:{GOLD}">Medium</b>, otherwise Low. On the test data the cases that really were attacks scored on average
  {PRI['mean_score_true']} versus {PRI['mean_score_false']} for false alarms, and {pct(PRI['precision_at_k'])} of the top
  {PRI['k']} cases were real attacks - so ranking puts real problems first.</p>
  <h3>Notifications</h3>
  <p>When a new case appears or gets more serious, a pop-up appears on screen. High and Critical cases also trigger a red
  "Possible breach" banner on every page with a button that jumps straight to the investigation.</p>
</section>

<section>
  <h2>6. The AI investigation assistant</h2>
  <p>You can ask questions in everyday English on the <b>Investigate</b> screen. Behind each answer:</p>
  <ol>
    <li><b>Find the evidence.</b> The question is matched to cases, computer addresses, attack types or time words, and the
    relevant records are pulled from the database: alerts, raw log lines, computer details, vulnerability facts, attack
    technique descriptions and response checklists. Each piece has an ID such as <code>EVT-102212</code>.</li>
    <li><b>Write the answer.</b> A language model (free Groq service, model chosen automatically from what Groq currently
    offers) is told to use only that evidence and to end every sentence with the IDs it relied on. Without an AI key, a
    simpler built-in writer produces the answer from the same evidence.</li>
    <li><b>Check the answer.</b> A checker reads every sentence. A sentence with no citation, or citing an ID that was not
    in the evidence, is marked unsupported and shown to the analyst as such.</li>
  </ol>
  <div class="chat"><div class="q">You: What is happening on my network right now and what should I do first?</div>
  <div>SecureOps AI: Both hosts also generate high-volume repeated connection attempts ... that match the brute-force
  pattern <span class="muted">[ALR-856, ALR-1010, PB-BRUTE]</span>. <b>First action:</b> verify and contain the brute-force
  sources according to the PB-BRUTE playbook <span class="muted">[PB-BRUTE]</span> ...</div>
  <div class="muted">openai/gpt-oss-120b · 100% of statements cite evidence</div></div>
  <p><b>Measured reliability:</b> across {LLM.get('incidents', 0)} real incidents the AI wrote {LLM.get('sentences', 0)}
  sentences; {pct(LLM.get('sentence_support_rate', 0))} cited only evidence that exists. An earlier run, with a shorter
  answer limit, scored 97.2% because some answers were cut off mid-sentence - the checker caught every one. Twenty incidents
  is a small sample, so this is a good sign rather than a guarantee.</p>
  <div class="callout"><b>Privacy note:</b> when an AI key is configured, the evidence for a question (addresses, ports,
  times, alert text) is sent to the Groq service to generate the answer. Without a key, nothing leaves the system.</div>
</section>

<section>
  <h2>7. How well it works - measured on real data</h2>
  <p>The system was run on all 18 recorded days exactly as it runs live. Settings were sanity-checked on the first 5
  days; the results below are from the <b>13 later days</b> that were never used for any decision. Accuracy is measured
  per computer per hour: "was this computer doing something malicious during this hour, and did we flag it?"</p>
  <table>
    <tr><th>Detector</th><th>Precision<br><span class="muted">alarms that were real</span></th><th>Recall<br>
      <span class="muted">attacks noticed</span></th><th>False alarm rate</th></tr>
    <tr><td>Rules + AI model (what you use)</td><td>{pct(DET['precision'])}</td><td>{pct(DET['recall'])}</td><td>{pct(DET['false_positive_rate'], 2)}</td></tr>
    <tr><td>Rules only</td><td>{pct(RULES['precision'])}</td><td>{pct(RULES['recall'])}</td><td>{pct(RULES['false_positive_rate'], 2)}</td></tr>
    <tr><td>AI anomaly model only</td><td>{pct(ANOM['precision'])}</td><td>{pct(ANOM['recall'])}</td><td>{pct(ANOM['false_positive_rate'], 2)}</td></tr>
  </table>
  <h3>Share of attack activity noticed, by attack type</h3>
  {bars(TACTIC_ROWS)}
  <p class="muted">"Noticed" = the computer-hour containing the attack was flagged. For the smaller categories part of
  this comes from the same computer also guessing passwords in that hour.</p>
  <h3>Where it falls short - and why</h3>
  <ul>
    <li><b>Quiet attacks are mostly missed.</b> Persistence, privilege escalation and exfiltration in this dataset are
    single, ordinary-looking file-sharing connections. Connection records alone (who, when, how much) cannot tell them
    apart from normal use; that needs the content of the traffic or endpoint data, which this dataset does not include.</li>
    <li><b>Slow reconnaissance</b> (a few probes per hour) stays under standard scan thresholds; only the AI model catches
    part of it.</li>
    <li><b>Two rules cannot be tested on this dataset</b> (threat-intel matches and data theft to the internet) because
    every machine in it is on one internal network. They were tested with live sensor traffic and automated tests.</li>
    <li><b>Analyst time saved was not measured</b> with real analysts; the app records actual time-to-acknowledge and
    time-to-resolve once people use it.</li>
  </ul>
</section>

<section>
  <h2>8. Using the app</h2>
  <div class="two">
    <div><h3>Live</h3><p>The real-time screen: a feed of detections that updates every few seconds, pop-up alerts,
    sensor status, traffic chart and what the models are seeing.</p></div>
    <div><h3>Overview &amp; Investigate</h3><p><b>Overview</b> shows totals, trends, the most targeted computers, the case
    list and measured accuracy. <b>Investigate</b> is the chat assistant next to an attack map and the case controls.</p></div>
  </div>
  <img class="shot" src="{img('live-stream.png')}">
  <img class="shot" src="{img('investigate.png')}">
</section>

<section>
  <h2>9. Safety, privacy and running it</h2>
  <ul>
    <li><b>Humans stay in charge.</b> Proposed actions (block, isolate, allow-list) are recorded for approval; nothing is
    executed automatically.</li>
    <li><b>Everything is audited.</b> Every change of owner, status or note is logged with who did it and when.</li>
    <li><b>Secrets stay secret.</b> API keys and database passwords live in a private secrets file or the host's secret
    store and are never written to the code or the database.</li>
    <li><b>Monitor only networks you own</b> or are authorised to monitor.</li>
    <li><b>Writes are protected.</b> Sending data to the system or changing cases through its programming interface needs a
    secret token.</li>
  </ul>
  <h3>Running it for free</h3>
  <table>
    <tr><th>Piece</th><th>Free service</th></tr>
    <tr><td>The web app</td><td>Streamlit Community Cloud</td></tr>
    <tr><td>AI explanations</td><td>Groq (free key)</td></tr>
    <tr><td>Database that survives restarts</td><td>Neon PostgreSQL</td></tr>
    <tr><td>Interface for sensors</td><td>Render</td></tr>
    <tr><td>Sensor</td><td>Raspberry Pi / any Linux machine with Docker</td></tr>
  </table>
  <p>Step-by-step instructions are in <code>DEPLOY.md</code>; technical details in <code>README.md</code>; full accuracy
  numbers in <code>reports/EVALUATION.md</code>.</p>
</section>

<section>
  <h2>10. Glossary</h2>
  <table>{''.join(f'<tr><td style="width:38mm"><b>{html.escape(k)}</b></td><td>{html.escape(v)}</td></tr>' for k, v in GLOSSARY)}</table>
  <h3>Credits</h3>
  <p class="ink2">UWF-ZeekData24 dataset: University of West Florida (CC BY 4.0). Threat intelligence: abuse.ch, Spamhaus.
  Vulnerability data: NIST NVD, CISA, FIRST. Attack knowledge: MITRE ATT&amp;CK. Network sensors: Zeek, Suricata
  (ET Open rules).</p>
</section>
</body></html>"""


def main():
    from playwright.sync_api import sync_playwright

    tmp = ROOT / "docs" / "_documentation.html"
    tmp.write_text(page, encoding="utf-8")
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(channel="msedge")
        except Exception:
            browser = p.chromium.launch()
        pg = browser.new_page()
        pg.goto(tmp.as_uri())
        pg.pdf(path=str(OUT), format="A4", print_background=True,
               margin={"top": "16mm", "bottom": "16mm", "left": "15mm", "right": "15mm"},
               display_header_footer=True, header_template="<span></span>",
               footer_template="<div style='font-size:8px;color:#8a8984;width:100%;text-align:center'>SecureOps AI - "
                               "<span class='pageNumber'></span> / <span class='totalPages'></span></div>")
        browser.close()
    tmp.unlink()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
