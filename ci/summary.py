#!/usr/bin/env python3
# Aggregate the 4 cells' LTP serial logs into a grade.txt-style score report:
# a total preview, per-cell totals, then every case with its per-cell TPASS.
#
# Score per case = TPASS sub-assertions (what the contest grader sums), counted
# between each "RUN LTP CASE <name>" marker and the next. A case that a cell
# never reached (time-cap) shows "-"; a case that ran but passed nothing shows 0.
#
# Writes the full report to $GITHUB_STEP_SUMMARY (renders on the run's Summary
# tab) and to score-report.md (uploaded as an artifact); prints a short preview
# to stdout for the job log.
#
# Usage: summary.py <artifact-dir>
import sys, os, glob, re

CELLS = ["rv-musl", "rv-glibc", "la-musl", "la-glibc"]
logdir = sys.argv[1] if len(sys.argv) > 1 else "dl"

def find_log(cell):
    hits = glob.glob(os.path.join(logdir, "**", cell + ".log"), recursive=True)
    return hits[0] if hits else None

def parse(path):
    scores, cur, n = {}, None, 0
    if not path or not os.path.exists(path):
        return scores
    with open(path, errors="replace") as f:
        for line in f:
            m = re.search(r"RUN LTP CASE (\S+)", line)
            if m:
                if cur is not None:
                    scores[cur] = scores.get(cur, 0) + n
                cur, n = m.group(1), 0
                continue
            if "TPASS" in line:
                n += 1
        if cur is not None:
            scores[cur] = scores.get(cur, 0) + n
    return scores

data = {c: parse(find_log(c)) for c in CELLS}
cases = sorted(set().union(*[set(d) for d in data.values()])) if any(data.values()) else []
ctot = {c: sum(data[c].values()) for c in CELLS}
grand = sum(ctot.values())

L = []
L.append("# LTP score preview")
L.append("")
L.append(f"## Total: {grand} TPASS")
L.append("")
L.append("| | " + " | ".join(CELLS) + " | total |")
L.append("|---|" + "---|" * (len(CELLS) + 1))
L.append("| **score** | " + " | ".join(str(ctot[c]) for c in CELLS) + f" | **{grand}** |")
L.append("| cases run | " + " | ".join(str(len(data[c])) for c in CELLS) + f" | {len(cases)} |")
L.append("")
L.append(f"## Per-case TPASS ({len(cases)} cases)")
L.append("")
L.append("| case | " + " | ".join(CELLS) + " | total |")
L.append("|---|" + "---|" * (len(CELLS) + 1))
for case in cases:
    cols = " | ".join(str(data[c][case]) if case in data[c] else "-" for c in CELLS)
    rt = sum(data[c].get(case, 0) for c in CELLS)
    L.append(f"| {case} | {cols} | {rt} |")
report = "\n".join(L) + "\n"

ss = os.environ.get("GITHUB_STEP_SUMMARY")
if ss:
    with open(ss, "a") as f:
        f.write(report)
with open("score-report.md", "w") as f:
    f.write(report)

print(f"TOTAL: {grand} TPASS across {len(cases)} cases")
for c in CELLS:
    print(f"  {c:9}: {ctot[c]:6}  ({len(data[c])} cases run)")
