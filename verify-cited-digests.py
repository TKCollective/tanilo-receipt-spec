#!/usr/bin/env python3
"""verify-cited-digests.py — every sha256 a document CLAIMS must resolve to real bytes.

Built 2026-09-08 after a fabricated digest reached a delivered README: the first
16 characters were real (observed in command output) and the remaining 48 were
generated. A 16-character prefix check would have passed it.

WHAT THIS CHECKS
  Prose and code files that make claims of the form "file X has sha256 Y".
  Every 64-hex-character string is resolved against:
    1. the sha256 of every file in the directory
    2. the sha256 of every blob in git history (for "the file at <old ref>" citations)
    3. an explicit allowlist of external artifacts, each with a stated reason

WHAT THIS DOES NOT CHECK
  Data files whose CONTENT is cryptographic values -- fixture sets, vector files,
  key material. A fixture's evidence roots and snippet digests are supposed to be
  there and resolve to nothing. Auditing them produces noise, and an audit that
  reports noise is one an operator learns to skip. Pass those files and the tool
  refuses rather than guessing.

USAGE
  python3 verify-cited-digests.py <prose-or-code-file>...
  exit 0 = every claimed digest resolves;  1 = at least one does not;  2 = misuse
"""
import hashlib, pathlib, re, subprocess, sys

# Extensions whose content is data rather than claims. Refused, not audited.
DATA_SUFFIXES = {".json", ".jsonl", ".pem", ".jwk", ".der", ".sig", ".bin"}

ALLOW = {
  "fe8567bd734602838c0f70bdc0741e506ff5476207bc641ff77ba3a5ea68e5cc":
      "rev5 fixture at ac33ad1^ — cited by rev6 E-2 as the stale value it corrects",
  "ba3bcaacc0e8dde8381e7daee2e3da8c9cd617b76f01d4698180bee16e48c5a3":
      "STRAWMAN v0.5 — external artifact held by Michael, not in this repo",
  "94792235cb95c80c290613177142fd0594765ddc10c1a432b7b6e8f0646d549b":
      "STRAWMAN v0.4 seated — external artifact",
  "042bca91ba0a49e2608b3fe0f735805922bd283d9e34953bdb74e6ab95eacc27":
      "STRAWMAN v0.3 as sent — external artifact",
  "3a5cf8fa2674d560aff05394a10f4ffc8912d265456237978190ce4de88b932f":
      "aer1_verify.py in gitlab.com/rambozambodotdev/zambo at b2b1a4ee, cited by examples/interop/aer1/chain-run-2026-10-08.md — external artifact",
  "d78fc31f" + "0"*56:
      "placeholder guard — never matches; present so the allowlist shape is obvious",
}

def build_index(root: pathlib.Path):
    idx = {}
    for p in root.iterdir():
        if p.is_file():
            idx.setdefault(hashlib.sha256(p.read_bytes()).hexdigest(), p.name)
    try:
        listing = subprocess.run(["git", "rev-list", "--objects", "--all"],
                                 capture_output=True, text=True, timeout=120).stdout
        for line in listing.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            sha, name = parts
            try:
                blob = subprocess.run(["git", "cat-file", "-p", sha],
                                      capture_output=True, timeout=15).stdout
            except Exception:
                continue
            idx.setdefault(hashlib.sha256(blob).hexdigest(), f"{name} (git history)")
    except Exception as e:
        print(f"  note: git history not indexed ({e}); historical citations may not resolve",
              file=sys.stderr)
    return idx

def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    idx = build_index(pathlib.Path("."))
    total_bad = 0
    for target in argv[1:]:
        p = pathlib.Path(target)
        if not p.exists():
            print(f"MISSING  {target}")
            total_bad += 1
            continue
        if p.suffix.lower() in DATA_SUFFIXES:
            print(f"REFUSED  {p.name}: data file, its digests are content not claims "
                  f"(suffix {p.suffix})")
            continue
        text = p.read_text(errors="replace")
        claimed = sorted(set(re.findall(r"\b[a-f0-9]{64}\b", text)))
        bad = [d for d in claimed if d not in idx and d not in ALLOW]
        if bad:
            print(f"FAIL     {p.name}: {len(claimed)} claimed, {len(bad)} unresolved")
            for d in bad:
                print(f"           {d}")
        else:
            print(f"OK       {p.name}: {len(claimed)} claimed, all resolve")
        total_bad += len(bad)
    print()
    print(f"unresolved digest claims: {total_bad}")
    return 1 if total_bad else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
