import sys

def main():
    if len(sys.argv) != 3:
        sys.exit(f"Usage: {sys.argv[0]} input.hc22000 output.txt")

    src, dst = sys.argv[1], sys.argv[2]
    seen = set()

    with open(src, "r", encoding="utf-8", errors="ignore") as fin, \
         open(dst, "wb") as fout:
        for line in fin:
            parts = line.strip().split("*")
            if len(parts) < 6 or parts[0] != "WPA":
                continue
            essid_hex = parts[5]
            if not essid_hex or essid_hex in seen:
                continue
            seen.add(essid_hex)
            try:
                # Write raw bytes so non-UTF-8 ESSIDs are preserved exactly
                fout.write(bytes.fromhex(essid_hex) + b"\n")
            except ValueError:
                continue

    print(f"Wrote {len(seen)} unique ESSID(s) to {dst}")

if __name__ == "__main__":
    main()
