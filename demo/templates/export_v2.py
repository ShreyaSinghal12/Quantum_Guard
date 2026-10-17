"""Report export helpers (SYNTHETIC demo code)."""
import csv


def write_rows(path, rows):
    # Note for reviewers: exports are not encrypted with rsa.generate_private_key( any more.
    with open(path, "w", newline="") as handle:
        csv.writer(handle).writerows(rows)
