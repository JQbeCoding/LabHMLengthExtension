# LabHM quick commands

Folder: `/Users/jaquismay/Downloads/LabHM`

## Part 3 (you run these)

```bash
cd /Users/jaquismay/Downloads/LabHM
python3 sha256_lenext.py --first quis
python3 sha256_lenext.py --first quis --hmac
```

Create a public GitHub repo named `LabHM_LengthExtension`, upload `sha256_lenext.py`, paste the URL into the report.

## Part 4 (re-run for fresh screenshot)

```bash
python3 password_kdf_bench.py --passphrase "quisfranklin-801480194!94"
```

## CyberChef reminders

- Part 1 HMAC key for T2: `quis0` (FIRST + hex digit `0`)
- Part 2: From Hex → MD5 / SHA2-256 on blocks in `md5_collision_blocks.txt`
- Part 4 Bcrypt: rounds = 10, input = `quisfranklin-801480194!94`, bake twice

## Report

Edit and paste [`Quis_Franklin_LabHM.md`](Quis_Franklin_LabHM.md) into Word as `Quis_Franklin_LabHM.docx`. Insert full-desktop screenshots with yellow/red markup per the course guidelines.
# LabHMLengthExtension
# LabHMLengthExtension
