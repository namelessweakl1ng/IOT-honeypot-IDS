# Controlled attack runner

Install `requirements.txt`, copy `.env.example` to `.env`, export its values, then run:

```bash
python -m attacks.runner.run ssh-bruteforce --target "$HONEYPOT_IP"
```

The runner accepts exactly one target, requires it to be a usable private address inside `LAB_SUBNET`, never scans a range, and only connects to project service ports. JSON ground truth is written to the ignored `attacks/runs/` directory.
