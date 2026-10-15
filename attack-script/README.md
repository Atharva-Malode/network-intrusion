# Attack Script — multi-class attack simulator

Generates traffic against your own demo site **through the capture proxy**
(`http://localhost:8080`), so the NIDS model can classify each attack class.
Everything runs locally for demonstration.

| Script          | Attack                                   | Target model class |
|-----------------|------------------------------------------|--------------------|
| `normal.py`     | Legitimate browsing                      | `Normal`           |
| `recon.py`      | Endpoint scanning / enumeration          | `Probe`            |
| `flood.py`      | DoS / DDoS flood                         | `DoS`              |
| `credential.py` | Auth brute force / credential stuffing   | `R2L`              |
| `exploit.py`    | RCE / path-traversal / LFI               | `U2R`              |

## Run a single attack

```bash
cd attack-script
uv sync            # or: pip install -e .
uv run python main.py recon      # normal | recon | flood | credential | exploit
```

## Scripted live demo

```bash
uv run python main.py demo
```

Cycles through: baseline normal → Probe → DoS → R2L → U2R (with normal traffic
running underneath the whole time). Watch the dashboard's **NIDS Attack
Classification** panel change class as each phase runs.

Source IPs are spoofed via the `X-Forwarded-For` header (`config.ATTACKER_IPS`).
Tune intensity in [`config.py`](config.py).
