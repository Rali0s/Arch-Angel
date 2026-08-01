# Arch Angel Remote Lab

Arch Angel brings the project surfaces together behind an original synthesized
music introduction. Its browser portal contains the Remote Lab, a fixed local
management scanner, the Guardian ASL method lab, and both interactive PDF
manuals.

The Remote Lab demonstrates the safe part of a reverse connection: a
simulated endpoint initiates an outbound check-in to a controller, polls for a
signed job, executes a fixed diagnostic action, and returns a structured result.

It is deliberately **not** a reverse shell. The controller and agent reject
arbitrary commands, script text, executable paths, unknown actions, and unknown
parameters.

## Lab boundary

- The controller binds to `127.0.0.1` by default.
- A non-loopback bind requires both `--allow-network` and TLS certificate/key
  arguments.
- Agent messages and jobs use HMAC-SHA256 signatures.
- Jobs are bound to one device, contain a nonce, and expire within five minutes.
- The only actions are `ping`, `system_info`, `disk_usage`, and `echo`.
- `disk_usage` is limited to the configured lab root.
- Audit events are written to `.guardian-remote-lab/audit.jsonl` by default.

This HMAC design is appropriate for a single-machine connection lab. A real
deployment should use per-device TPM-backed keys, mutual TLS, signed policy, JEA
role capabilities, operator MFA/RBAC, and an append-only audit service.

## Quick start

Open three terminals in this directory. Set lab-only secrets in each terminal:

```powershell
$env:GUARDIAN_LAB_SHARED_SECRET = 'replace-with-a-random-32-character-lab-secret'
$env:GUARDIAN_LAB_OPERATOR_TOKEN = 'replace-with-a-random-operator-token'
```

On macOS or Linux, use the equivalent `export` commands.

Terminal 1 - start the loopback controller:

```powershell
python .\controller.py
```

Open <http://127.0.0.1:8765/health> in a browser for the live dashboard. Browser
requests receive the dashboard, while scripts such as `curl` continue to receive
the small JSON health response. Choose **Play heavy metal + enter** for the
original Web Audio riff, then move between Remote Lab, Scanner, ASL Lab, and PDF
Manuals. The manual shelf opens the uploaded *Rootkit Arsenal* by default and
streams it with byte-range support alongside the two Guardian manuals.
The portal refreshes once per second. Paste the operator token into its
session-only field to queue one of the fixed actions or run the loopback scanner.

### ASL Patch & Upload

In **ASL Lab**, switch from **Hook examples** to **Patch & Upload**. The segment
can read a local `.dsl`, `.asl`, or text file into the editor, show an advisory
patch preview, calculate a browser SHA-256, and upload the source to authenticated
local staging. The controller validates the source again, then stores it with a
manifest and server-computed SHA-256 under
`.guardian-remote-lab/asl-staging/<stage-id>/`.

Staging is intentionally a review boundary: it does not invoke iASL, create an
AML table, patch firmware, load a table, or deploy anything. Hardware-region and
table-loading constructs are rejected. Every receipt remains marked
`staged-only`, `compile_status: not-run`, and `deployable: false` so later build
or OEM-signing work cannot be confused with this lab upload step.

The current validation does **not** compare a patch with the host's DSDT/SSDT
namespace or prove that references resolve on a particular machine. A separate,
explicit compatibility step would need an authorized ACPI table capture,
decompilation, namespace/reference analysis, and iASL diagnostics. Keep that
machine-specific evidence separate from the source-staging receipt.

PDF manuals are optional local content and are not bundled with the repository.
Place permitted PDFs in `manuals/`, or configure their locations before
starting the controller:

```powershell
$env:GUARDIAN_LAB_MANUAL_DIR = 'C:\GuardianLab\manuals'
$env:GUARDIAN_LAB_ARSENAL_PDF = 'C:\GuardianLab\private\The-Rootkit-Arsenal.pdf'
$env:GUARDIAN_LAB_EXPLOITATION_PDF = 'C:\GuardianLab\private\Hacking-The-Art-of-Exploitation-2nd-Edition.pdf'
```

The last two variables override their individual private-library entries.
Missing manuals return a normal `404` and do not affect the Remote, Scanner, or
ASL workspaces.

Terminal 2 - start the simulated outbound endpoint:

```powershell
python .\agent.py --device-id lab-device-01
```

Terminal 3 - inspect the device, queue a diagnostic job, then inspect results:

```powershell
python .\operator.py devices
python .\operator.py submit --device-id lab-device-01 --action ping
python .\operator.py results
```

Other fixed actions:

```powershell
python .\operator.py submit --device-id lab-device-01 --action system_info
python .\operator.py submit --device-id lab-device-01 --action disk_usage
python .\operator.py submit --device-id lab-device-01 --action echo --message 'hello from the lab'
```

The agent polls every three seconds by default. Use `--once` for one check-in and
poll cycle.

## Isolated network lab

Loopback is the default. To accept a simulated endpoint from another machine,
use an IP address assigned to an isolated lab interface and a certificate that
the endpoint already trusts:

```powershell
python .\controller.py --bind 192.0.2.10 --port 8765 --allow-network `
  --certfile .\lab-controller.crt --keyfile .\lab-controller.key
```

Then point the endpoint at the matching HTTPS name or address:

```powershell
python .\agent.py --controller https://lab-controller.example:8765 `
  --device-id lab-device-01
```

Keep the listener on an isolated lab VLAN, restrict its firewall scope, and do
not reuse the HMAC secret or operator token between devices or environments.
The network mode still exposes only the four fixed actions.

## Tests

Run from this directory:

```powershell
python -m unittest discover .\tests -v
```

The tests verify successful outbound check-in and result delivery, ASL staging
manifests and SHA-256 receipts, and prove that hardware-region ASL, `shell`,
`command`, unsigned messages, altered jobs, and wrong-device jobs are rejected.
