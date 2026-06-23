# Aegis Sentinel — Device Protection Edition

A no-npm Node.js Cybersecurity SOC website with real account registration, server-side sessions, public contact details, Gmail contact-message delivery, real-time simulated SOC telemetry, and an optional **Windows-only Local Device Agent**.

## What works for real

- Users can sign up, sign in, and sign out through the Node.js server.
- Contact-form messages are saved in SQLite.
- When Gmail is configured, contact-form messages are also emailed to `mohanbravanya15@gmail.com`.
- The dashboard receives server-sent real-time demo telemetry.
- The optional Device Agent can operate on the **same Windows PC where the agent is voluntarily installed**:
  - Read Microsoft Defender protection status.
  - Launch Microsoft Defender Quick Scan or Full Scan.
  - List Aegis Sentinel firewall rules.
  - Create/remove Aegis Sentinel inbound and outbound firewall rules for one confirmed IP address.

## What is intentionally not possible

- A browser website cannot silently scan or control any laptop.
- It cannot access a friend's, family's, LinkedIn member's, or Google user's device/account without that person's explicit authorization.
- It does not hack, trace, or “automatically block all hackers.” You must identify a confirmed malicious IP from your own authorized security evidence before using the block control.
- SOC events, cases, threat intelligence, charts, and playbook results remain simulated portfolio/training data.

## Owner contact details in this build

- Email: `mohanbravanya15@gmail.com`
- LinkedIn: `https://www.linkedin.com/in/bravanya-mohawannan/`
- Phone: `+94 729412345`
- Alternate phone: `+94 721509250`

## Requirements

- Windows 10/11 for Device Agent features.
- Node.js `22.5+`. You have Node.js 24, so no npm install is required.
- Microsoft Defender available/enabled for scans.
- Administrator permission only for Windows Firewall block/remove actions.

## Start the main website

Extract the ZIP, then open PowerShell inside the **inner project folder** (the folder containing `server.js`):

```powershell
Copy-Item .env.example .env
node server.js
```

Open:

```text
http://localhost:3000
```

Demo account:

```text
Email: demo@aegis.local
Password: Demo@123
```

## Configure Gmail delivery

Follow [GMAIL_SETUP_TAMIL.md](GMAIL_SETUP_TAMIL.md).

Never enter your normal Gmail password. Use a Gmail App Password in `.env` only.

## Start local laptop scanning / firewall controls

1. Open a second PowerShell window in the `agent` folder.
2. Start the local agent:

```powershell
node .\aegis-device-agent.js
```

3. It creates `agent-config.json` on the first run.
4. Copy the `token` value from that file.
5. Sign in to the website → **Device Protection** → paste the token → **Connect local agent**.
6. Use **Quick scan** or **Full scan** to launch Windows Defender.
7. For Firewall block/remove controls, right-click `agent\start-agent-admin.ps1` → **Run with PowerShell** → approve UAC. Then reconnect the agent.

## Public website access

After deployment, anyone can access the public site URL in a browser and create their own website account.

For any visitor to scan *their own* Windows PC, they must download/run the Device Agent locally and explicitly connect it with their own local token. Your public web server never gains permission to inspect their device.

## Deploy

The main site is deployable to Railway or Render. Use persistent storage for `/app/data` because SQLite stores accounts and contact messages. Configure `NODE_ENV=production`, `DATA_DIR=/app/data`, and your Gmail values as private deployment environment variables. Do **not** deploy the `agent` folder as a public server; it is a localhost-only Windows companion.

## Project structure

```text
server.js                       Main site + auth + database + Gmail SMTP delivery
public/                         Browser pages, dashboard, contact page, device controls
agent/aegis-device-agent.js     Windows Defender + firewall local agent
agent/start-agent-admin.ps1     Starts local agent elevated for firewall permissions
agent/agent-config.json         Generated locally; contains a private token (do not share)
.env                            Private contact/Gmail config (do not commit)
GMAIL_SETUP_TAMIL.md            Gmail setup guide in Tamil
```
