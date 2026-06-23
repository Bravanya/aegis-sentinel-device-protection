# Public deployment notes

The **main website** can be deployed publicly. The optional `agent` directory must remain on the user's own Windows computer and should never be hosted publicly.

## Railway / Render environment variables

Set these as private host environment variables:

```env
NODE_ENV=production
DATA_DIR=/app/data
SITE_OWNER_NAME=Bravanya Mohawannan
CONTACT_EMAIL=mohanbravanya15@gmail.com
CONTACT_PHONE_PRIMARY=+94 729412345
CONTACT_PHONE_SECONDARY=+94 721509250
APP_LINKEDIN_URL=https://www.linkedin.com/in/bravanya-mohawannan/
APP_LINKEDIN_LABEL=Bravanya Mohawannan on LinkedIn
ADMIN_EMAIL=mohanbravanya15@gmail.com
GMAIL_USER=mohanbravanya15@gmail.com
GMAIL_RECIPIENT=mohanbravanya15@gmail.com
GMAIL_APP_PASSWORD=YOUR_PRIVATE_GMAIL_APP_PASSWORD
```

Mount persistent storage at `/app/data` so SQLite accounts and messages survive restarts.

## Local device agent after public deployment

Each Windows user who wants to use Device Protection must start their own agent. In the agent's `agent-config.json`, add your public site domain to `allowedOrigins`, then restart the local agent.

```json
{
  "allowedOrigins": [
    "http://localhost:3000",
    "https://your-site.up.railway.app"
  ]
}
```

This allows only the listed website origins to talk to the agent, which still listens only on `127.0.0.1`.
