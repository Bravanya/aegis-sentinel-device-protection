# Gmail message delivery setup — Tamil guide

இந்த project contact form-ல் ஒரு visitor message அனுப்பும்போது:

1. அந்த message project database-ல் save ஆகும்.
2. Gmail setup சரியாக இருந்தால் அதே message `mohanbravanya15@gmail.com` inbox-க்கும் வரும்.

## முக்கியம்

உங்கள் normal Gmail password-ஐ `.env` file-ல் எழுதக்கூடாது.
Gmail **App Password** மட்டும் பயன்படுத்த வேண்டும்.

## செய்ய வேண்டியது

1. `aegis-sentinel-device-protection` project folder-ல் `.env.example` file-ஐ copy செய்து `.env` என்ற பெயரில் வைத்துக்கொள்ளுங்கள்:

```powershell
Copy-Item .env.example .env
```

2. Gmail account `mohanbravanya15@gmail.com`-ல் **2-Step Verification** enable செய்யுங்கள்.

3. Google Account Security page-ல் **App passwords** உருவாக்குங்கள். Google உருவாக்கும் 16-character password-ஐ copy செய்யுங்கள்.

4. VS Code-ல் `.env` file open பண்ணி இந்த line மட்டும் மாற்றுங்கள்:

```env
GMAIL_APP_PASSWORD=PASTE_YOUR_16_CHARACTER_GMAIL_APP_PASSWORD_HERE
```

உதாரண வடிவம் மட்டும்:

```env
GMAIL_APP_PASSWORD=abcd efgh ijkl mnop
```

Spaces இருந்தாலும் project handle பண்ணும். ஆனால் உங்கள் real App Password-ஐ GitHub, screenshot, LinkedIn, chat, அல்லது public file-ல் share பண்ணாதீர்கள்.

5. PowerShell-ல் server-ஐ stop செய்யுங்கள்:

```text
Ctrl + C
```

6. மறுபடியும் start செய்யுங்கள்:

```powershell
node server.js
```

7. Website-ல் sign in செய்து **Contact & LinkedIn** page-ல் ஒரு test message send செய்யுங்கள்.

8. `mohanbravanya15@gmail.com` inbox மற்றும் Spam folder இரண்டையும் check செய்யுங்கள்.

## Test result

Contact form கீழே:

```text
Message saved and delivered to the owner Gmail inbox.
```

என்று வந்தால் Gmail delivery வேலை செய்கிறது.

`Message saved in the project database...` என்று வந்தால் Gmail App Password setup செய்யப்படவில்லை அல்லது Gmail SMTP login reject செய்துள்ளது.

## If App Password is not visible

2-Step Verification enable செய்திருந்தாலும் App Password option தெரியாமல் இருக்கலாம். Google Workspace/school account, Advanced Protection, அல்லது security-key-only 2-Step Verification போன்ற settings காரணமாக அது unavailable ஆகலாம். அப்படியானால் Gmail API + OAuth setup பயன்படுத்த வேண்டும்.
