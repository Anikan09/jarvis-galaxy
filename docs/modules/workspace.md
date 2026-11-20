# Workspace module

Your inbox, your calendar and a spoken morning briefing. **Read-only**: Jarvis can't send, delete or change anything.

**Switch it on:** `"modules": { "workspace": true }` in `config.json`.

| Say | What happens |
|---|---|
| "Good morning" / "Brief me" | A spoken briefing: today's events, and the emails that need a reply or action, most important first. |
| "What needs me?" / "Check my inbox" | The last two days of unread or important mail, sorted into *reply*, *action* and *FYI*. |
| "What's on my calendar today?" | Today's events from Google and Apple, merged. |

**Only senders, subjects, short previews and dates are read: never message bodies or attachments.** E-mails are written by other people, so the brain treats them strictly as data: it never follows instructions in them and never repeats links or codes from them.

## Connect Google (Gmail + Calendar)

You use **your own** Google Cloud OAuth client, so no one else's app ever touches your account.

1. `pip install google-api-python-client google-auth-oauthlib`
2. In [Google Cloud Console](https://console.cloud.google.com/): create a project, enable the **Gmail API** and the **Google Calendar API**, configure the OAuth consent screen (External, add yourself as a test user), then create an **OAuth client ID** of type **Desktop app** and download its JSON file.
3. `python -m modules.workspace.google path\to\client_secret.json` and sign in. Jarvis asks only for **gmail.readonly** and **calendar.readonly**.
4. The token is stored encrypted in `data/`. You can delete the downloaded client file afterwards.

## Connect Apple Calendar (iCloud)

1. `pip install caldav`
2. Make an **app-specific password** at [account.apple.com](https://account.apple.com) → Sign-In and Security → App-Specific Passwords. Never use your Apple ID password.
3. `python -m core.vault set apple_app_password` (typed hidden, stored encrypted)
4. In `config.json`: `"workspace": { "apple_id": "your-apple-id@example.com", "apple_calendar": "" }` (empty = all calendars).

## What leaves the PC

Requests go straight from your PC to Google and Apple. For the briefing, today's event titles and the senders, subjects and previews of the emails that need you go to Claude to be turned into a few spoken sentences. In private mode, the local model writes the briefing instead.
