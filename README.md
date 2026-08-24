# SYCS Voldemort

A Discord bot that takes care of running a server, plus a web panel to manage it.

Metal spot prices, AI chat, audit logging, join and leave records, earthquake alerts,
music playback, text-to-speech — all of it in one bot.

Settings can be changed **either from Discord slash commands or from a browser-based
admin panel**. Which features are reachable from which is tabulated in
[docs/FEATURES.ja.md](docs/FEATURES.ja.md).

日本語版: [README.ja.md](README.ja.md)

## What is in it

- Precious metal prices (gold, silver, platinum)
- AI conversation, restricted to channels you nominate
- Audit logging and long-term retention of user state
- Join/leave greetings and voice-channel notifications
- Sticky messages and reaction roles
- Google News delivery and earthquake alerts (P2PQuake)
- Music download and playback (DJAudio-DL)
- Text-to-speech, with per-user voice settings and a pronunciation dictionary
- Voice-channel recording, one track per speaker, usable alongside text-to-speech
- Detection of suspicious activity
- An admin panel (FastAPI) and a web tracker for metal prices

## Processes

| Process | Entry point | Role |
|---|---|---|
| Discord Bot | `main.py` | Discord events and slash commands |
| Admin UI | `admin_main.py` | Management panel (FastAPI) |
| Web App | `web_main.py` | Metal price tracker (FastAPI) |

Settings are persisted to `settings.json` by `services/settings_store.py`.

## Running it locally

```bash
pip install -r requirements.txt
```

```bash
python main.py         # Discord bot
python admin_main.py   # admin panel
python web_main.py     # web tracker
```

`ffmpeg`, needed by DJAudio, is fetched automatically if not found
(via `imageio-ffmpeg`); set `DJAUDIO_FFMPEG_PATH` to point at your own.

Docker Compose and the full environment-variable reference are in
[docs/SETUP.ja.md](docs/SETUP.ja.md).

## Checks during development

```bash
python -m unittest discover -s tests -t .   # Admin API tests (no DB needed)
python tools/check_admin_schema.py          # Settings schema vs. services wiring
python tools/check_admin_ui.py              # Drive the admin desktop in a real browser
python tools/generate_admin_docs.py         # Regenerate the settings table in docs/ADMIN.ja.md
```

All of them run against a temporary `SETTINGS_DIR`, so your real `settings.json` is left alone.

---

## Documentation

| | |
|---|---|
| [docs/FEATURES.ja.md](docs/FEATURES.ja.md) | Every feature in detail, and which of them can be driven from where |
| [docs/COMMANDS.ja.md](docs/COMMANDS.ja.md) | Slash command reference |
| [docs/SETUP.ja.md](docs/SETUP.ja.md) | Docker Compose, environment variables, multi-instance setups |
| [docs/ADMIN.ja.md](docs/ADMIN.ja.md) | Using the admin panel, where data is stored |
| [docs/TROUBLESHOOTING.ja.md](docs/TROUBLESHOOTING.ja.md) | Common problems, directory overview |

Detailed documentation is Japanese-only for now.
