# PassForge 🔐

A tiny, dependency-free **password strength analyzer and secure generator** that runs entirely in your browser.
Nothing you type is sent anywhere, stored, or logged.

## Features
- **Analyzer**: live entropy estimate, strength meter, estimated offline crack time, checklist, and tips
- **Pattern penalties**: common passwords, keyboard walks (`qwerty`), sequences (`abcd`, `4321`), repeats, years, and `Word123!` shapes
- **Generator**: random passwords (8–64 chars) with selectable character sets and a look-alike filter
- **Passphrases**: memorable multi-word phrases with optional capitalization, number and separator
- **Secure randomness**: `crypto.getRandomValues` with rejection sampling (no modulo bias) and a Fisher–Yates shuffle
- Responsive, keyboard accessible, light/dark aware

## Run it
No build step. Open `index.html` in a browser, or serve the folder:

```bash
python3 -m http.server 8000
```

### Host free on GitHub Pages
Repo **Settings → Pages → Deploy from branch → `main` / root**.

## How the score works
`entropy ≈ length × log2(character pool size)`, then reduced for predictable patterns.
Crack time assumes an offline attacker making **10 billion guesses per second** and finding the password on average halfway through the search space.

> **Limitations:** this is an educational estimate, not a guarantee. The passphrase mode uses a small built-in word list (217 words, roughly 7.8 bits per word), so use 6+ words for important accounts. Always use a unique password per site and a password manager with 2FA.

## Tech
HTML · CSS · vanilla JavaScript

## Ideas to extend
- Add the [HIBP k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords) breach check
- Larger word list (e.g. EFF long list)
- Export / copy history with auto-clear

## License
MIT © Abhishek Maurya
