# NGShield Browser Extension

A powerful ad blocker and threat protection extension that integrates with your NGShield dashboard to block ads and malicious content on your monitored domains.

## Features

- **Ad Blocking**: Automatically blocks ads on domains you're monitoring with NGShield
- **Real-time Blocking**: Uses blocklist from your NGShield account to block ads instantly
- **Threat Protection**: Prevents malicious ad networks from loading
- **Lightweight**: Minimal performance impact; runs as a service worker
- **Easy Setup**: One-time configuration with your NGShield API key

## Installation

### Development Setup (Chrome/Chromium)

1. **Clone or extract the extension folder**
   ```
   extension/
   ├── manifest.json
   ├── background.js
   ├── content.js
   ├── popup.html
   ├── popup.js
   └── styles.css
   ```

2. **Open Chrome Extensions Page**
   - Go to `chrome://extensions/`
   - Enable "Developer mode" (top-right corner)

3. **Load the extension**
   - Click "Load unpacked"
   - Select the `extension/` folder
   - The extension should appear in your extensions list

4. **Configure the extension**
   - Click the NGShield extension icon in your toolbar
   - Enter your NGShield server URL (e.g., `http://localhost:8000`)
   - Paste your API key (obtain from NGShield dashboard Settings)
   - Click "Save Configuration"

5. **Done!**
   The extension will auto-sync your blocklist every hour

## Getting Your API Key

1. Log in to your NGShield dashboard
2. Go to **Settings** → **API Keys**
3. Create a new "Extension API Key"
4. Copy and paste it into the extension popup

## How It Works

### Background Script (`background.js`)
- Periodically fetches your blocklist from the NGShield server
- Stores blocklist locally in Chrome storage for fast access
- Handles blocking of flagged URLs
- Receives reports from content scripts

### Content Script (`content.js`)
- Runs on all web pages
- Hides ad elements using CSS selectors
- Removes ad iframes with known ad domains
- Monitors for dynamically loaded ads (DOM observer)
- Reports ad clicks to the server

### Popup UI (`popup.html`, `popup.js`)
- Shows extension status and configuration
- Displays blocked URL count
- Lists monitored domains
- Allows manual refresh of blocklist
- Provides quick access to settings

## API Endpoints

The extension communicates with these NGShield backend endpoints:

### `GET /api/extension/blocklist/`
Returns the current blocklist for the user.

**Headers:**
```
Authorization: Bearer {API_KEY}
```

**Response:**
```json
{
  "blocked_urls": ["ads.example.com", "adserver.net", ...],
  "monitored_domains": ["example.ng", "mysite.ng", ...],
  "timestamp": "2025-01-15T10:30:00Z"
}
```

### `POST /api/extension/report-ad/`
Report a suspicious ad URL.

**Headers:**
```
Authorization: Bearer {API_KEY}
Content-Type: application/json
```

**Body:**
```json
{
  "ad_url": "https://ads.malicious.com/banner.js",
  "source_page": "https://example.ng/page",
  "reported_at": "2025-01-15T10:30:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "blocked_url_id": 42,
  "alert_id": 123
}
```

### `POST /api/extension/check-url/`
Check if a single URL is blocked (lightweight).

**Body:**
```json
{
  "url": "https://ads.example.com/ad.js"
}
```

**Response:**
```json
{
  "blocked": true,
  "url": "https://ads.example.com/ad.js"
}
```

## Configuration

### Server URL
The base URL of your NGShield instance. Examples:
- Development: `http://localhost:8000`
- Production: `https://ngshield.example.com`

### API Key
A long token generated in your NGShield dashboard under Settings → API Keys. Keep this secret!

### Auto-Refresh
The extension automatically refreshes the blocklist every 1 hour. You can manually refresh by clicking "Refresh Blocklist" in the popup.

## Troubleshooting

### Ads still appearing
1. Check that the extension is enabled in `chrome://extensions/`
2. Verify API key is correctly set (click extension icon → Settings)
3. Try clicking "Refresh Blocklist"
4. Clear browser cache (Ctrl+Shift+Delete)

### "Rescan failed" errors
1. Check that your NGShield server is running
2. Verify the server URL is correct (no trailing slash)
3. Ensure your API key is valid and not expired
4. Check browser console (F12) for detailed errors

### High memory usage
The extension caches the blocklist in memory. If you have thousands of blocked URLs:
- Manually delete old alerts from NGShield dashboard
- Reduce the number of monitored domains
- Restart Chrome

## Privacy

- The extension only communicates with your NGShield server
- Blocklist is stored locally in your browser
- Extension does not track your browsing habits
- All data stays on your device and server

## Development

### File Structure
- `manifest.json` - Extension metadata and permissions
- `background.js` - Service worker; handles blocklist updates and blocking
- `content.js` - Injected into all pages; hides ads and elements
- `popup.html` - UI shown when you click the extension icon
- `popup.js` - Logic for the popup
- `styles.css` - Styling for popup

### Adding new blocking rules
Edit the `adSelectors` array in `content.js` to add new CSS selectors for ads.

### Testing
1. Make changes to any file
2. Go to `chrome://extensions/`
3. Click the reload icon for NGShield
4. Refresh the web page you're testing

## Support

For issues, feature requests, or questions:
- Open an issue on the NGShield GitHub repository
- Check the NGShield documentation at your server's `/api_docs/` page

## License

NGShield Browser Extension is licensed under the same license as NGShield.
