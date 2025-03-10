# Gmail AutoAuth MCP Server

A Model Context Protocol (MCP) server for Gmail integration in Claude Desktop with auto authentication support. This server enables AI assistants to manage Gmail through natural language interactions.

![](https://badge.mcpx.dev?type=server 'MCP Server')
[![smithery badge](https://smithery.ai/badge/@gongrzhe/server-gmail-autoauth-mcp)](https://smithery.ai/server/@gongrzhe/server-gmail-autoauth-mcp)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)


## Features

- Send emails with subject, content, attachments, and recipients
- Full support for international characters in subject lines and email content
- Read email messages by ID with advanced MIME structure handling
- View email attachments information (filenames, types, sizes)
- Search emails with various criteria (subject, sender, date range)
- List all available Gmail labels (system and user-defined)
- List emails in inbox, sent, or custom labels
- Mark emails as read/unread
- Move emails to different labels/folders
- Delete emails
- Full integration with Gmail API
- Simple OAuth2 authentication flow with auto browser launch
- Support for both Desktop and Web application credentials
- Global credential storage for convenience
- Environment variable support for credentials and configuration

## Installation & Authentication

### Using Environment Variables (New)

You can provide OAuth credentials directly through environment variables:

1. Copy the `.env.example` file to `.env`
2. Fill in your Google OAuth credentials:
   - `GMAIL_CLIENT_ID` and `GMAIL_CLIENT_SECRET` - Required for authentication
   - `GMAIL_ACCESS_TOKEN` and `GMAIL_REFRESH_TOKEN` - Optional, to skip browser authentication
   - `GMAIL_TOKEN_EXPIRY` - Optional, timestamp of token expiration
   - `GMAIL_AUTH_SERVER_HOST` - Optional, hostname for the authentication server (default: localhost)
   - `GMAIL_AUTH_SERVER_PORT` - Optional, port for the authentication server (default: 3000)

Example:
```env
GMAIL_CLIENT_ID=your_client_id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your_client_secret
GMAIL_AUTH_SERVER_HOST=localhost
GMAIL_AUTH_SERVER_PORT=3000
```

### Installing via Smithery

To install Gmail AutoAuth for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@gongrzhe/server-gmail-autoauth-mcp):

```bash
npx -y @smithery/cli install @gongrzhe/server-gmail-autoauth-mcp --client claude
```

### Installing Manually
1. Create a Google Cloud Project and obtain credentials:

   a. Create a Google Cloud Project:
      - Go to [Google Cloud Console](https://console.cloud.google.com/)
      - Create a new project or select an existing one
      - Enable the Gmail API for your project

   b. Create OAuth 2.0 Credentials:
      - Go to "APIs & Services" > "Credentials"
      - Click "Create Credentials" > "OAuth client ID"
      - Choose either "Desktop app" or "Web application" as application type
      - Give it a name and click "Create"
      - For Web application, add the appropriate redirect URI based on your configuration:
        - Default: `http://localhost:3000/oauth2callback`
        - Custom: `http://{GMAIL_AUTH_SERVER_HOST}:{GMAIL_AUTH_SERVER_PORT}/oauth2callback`
      - Download the JSON file of your client's OAuth keys
      - Rename the key file to `gcp-oauth.keys.json`

2. Run Authentication:

   You can authenticate in two ways:

   a. Global Authentication (Recommended):
   ```bash
   # First time: Place gcp-oauth.keys.json in your home directory's .gmail-mcp folder
   mkdir -p ~/.gmail-mcp
   mv gcp-oauth.keys.json ~/.gmail-mcp/

   # Run authentication from anywhere
   npx @gongrzhe/server-gmail-autoauth-mcp auth
   ```

   b. Local Authentication:
   ```bash
   # Place gcp-oauth.keys.json in your current directory
   # The file will be automatically copied to global config
   npx @gongrzhe/server-gmail-autoauth-mcp auth
   ```

   The authentication process will:
   - Look for `gcp-oauth.keys.json` in the current directory or `~/.gmail-mcp/`
   - If found in current directory, copy it to `~/.gmail-mcp/`
   - Open your default browser for Google authentication
   - Save credentials as `~/.gmail-mcp/credentials.json`

   > **Note**: 
   > - After successful authentication, credentials are stored globally in `~/.gmail-mcp/` and can be used from any directory
   > - Both Desktop app and Web application credentials are supported
   > - For Web application credentials, make sure to add the appropriate redirect URI to your authorized redirect URIs based on your configuration:
   >   - Default: `http://localhost:3000/oauth2callback`
   >   - Custom: `http://{GMAIL_AUTH_SERVER_HOST}:{GMAIL_AUTH_SERVER_PORT}/oauth2callback`

3. Configure in Claude Desktop:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "npx",
      "args": [
        "@gongrzhe/server-gmail-autoauth-mcp"
      ]
    }
  }
}
```

### Docker Support

If you prefer using Docker:

1. Authentication:
```bash
docker run -i --rm \
  --mount type=bind,source=/path/to/gcp-oauth.keys.json,target=/gcp-oauth.keys.json \
  -v mcp-gmail:/gmail-server \
  -e GMAIL_OAUTH_PATH=/gcp-oauth.keys.json \
  -e "GMAIL_CREDENTIALS_PATH=/gmail-server/credentials.json" \
  -e "GMAIL_AUTH_SERVER_HOST=localhost" \
  -e "GMAIL_AUTH_SERVER_PORT=3000" \
  -p 3000:3000 \
  mcp/gmail auth
```

2. Usage:
```json
{
  "mcpServers": {
    "gmail": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "mcp-gmail:/gmail-server",
        "-e",
        "GMAIL_CREDENTIALS_PATH=/gmail-server/credentials.json",
        "mcp/gmail"
      ]
    }
  }
}
```

## Usage Examples

The server provides several tools that can be used through the Claude Desktop:

### Send Email
```json
{
  "to": ["recipient@example.com"],
  "subject": "Meeting Tomorrow",
  "body": "Hi,\n\nJust a reminder about our meeting tomorrow at 10 AM.\n\nBest regards",
  "cc": ["cc@example.com"],
  "bcc": ["bcc@example.com"]
}
```

### Search Emails
```json
{
  "query": "from:sender@example.com after:2024/01/01",
  "maxResults": 10
}
```

### Read Email
```json
{
  "messageId": "message123"
}
```

### Move Email
```json
{
  "messageId": "message123",
  "labelIds": ["INBOX", "IMPORTANT"]
}
```

### List Email Labels
```json
{
  // No parameters needed
}
```

## Advanced Features

### International Character Support

The server fully supports non-ASCII characters in email subjects and content, including:
- Turkish, Chinese, Japanese, Korean, and other non-Latin alphabets
- Special characters and symbols
- Proper encoding ensures correct display in email clients like Outlook

### Complex Email Handling

The server can properly extract content from various email types:
- HTML-formatted emails
- Multi-part MIME messages
- Calendar invitations
- Notification emails (LinkedIn, social media, etc.)
- Emails with attachments

## Security Notes

- OAuth credentials are stored securely in your local environment (`~/.gmail-mcp/`)
- The server uses offline access to maintain persistent authentication
- Never share or commit your credentials to version control
- Regularly review and revoke unused access in your Google Account settings
- Credentials are stored globally but are only accessible by the current user

## Troubleshooting

1. **OAuth Keys Not Found**
   - Make sure `gcp-oauth.keys.json` is in either your current directory or `~/.gmail-mcp/`
   - Check file permissions

2. **Invalid Credentials Format**
   - Ensure your OAuth keys file contains either `web` or `installed` credentials
   - For web applications, verify the redirect URI is correctly configured

3. **Port Already in Use**
   - If the default port (3000) is already in use, you can:
     - Free up the port by stopping the process using it
     - Or configure a different port using the `GMAIL_AUTH_SERVER_PORT` environment variable
   - Remember to update your Google OAuth redirect URIs if you change the host or port

4. **Custom Host Configuration**
   - If using a custom host with `GMAIL_AUTH_SERVER_HOST`, ensure:
     - The hostname is accessible from the device where you're running the server
     - You've updated your Google OAuth redirect URIs accordingly

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the ISC License.

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.

## Development

### Testing with Environment Variables

For testing purposes, you can create a `.env` file in the project root with your test credentials:

```env
GMAIL_CLIENT_ID=your_test_client_id
GMAIL_CLIENT_SECRET=your_test_client_secret
GMAIL_AUTH_SERVER_HOST=localhost
GMAIL_AUTH_SERVER_PORT=3000
```

This allows you to test the application without modifying any code or creating credential files.
