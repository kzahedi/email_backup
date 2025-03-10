# Email Backup Tool

This tool allows you to backup your Gmail account by downloading all emails from all folders and saving them as text files, then creating a zip archive of the backup.

## Features

- Downloads all folders and emails from Gmail
- Saves emails as readable text files
- Downloads and saves email attachments
- Creates a zip archive of the backup
- Supports incremental backups (only downloads new emails)
- Preserves folder structure
- Handles multipart emails
- Secure password input
- Automatic detection of Mail.app email accounts (macOS)
- Privacy protection for sensitive information

## Requirements

- Python 3.6 or higher
- tqdm package for progress bars
- macOS (for Mail.app account integration)

## Usage

1. Run the script:
   ```bash
   python email_backup.py
   ```

2. The script will:
   - Automatically detect email accounts configured in Mail.app
   - Show a list of available accounts (with email addresses partially redacted)
   - Let you select an account or enter credentials manually
   - If selecting a Mail.app account, you'll only need to enter the password
   - If entering manually, provide email address and password

3. The script will then:
   - Connect to your email server
   - Download all folders and emails (or only new emails if running for the second time)
   - Download all attachments
   - Create a zip file with the backup

## Backup Location

All backups are stored in your Documents folder:
```
~/Documents/email_backups/
└── email_address/
    ├── logs/
    │   └── backup_YYYYMMDD_HHMMSS.log
    ├── folder1/
    │   ├── .last_email_id
    │   ├── 20240315_123456_Email_Subject1/
    │   │   ├── email.txt
    │   │   └── attachments/
    │   │       ├── document1.pdf
    │   │       └── image1.jpg
    │   └── 20240315_123457_Email_Subject2/
    │       ├── email.txt
    │       └── attachments/
    └── folder2/
        └── ...
```

- Each email account gets its own directory under `~/Documents/email_backups/`
- Each email is saved in its own directory named with date and subject
- The email content is saved as `email.txt`
- Attachments are saved in an `attachments` subdirectory
- Each folder contains a `.last_email_id` file to track the last downloaded email
- A zip file is created with the format: `email_at_domain_backup_YYYYMMDD_HHMMSS.zip`

## Mail.app Integration

On macOS, the script can automatically detect email accounts configured in Mail.app:
- Reads account information from `~/Library/Mail/V9/MailData/Accounts.plist`
- Shows a list of available email accounts (with email addresses partially redacted)
- Allows you to select an account or enter credentials manually
- Only requires password entry for Mail.app accounts
- Falls back to manual entry if no Mail.app accounts are found

## Incremental Backup

The script supports incremental backups:
- On first run, it downloads all emails
- On subsequent runs, it only downloads new emails that arrived after the last backup
- Each folder maintains its own `.last_email_id` file to track the last downloaded email
- You can run the script multiple times to keep your backup up to date

## Security and Privacy

The script includes several security and privacy protection measures:

### Password Security
- Passwords are never stored and are only used for the current session
- Password input is hidden from the screen
- For Gmail accounts with 2FA enabled, use an App Password instead of your regular password

### Connection Security
- Uses secure IMAP SSL connection
- All network communication is encrypted

### Privacy Protection
- Email addresses are partially redacted in logs (e.g., "j***@example.com")
- Folder names containing email addresses are redacted in logs
- Log files include a warning about potential sensitive information
- Backup files are stored locally only
- No data is transmitted to external servers

### Sensitive Data Detection
The script includes detection for common sensitive data patterns:
- Credit card numbers
- Social security numbers
- Email addresses
- Phone numbers
- Passport numbers

### File System Security
- All backup files are stored in your local Documents folder
- Backup files are not included in Git repository
- Log files are excluded from Git repository
- Each backup session creates a new log file with timestamp

## Error Handling

The script includes error handling for:
- Connection failures
- Invalid credentials
- Email decoding issues
- File system operations
- Attachment processing errors
- Mail.app configuration reading errors

If any individual email or attachment fails to process, the script will continue with the remaining items and report the error.