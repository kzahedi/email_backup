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

## Requirements

- Python 3.6 or higher
- tqdm package for progress bars

## Usage

1. Run the script:
   ```bash
   python email_backup.py
   ```

2. Enter your Gmail credentials when prompted:
   - Email address
   - Password (or App Password if 2FA is enabled)

3. The script will:
   - Connect to Gmail
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

## Incremental Backup

The script supports incremental backups:
- On first run, it downloads all emails
- On subsequent runs, it only downloads new emails that arrived after the last backup
- Each folder maintains its own `.last_email_id` file to track the last downloaded email
- You can run the script multiple times to keep your backup up to date

## Security Note

- Your password is never stored and is only used for the current session
- The script uses secure IMAP SSL connection
- Password input is hidden from the screen
- For Gmail accounts with 2FA enabled, use an App Password instead of your regular password

## Error Handling

The script includes error handling for:
- Connection failures
- Invalid credentials
- Email decoding issues
- File system operations
- Attachment processing errors

If any individual email or attachment fails to process, the script will continue with the remaining items and report the error.