#!/usr/bin/env python3
import argparse
import email
import getpass
import imaplib
import json
import logging
import os
import plistlib
import re
import zipfile
from datetime import datetime
from email.header import decode_header

import keyring
from tqdm import tqdm


def get_backup_dir(email_address):
    """Get the backup directory path for the email account"""
    documents_dir = os.path.expanduser("~/Documents")
    backup_base = os.path.join(documents_dir, "email_backups")
    account_dir = os.path.join(backup_base, email_address)
    return account_dir


def sanitize_email(email_address):
    """Sanitize email address for logging"""
    if not email_address:
        return "REDACTED"
    username, domain = email_address.split("@")
    return f"{username[0]}***@{domain}"


def sanitize_folder(folder_name):
    """Sanitize folder name for logging"""
    if not folder_name:
        return "REDACTED"
    return re.sub(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "REDACTED", folder_name
    )


def contains_sensitive_data(text):
    """Check if text contains potentially sensitive data"""
    sensitive_patterns = [
        r"\b\d{16}\b",  # Credit card numbers
        r"\b\d{3}-\d{2}-\d{4}\b",  # Social security numbers
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email addresses
        r"\b\d{10}\b",  # Phone numbers
        r"\b[A-Z]{2}\d{6}[A-Z]?\b",  # Passport numbers
    ]
    return any(re.search(pattern, text) for pattern in sensitive_patterns)


def setup_logging(email_address):
    """Setup logging for the email account"""
    account_dir = get_backup_dir(email_address)
    log_dir = os.path.join(account_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(
        log_dir, f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )

    # Add warning about sensitive data
    with open(log_file, "w") as f:
        f.write(
            "WARNING: This log file may contain sensitive information. Handle with care.\n\n"
        )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


def get_mail_app_accounts():
    """Get email accounts from Mail.app configuration"""
    accounts_file = os.path.expanduser("~/Library/Mail/V9/MailData/Accounts.plist")
    if not os.path.exists(accounts_file):
        return None

    try:
        with open(accounts_file, "rb") as f:
            accounts_data = plistlib.load(f)

        email_accounts = []
        for account in accounts_data.get("MailAccounts", []):
            if account.get("AccountType") == "EmailAccount":
                email_accounts.append(
                    {
                        "email": account.get("AccountEmailAddress"),
                        "imap_server": account.get("AccountHostName"),
                        "username": account.get("AccountUserName"),
                        "port": account.get("AccountPort", 993),
                    }
                )
        return email_accounts
    except Exception as e:
        logging.error(f"Error reading Mail.app accounts: {str(e)}")
        return None


def select_account(accounts):
    """Let user select an account from the list"""
    if not accounts:
        return None

    print("\nAvailable Mail.app accounts:")
    for i, account in enumerate(accounts, 1):
        # Sanitize email for display
        safe_email = sanitize_email(account["email"])
        print(f"{i}. {safe_email} ({account['imap_server']})")

    while True:
        try:
            choice = input(
                "\nSelect account number (or press Enter to enter manually): "
            ).strip()
            if not choice:  # Empty input
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(accounts):
                return accounts[idx]
            print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")


def get_accounts_file():
    """Get the path to the accounts file"""
    documents_dir = os.path.expanduser("~/Documents")
    backup_base = os.path.join(documents_dir, "email_backups")
    os.makedirs(backup_base, exist_ok=True)
    return os.path.join(backup_base, ".accounts.json")


def load_accounts():
    """Load saved email accounts"""
    accounts_file = get_accounts_file()
    if os.path.exists(accounts_file):
        try:
            with open(accounts_file, "r") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading accounts: {str(e)}")
    return []


def save_accounts(accounts):
    """Save email accounts (without passwords)"""
    accounts_file = get_accounts_file()
    try:
        with open(accounts_file, "w") as f:
            json.dump(accounts, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving accounts: {str(e)}")


def add_account(email_address=None):
    """Add a new email account"""
    # If email is provided, try to find it in Mail.app accounts first
    if email_address:
        accounts = get_mail_app_accounts()
        if accounts:
            for account in accounts:
                if account["email"] == email_address:
                    imap_server = account["imap_server"]
                    print(f"\nFound account: {sanitize_email(email_address)}")
                    password = getpass.getpass(
                        "Enter password (or App Password if 2FA is enabled): "
                    )
                    return {
                        "email": email_address,
                        "imap_server": imap_server,
                        "password": password,
                    }

    # If no email provided or not found in Mail.app, try Mail.app accounts first
    accounts = get_mail_app_accounts()
    if accounts:
        selected_account = select_account(accounts)
        if selected_account:
            email_address = selected_account["email"]
            imap_server = selected_account["imap_server"]
            print(f"\nSelected account: {sanitize_email(email_address)}")
            password = getpass.getpass(
                "Enter password (or App Password if 2FA is enabled): "
            )
            return {
                "email": email_address,
                "imap_server": imap_server,
                "password": password,
            }

    # Manual input
    if not email_address:
        email_address = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")
    imap_server = input("Enter IMAP server: ")

    return {"email": email_address, "imap_server": imap_server, "password": password}


def store_account(account):
    """Store account securely"""
    # Store password in keyring
    keyring.set_password("email_backup", account["email"], account["password"])

    # Store account info without password
    accounts = load_accounts()
    account_info = {"email": account["email"], "imap_server": account["imap_server"]}

    # Update if account exists, otherwise append
    for i, existing in enumerate(accounts):
        if existing["email"] == account["email"]:
            accounts[i] = account_info
            break
    else:
        accounts.append(account_info)

    save_accounts(accounts)


def get_account_password(email):
    """Get stored password for account"""
    return keyring.get_password("email_backup", email)


def connect_to_server(email_address, password, imap_server, logger):
    """Connect to IMAP server"""
    try:
        imap = imaplib.IMAP4_SSL(imap_server)
        # Encode email address to handle non-ASCII characters
        encoded_email = email_address.encode("utf-8")
        imap.login(encoded_email.decode("utf-8"), password)
        safe_email = sanitize_email(email_address)
        logger.info(f"Successfully connected to {imap_server} for {safe_email}")
        return imap
    except Exception as e:
        logger.error(f"Failed to connect: {str(e)}")
        exit(1)


def sanitize_folder_name(folder_name):
    """Sanitize folder name to be safe for all operating systems"""
    if not folder_name:
        return "unnamed_folder"

    # Replace invalid characters with underscores
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        folder_name = folder_name.replace(char, "_")

    # Remove leading/trailing spaces and dots
    folder_name = folder_name.strip(". ")

    # If folder name is empty after sanitization, use a default name
    if not folder_name:
        return "unnamed_folder"

    # Limit folder name length to avoid issues with long paths
    if len(folder_name) > 255:
        folder_name = folder_name[:200]

    return folder_name


def get_folder_structure(imap, logger):
    """Get all folders from the email server"""
    folders = []
    for folder_data in imap.list()[1]:
        folder_name = folder_data.decode().split('"/"')[-1].strip()
        folders.append(folder_name)
    safe_folders = [sanitize_folder(f) for f in folders]
    logger.info(f"Found folders: {safe_folders}")
    return folders


def get_last_email_id(folder_path, logger):
    """Get the last downloaded email ID for a folder"""
    last_id_file = os.path.join(folder_path, ".last_email_id")
    if os.path.exists(last_id_file):
        with open(last_id_file, "r") as f:
            last_id = f.read().strip()
            logger.debug(
                f"Found last email ID for {sanitize_folder(folder_path)}: {last_id}"
            )
            return last_id
    logger.debug(f"No last email ID found for {sanitize_folder(folder_path)}")
    return None


def save_last_email_id(folder_path, email_id, logger):
    """Save the last downloaded email ID for a folder"""
    last_id_file = os.path.join(folder_path, ".last_email_id")
    with open(last_id_file, "w") as f:
        f.write(email_id)
    logger.debug(f"Saved last email ID for {sanitize_folder(folder_path)}: {email_id}")


def parse_email_date(date_str):
    """Parse email date string handling various timezone formats"""
    try:
        # Try standard format first
        return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
    except ValueError:
        try:
            # Try without timezone
            return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S")
        except ValueError:
            try:
                # Try with GMT/UTC timezone
                date_str = date_str.replace(" GMT", " +0000").replace(" UTC", " +0000")
                return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
            except ValueError:
                # If all parsing fails, use current time
                return datetime.now()


def decode_email_body(part, logger):
    """Decode email body with fallback encodings"""
    try:
        # Get the charset from the part, default to utf-8
        charset = part.get_content_charset() or "utf-8"

        # Common encodings to try
        encodings = [charset, "utf-8", "latin1", "iso-8859-1", "cp1252", "ascii"]

        # Try each encoding
        for encoding in encodings:
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    return "[Error: Empty email body]"
                return payload.decode(encoding)
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.warning(f"Error decoding with {encoding}: {str(e)}")
                continue

        # If all encodings fail, try to decode with 'replace' error handler
        try:
            return payload.decode("utf-8", errors="replace")
        except:
            return "[Error: Could not decode email body with any encoding]"

    except Exception as e:
        logger.error(f"Error in decode_email_body: {str(e)}")
        return "[Error: Could not decode email body]"


def safe_decode_header(header_value, logger):
    """Safely decode email header values"""
    try:
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        result = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                try:
                    if charset:
                        result.append(part.decode(charset))
                    else:
                        # Try common encodings if charset is not specified
                        for encoding in ["utf-8", "latin1", "iso-8859-1", "cp1252"]:
                            try:
                                result.append(part.decode(encoding))
                                break
                            except UnicodeDecodeError:
                                continue
                        else:
                            result.append(part.decode("utf-8", errors="replace"))
                except Exception as e:
                    logger.warning(f"Error decoding header part: {str(e)}")
                    result.append(part.decode("utf-8", errors="replace"))
            else:
                result.append(part)
        return "".join(result)
    except Exception as e:
        logger.error(f"Error in safe_decode_header: {str(e)}")
        return str(header_value)


def verify_download_count(imap, folder, local_path, logger):
    """Verify that all emails were downloaded successfully"""
    try:
        # Get count from server
        imap.select(folder)
        _, message_numbers = imap.search(None, "ALL")
        server_count = len(message_numbers[0].split())

        # Get count from local directory
        local_count = 0
        for item in os.listdir(local_path):
            if os.path.isdir(os.path.join(local_path, item)) and not item.startswith(
                "."
            ):
                local_count += 1

        if server_count != local_count:
            logger.warning(
                f"Download count mismatch in {sanitize_folder(folder)}: "
                f"Server has {server_count} emails, but {local_count} were downloaded"
            )
            return False
        else:
            logger.info(
                f"Verified download count for {sanitize_folder(folder)}: "
                f"{local_count} emails downloaded successfully"
            )
            return True
    except Exception as e:
        logger.error(f"Error verifying download count: {str(e)}")
        return False


def sanitize_filename(filename):
    """Sanitize filename to be safe for all operating systems"""
    if not filename:
        return "unnamed_attachment"

    # Replace invalid characters with underscores
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")

    # Remove leading/trailing spaces and dots
    filename = filename.strip(". ")

    # If filename is empty after sanitization, use a default name
    if not filename:
        return "unnamed_attachment"

    # Limit filename length to avoid issues with long paths
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:200] + ext

    return filename


def download_emails(imap, folder, local_path, logger):
    """Download all emails from a folder and save them as text files"""
    safe_folder = sanitize_folder(folder)
    logger.info(f"Starting download from folder: {safe_folder}")

    # Select the folder
    imap.select(folder)

    # Get last downloaded email ID
    last_id = get_last_email_id(local_path, logger)

    # Search for all emails in the folder
    if last_id:
        # Search for emails newer than the last downloaded one
        _, message_numbers = imap.search(None, f"UID {last_id}:*")
    else:
        # If no last ID, download all emails
        _, message_numbers = imap.search(None, "ALL")

    if not message_numbers[0]:
        logger.info(f"No new emails in folder: {safe_folder}")
        return

    message_list = message_numbers[0].split()
    logger.info(f"Found {len(message_list)} emails to download in {safe_folder}")

    latest_id = None
    has_attachments = False
    successful_downloads = 0

    for num in tqdm(message_list, desc=f"Downloading {safe_folder}", unit="email"):
        try:
            # Fetch the email message
            _, msg_data = imap.fetch(num, "(RFC822)")
            email_body = msg_data[0][1]

            try:
                email_message = email.message_from_bytes(email_body)
            except Exception as e:
                logger.error(f"Error creating email message from bytes: {str(e)}")
                continue

            # Get subject and date using safe decoding
            subject = safe_decode_header(email_message["subject"], logger)
            date = safe_decode_header(email_message["date"], logger)
            from_addr = safe_decode_header(email_message["from"], logger)
            to_addr = safe_decode_header(email_message["to"], logger)

            # Create filename from subject and date
            safe_subject = "".join(
                c for c in subject if c.isalnum() or c in (" ", "-", "_")
            ).strip()
            try:
                email_date = parse_email_date(date)
                safe_date = email_date.strftime("%Y%m%d_%H%M%S")
            except Exception as e:
                logger.warning(
                    f"Error parsing date '{date}': {str(e)}. Using current time."
                )
                safe_date = datetime.now().strftime("%Y%m%d_%H%M%S")

            email_filename = f"{safe_date}_{safe_subject[:50]}"

            # Create directory for this email
            email_dir = os.path.join(local_path, email_filename)
            os.makedirs(email_dir, exist_ok=True)

            # Save email content
            email_filepath = os.path.join(email_dir, "email.txt")
            with open(email_filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write(f"Subject: {subject}\n")
                f.write(f"Date: {date}\n")
                f.write(f"From: {from_addr}\n")
                f.write(f"To: {to_addr}\n")
                f.write("-" * 50 + "\n")

                # Write email body
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            body = decode_email_body(part, logger)
                            f.write(body)
                        # Handle attachments
                        elif part.get_content_maintype() != "multipart":
                            try:
                                filename = part.get_filename()
                                if filename:
                                    # Create attachments directory only if needed
                                    if not has_attachments:
                                        attachments_dir = os.path.join(
                                            email_dir, "attachments"
                                        )
                                        os.makedirs(attachments_dir, exist_ok=True)
                                        has_attachments = True

                                    # Decode and sanitize filename
                                    filename = safe_decode_header(filename, logger)
                                    safe_filename = sanitize_filename(filename)

                                    # If filename was changed, log it
                                    if safe_filename != filename:
                                        logger.info(
                                            f"Sanitized attachment filename: "
                                            f"{filename} -> {safe_filename}"
                                        )

                                    # Save attachment
                                    attachment_path = os.path.join(
                                        attachments_dir, safe_filename
                                    )
                                    with open(attachment_path, "wb") as attachment_file:
                                        attachment_file.write(
                                            part.get_payload(decode=True)
                                        )
                                    f.write(f"\n[Attachment: {filename}]\n")
                                    logger.debug(f"Saved attachment: {safe_filename}")
                            except Exception as e:
                                logger.error(f"Error saving attachment: {str(e)}")
                                f.write(f"\n[Error saving attachment: {str(e)}]\n")
                else:
                    body = decode_email_body(email_message, logger)
                    f.write(body)

            # Update latest ID
            latest_id = num.decode()
            successful_downloads += 1

        except Exception as e:
            logger.error(f"Error processing email {num}: {str(e)}")
            continue

    # Save the latest email ID
    if latest_id:
        save_last_email_id(local_path, latest_id, logger)
        logger.info(f"Updated last email ID for folder {safe_folder}: {latest_id}")

    # Verify download count
    if not verify_download_count(imap, folder, local_path, logger):
        logger.warning(
            f"Some emails may not have been downloaded successfully in {safe_folder}. "
            f"Successfully downloaded: {successful_downloads}/{len(message_list)}"
        )


def create_backup(email_address, logger):
    """Create a zip file containing all downloaded emails"""
    safe_email = sanitize_email(email_address)
    zip_filename = f"{safe_email.replace('@', '_at_')}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    logger.info(f"Creating zip archive: {zip_filename}")

    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(email_address):
            for file in files:
                if file.endswith(".log"):  # Skip log files
                    continue
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, email_address)
                zipf.write(filepath, arcname)

    logger.info(f"Zip archive created successfully: {zip_filename}")
    return zip_filename


def backup_account(email_address, password, imap_server, logger):
    """Backup a single email account"""
    try:
        # Connect to server
        imap = connect_to_server(email_address, password, imap_server, logger)

        # Get folder structure
        folders = get_folder_structure(imap, logger)

        # Create main directory for this email account
        account_dir = get_backup_dir(email_address)
        os.makedirs(account_dir, exist_ok=True)

        # Download emails from each folder
        all_folders_successful = True
        for folder in folders:
            # Create folder directory with sanitized name
            safe_folder_name = sanitize_folder_name(folder)
            folder_path = os.path.join(account_dir, safe_folder_name)
            os.makedirs(folder_path, exist_ok=True)

            # Download emails
            download_emails(imap, folder, folder_path, logger)

            # Verify download count
            if not verify_download_count(imap, folder, folder_path, logger):
                all_folders_successful = False

        # Create zip backup
        zip_filename = create_backup(account_dir, logger)

        if all_folders_successful:
            logger.info(
                f"Backup completed successfully for {sanitize_email(email_address)} - all emails verified"
            )
        else:
            logger.warning(
                f"Backup completed with some verification issues for {sanitize_email(email_address)}"
            )

        # Cleanup
        imap.close()
        imap.logout()

        return all_folders_successful
    except Exception as e:
        logger.error(
            f"Error backing up account {sanitize_email(email_address)}: {str(e)}"
        )
        return False


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Email Backup Tool")
    parser.add_argument(
        "--new",
        action="append",
        help="Add a new email account. Can be specified multiple times with email addresses.",
        default=[],
    )
    args = parser.parse_args()

    # Handle new account additions
    if args.new:
        print(f"\nAdding {len(args.new)} new account(s)...")
        for email in args.new:
            print(f"\nAdding account: {sanitize_email(email)}")
            account = add_account(email)
            store_account(account)
            print(f"Account {sanitize_email(account['email'])} added successfully")

    # Load all accounts
    accounts = load_accounts()
    if not accounts:
        print("No accounts found. Use --new to add an account.")
        return

    # Backup each account
    all_successful = True
    for account in accounts:
        email = account["email"]
        password = get_account_password(email)
        if not password:
            print(f"\nPassword not found for {sanitize_email(email)}. Skipping...")
            all_successful = False
            continue

        # Setup logging for this account
        logger = setup_logging(email)
        logger.info(f"Starting backup for {sanitize_email(email)}")

        # Backup the account
        if not backup_account(email, password, account["imap_server"], logger):
            all_successful = False

    if all_successful:
        print("\nAll accounts backed up successfully")
    else:
        print("\nSome accounts had issues during backup")


if __name__ == "__main__":
    main()
