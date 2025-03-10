#!/usr/bin/env python3
import email
import getpass
import imaplib
import logging
import os
import zipfile
from datetime import datetime
from email.header import decode_header

from tqdm import tqdm


def get_backup_dir(email_address):
    """Get the backup directory path for the email account"""
    documents_dir = os.path.expanduser("~/Documents")
    backup_base = os.path.join(documents_dir, "email_backups")
    account_dir = os.path.join(backup_base, email_address)
    return account_dir


def setup_logging(email_address):
    """Setup logging for the email account"""
    account_dir = get_backup_dir(email_address)
    log_dir = os.path.join(account_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(
        log_dir, f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(log_file), logging.StreamHandler()],
    )
    return logging.getLogger(__name__)


def get_credentials():
    """Get email credentials from user"""
    email_address = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")
    imap_server = input("Enter IMAP server address: ")
    return email_address, password, imap_server


def connect_to_server(email_address, password, imap_server, logger):
    """Connect to IMAP server"""
    try:
        imap = imaplib.IMAP4_SSL(imap_server)
        # Encode email address to handle non-ASCII characters
        encoded_email = email_address.encode("utf-8")
        imap.login(encoded_email.decode("utf-8"), password)
        logger.info(f"Successfully connected to {imap_server}")
        return imap
    except Exception as e:
        logger.error(f"Failed to connect: {str(e)}")
        exit(1)


def get_folder_structure(imap, logger):
    """Get all folders from the email server"""
    folders = []
    for folder_data in imap.list()[1]:
        folder_name = folder_data.decode().split('"/"')[-1].strip()
        folders.append(folder_name)
    logger.info(f"Found folders: {folders}")
    return folders


def get_last_email_id(folder_path, logger):
    """Get the last downloaded email ID for a folder"""
    last_id_file = os.path.join(folder_path, ".last_email_id")
    if os.path.exists(last_id_file):
        with open(last_id_file, "r") as f:
            last_id = f.read().strip()
            logger.debug(f"Found last email ID for {folder_path}: {last_id}")
            return last_id
    logger.debug(f"No last email ID found for {folder_path}")
    return None


def save_last_email_id(folder_path, email_id, logger):
    """Save the last downloaded email ID for a folder"""
    last_id_file = os.path.join(folder_path, ".last_email_id")
    with open(last_id_file, "w") as f:
        f.write(email_id)
    logger.debug(f"Saved last email ID for {folder_path}: {email_id}")


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


def download_emails(imap, folder, local_path, logger):
    """Download all emails from a folder and save them as text files"""
    logger.info(f"Starting download from folder: {folder}")

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
        logger.info(f"No new emails in folder: {folder}")
        return

    message_list = message_numbers[0].split()
    logger.info(f"Found {len(message_list)} emails to download in {folder}")

    latest_id = None
    has_attachments = False

    for num in tqdm(message_list, desc=f"Downloading {folder}", unit="email"):
        try:
            # Fetch the email message
            _, msg_data = imap.fetch(num, "(RFC822)")
            email_body = msg_data[0][1]
            email_message = email.message_from_bytes(email_body)

            # Get subject and date
            subject = decode_header(email_message["subject"])[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode()
            date = email_message["date"]

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
            with open(email_filepath, "w", encoding="utf-8") as f:
                f.write(f"Subject: {subject}\n")
                f.write(f"Date: {date}\n")
                f.write(f"From: {email_message['from']}\n")
                f.write(f"To: {email_message['to']}\n")
                f.write("-" * 50 + "\n")

                # Write email body
                if email_message.is_multipart():
                    for part in email_message.walk():
                        if part.get_content_type() == "text/plain":
                            try:
                                body = part.get_payload(decode=True).decode()
                                f.write(body)
                            except Exception as e:
                                logger.error(f"Error decoding email body: {str(e)}")
                                f.write("[Error: Could not decode email body]")
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

                                    # Decode filename if needed
                                    filename = decode_header(filename)[0][0]
                                    if isinstance(filename, bytes):
                                        filename = filename.decode()

                                    # Save attachment
                                    attachment_path = os.path.join(
                                        attachments_dir, filename
                                    )
                                    with open(attachment_path, "wb") as attachment_file:
                                        attachment_file.write(
                                            part.get_payload(decode=True)
                                        )
                                    f.write(f"\n[Attachment: {filename}]\n")
                                    logger.debug(f"Saved attachment: {filename}")
                            except Exception as e:
                                logger.error(f"Error saving attachment: {str(e)}")
                                f.write(f"\n[Error saving attachment: {str(e)}]\n")
                else:
                    try:
                        body = email_message.get_payload(decode=True).decode()
                        f.write(body)
                    except Exception as e:
                        logger.error(f"Error decoding email body: {str(e)}")
                        f.write("[Error: Could not decode email body]")

            # Update latest ID
            latest_id = num.decode()

        except Exception as e:
            logger.error(f"Error processing email {num}: {str(e)}")
            continue

    # Save the latest email ID
    if latest_id:
        save_last_email_id(local_path, latest_id, logger)
        logger.info(f"Updated last email ID for folder {folder}: {latest_id}")


def create_backup(email_address, logger):
    """Create a zip file containing all downloaded emails"""
    zip_filename = f"{email_address.replace('@', '_at_')}_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
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


def main():
    # Get credentials
    email_address, password, imap_server = get_credentials()

    # Setup logging
    logger = setup_logging(email_address)
    logger.info("Starting email backup process")

    # Connect to server
    imap = connect_to_server(email_address, password, imap_server, logger)

    # Get folder structure
    folders = get_folder_structure(imap, logger)

    # Create main directory for this email account
    account_dir = get_backup_dir(email_address)
    os.makedirs(account_dir, exist_ok=True)

    # Download emails from each folder
    for folder in folders:
        # Create folder directory
        folder_path = os.path.join(account_dir, folder)
        os.makedirs(folder_path, exist_ok=True)

        # Download emails
        download_emails(imap, folder, folder_path, logger)

    # Create zip backup
    zip_filename = create_backup(account_dir, logger)
    logger.info("Backup process completed successfully")

    # Cleanup
    imap.close()
    imap.logout()


if __name__ == "__main__":
    main()
