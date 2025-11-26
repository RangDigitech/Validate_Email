"""
Test script to verify email attachment handling
This will show us the actual MIME structure being generated
"""
import sys
sys.path.insert(0, r'c:\Users\JEET\Downloads\Mail_Verifier1')

from utils.emailer import _make_msg

# Create a test message with attachment
test_attachment = {
    "filename": "test.txt",
    "data": b"Hello, this is a test attachment!",
    "content_type": "text/plain"
}

msg = _make_msg(
    to="test@example.com",
    subject="Test Email with Attachment",
    html_body="<h1>Test HTML</h1><p>This is a test email.</p>",
    text_body="Test plain text\n\nThis is a test email.",
    attachments=[test_attachment]
)

# Print the message structure
print("=" * 80)
print("EMAIL MESSAGE STRUCTURE:")
print("=" * 80)
print(f"Content-Type: {msg.get_content_type()}")
print(f"Is multipart: {msg.is_multipart()}")
print()

if msg.is_multipart():
    print("Message parts:")
    for i, part in enumerate(msg.walk()):
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition()
        print(f"  Part {i}: {content_type} (disposition: {content_disposition})")
        if content_disposition == 'attachment':
            print(f"    Filename: {part.get_filename()}")

print()
print("=" * 80)
print("FULL MESSAGE (first 1000 chars):")
print("=" * 80)
print(str(msg)[:1000])
