# test_welcome_email.py

from emails import build_welcome_email

# Fake user object for testing


class User:
    def __init__(self, username, email):
        self.username = username
        self.email = email


# Example user and password
user = User(username="johndoe", email="john@example.com")
temporary_password = "Welcome@123"

# Generate the HTML email content
email_html = build_welcome_email(user, temporary_password)

# Write it to an HTML file
with open("welcome_email_test.html", "w", encoding="utf-8") as f:
    f.write(email_html)
    print("✅ Welcome email saved as welcome_email_test.html")
    print("💡 Open this file in your browser to preview.")
