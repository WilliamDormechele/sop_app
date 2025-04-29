# emails.py
# 📩 NHRC SOP Portal - Email Templates
# ------------------------------------------------
# This file contains reusable functions to generate
# beautiful HTML emails for password reset, welcome,
# SOP assignment notifications, reminders, etc.
# ------------------------------------------------

# emails.py
# 📩 NHRC SOP Portal - Email Templates
# ------------------------------------------------

# 🔒 Password Reset Email
def build_password_reset_email(user, random_password, subject="🔒 Password Reset Notification"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>{subject}</title></head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0;">
  <div style="max-width: 600px; margin: 40px auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
    <h2 style="color: #0044cc; text-align: center;">{subject}</h2>
    <p>Dear <strong>{user.username}</strong>,</p>
    <p>Your password has been automatically reset. Please find your new temporary password below:</p>
    <div style="background-color: #f0f0f0; padding: 15px; text-align: center; border-radius: 6px; font-size: 18px; font-weight: bold; color: #333;">🔑 {random_password}</div>
    <p style="margin-top: 20px;">Please log in and change it immediately for your account security.</p>
    <p>If you did not request this reset, please contact the administrator immediately.</p>
    <br>
    <p style="text-align: center; color: #888;">Best regards,<br><strong>NHRC SOP Portal Team</strong></p>
  </div>
</body>
</html>"""



# 👋 New Account Welcome Email
def build_welcome_email(user, temporary_password, subject="👋 Welcome to NHRC SOP Portal"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>{subject}</title></head>
<body style="font-family: Arial, sans-serif; background-color: #f9f9f9; margin: 0; padding: 0;">
  <div style="max-width: 600px; margin: 40px auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
    <h2 style="color: #0044cc; text-align: center;">{subject}</h2>
    <p>Dear <strong>{user.username}</strong>,</p>
    <p>Welcome! Your account has been created successfully.</p>
    <p>Here are your login credentials:</p>
    <ul>
      <li><strong>Username:</strong> {user.username}</li>
      <li><strong>Temporary Password:</strong> {temporary_password}</li>
    </ul>
    <p>Please login and change your password immediately.</p>
    <a href="http://127.0.0.1:5000/login" style="display:inline-block;margin-top:20px;padding:10px 20px;background-color:#0044cc;color:#fff;border-radius:6px;text-decoration:none;">Login Now</a>
    <p style="margin-top: 30px;">If you need any help, contact support.</p>
    <p style="text-align: center; color: #888;">NHRC SOP Portal Team</p>
  </div>
</body>
</html>"""


# 📄 New SOP Assignment Email
def build_sop_assignment_email(user, sop_title, subject="📄 New SOP Assignment Notification"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>{subject}</title>
      <style>
        body {{
          font-family: Arial, sans-serif;
          background-color: #f4f4f4;
          margin: 0; padding: 0;
        }}
        .container {{
          max-width: 600px;
          margin: 40px auto;
          background: #ffffff;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
          text-align: center;
          padding-bottom: 20px;
          border-bottom: 1px solid #dddddd;
        }}
        .title {{
          color: #0044cc;
        }}
        .content {{
          padding: 20px 0;
          color: #333333;
          font-size: 16px;
        }}
        .footer {{
          margin-top: 30px;
          font-size: 12px;
          text-align: center;
          color: #888888;
        }}
      </style>
    </head>
    <body>
    <div class="container">
      <div class="header">
        <h2 class="title">{subject}</h2>
      </div>
      <div class="content">
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>A new SOP <strong>"{sop_title}"</strong> has been assigned to you.</p>
        <p>Please review and acknowledge it at your earliest convenience.</p>
        <a href="http://127.0.0.1:5000/login" style="background:#0044cc;color:white;padding:10px 20px;border-radius:5px;text-decoration:none;">View SOP</a>
        <p style="margin-top: 30px;">If you have any questions, contact your supervisor.</p>
      </div>
      <div class="footer">
        Best regards,<br><strong>NHRC SOP Portal Team</strong>
      </div>
    </div>
    </body>
    </html>
    """


# ⏰ SOP Due Reminder Email
def build_due_reminder_email(user, sop_title, subject="⏰ SOP Due Reminder"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>{subject}</title></head>
<body style="font-family: Arial, sans-serif; background-color: #fff9f0; margin: 0; padding: 0;">
  <div style="max-width: 600px; margin: 40px auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h2 style="color: #ff6600; text-align: center;">{subject}</h2>
    <p>Dear <strong>{user.username}</strong>,</p>
    <p>This is a reminder that your SOP:</p>
    <div style="background-color: #fff2cc; padding: 15px; text-align: center; border-radius: 6px; font-size: 18px; font-weight: bold;">📄 {sop_title}</div>
    <p>is due on <strong>to read</strong>.</p>
    <p>Please ensure you complete the review and acknowledgement before the deadline.</p>
    <a href="http://127.0.0.1:5000/login" style="background-color:#ff6600;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;margin-top:20px;display:inline-block;">View SOP</a>
    <p style="text-align: center; color: #888; margin-top: 30px;">NHRC SOP Portal Team</p>
  </div>
</body>
</html>"""


# 🛠 Amendment Closed Notification Email
def build_amendment_closed_email(user, sop_title, amendment_details, subject="🛠 Amendment Closed Notification"):
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>{subject}</title></head>
<body style="font-family: Arial, sans-serif; background-color: #eef9f2; margin: 0; padding: 0;">
  <div style="max-width: 600px; margin: 40px auto; background: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h2 style="color: #28a745; text-align: center;">{subject}</h2>
    <p>Dear <strong>{user.username}</strong>,</p>
    <p>The amendment request for the SOP titled:</p>
    <div style="background-color: #d4edda; padding: 15px; text-align: center; border-radius: 6px; font-size: 18px; font-weight: bold;">📄 {sop_title}</div>
    <p>has been <strong>reviewed and closed</strong>.</p>
    <p><strong>Summary of amendment:</strong></p>
    <div style="background-color: #f8f9fa; padding: 10px; border-radius: 5px; color: #555;">
      {amendment_details}
    </div>
    <p>Please login to review the updated SOP if applicable.</p>
    <a href="http://127.0.0.1:5000/login" style="background-color:#28a745;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;margin-top:20px;display:inline-block;">View SOP</a>
    <p style="text-align: center; color: #888; margin-top: 30px;">NHRC SOP Portal Team</p>
  </div>
</body>
</html>"""

# build_password_reset_email
def build_password_reset_email(user, random_password, subject="🔒 Password Reset Notification"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>{subject}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
      body {{
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        margin: 0;
        padding: 0;
      }}
      .container {{
        max-width: 600px;
        margin: 40px auto;
        background: #ffffff;
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
      }}
      .header {{
        text-align: center;
        padding-bottom: 20px;
        border-bottom: 1px solid #dddddd;
      }}
      .header img {{
        width: 80px;
        margin-bottom: 10px;
      }}
      .title {{
        color: #0044cc;
        margin-top: 0;
      }}
      .content {{
        padding: 20px 0;
        color: #333333;
        font-size: 16px;
      }}
      .footer {{
        margin-top: 30px;
        font-size: 12px;
        text-align: center;
        color: #888888;
        border-top: 1px solid #dddddd;
        padding-top: 15px;
      }}
      .password-box {{
        background-color: #f0f0f0;
        padding: 15px;
        margin: 20px 0;
        border-radius: 6px;
        font-size: 18px;
        font-weight: bold;
        text-align: center;
        color: #333333;
      }}
      .button {{
        display: inline-block;
        background-color: #0044cc;
        color: #ffffff;
        padding: 10px 20px;
        margin-top: 20px;
        border-radius: 6px;
        text-decoration: none;
      }}
    </style>
    </head>
    <body>

    <div class="container">
      <div class="header">
        <img src="https://i.imgur.com/6NKPrhK.png" alt="NHRC SOP Logo">
        <h2 class="title">{subject}</h2>
      </div>

      <div class="content">
        <p>Dear <strong>{user.username}</strong>,</p>

        <p>Your password has been automatically reset. Please find your new temporary password below:</p>

        <div class="password-box">
          🔑 {random_password}
        </div>

        <p>Please log in using this password and change it immediately for your account security.</p>

        <a href="http://127.0.0.1:5000/login" class="button">Login Now</a>

        <p style="margin-top: 30px;">If you did not request this reset, please contact the administrator immediately.</p>
      </div>

      <div class="footer">
        Best regards,<br>
        <strong>NHRC SOP Portal Team</strong><br>
        <br>
        <a href="#" style="color: #888;">Privacy Policy</a> | <a href="#" style="color: #888;">Contact Support</a><br>
        © 2025 NHRC SOP Portal
      </div>
    </div>

    </body>
    </html>
    """


# build_welcome_email
def build_welcome_email(user, temporary_password, subject="👋 Welcome to NHRC SOP Portal"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>{subject}</title>
      <style>
        body {{
          font-family: Arial, sans-serif;
          background-color: #f9f9f9;
          margin: 0; padding: 0;
        }}
        .container {{
          max-width: 600px;
          margin: 40px auto;
          background: #ffffff;
          padding: 30px;
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
          text-align: center;
          padding-bottom: 20px;
        }}
        .content {{
          color: #333;
          font-size: 16px;
          padding: 20px 0;
        }}
        .footer {{
          margin-top: 30px;
          font-size: 12px;
          text-align: center;
          color: #888;
        }}
      </style>
    </head>
    <body>
    <div class="container">
      <div class="header">
        <h2>{subject}</h2>
      </div>
      <div class="content">
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>Your account has been created successfully.</p>
        <p>Here are your login credentials:</p>
        <ul>
          <li><strong>Username:</strong> {user.username}</li>
          <li><strong>Temporary Password:</strong> {temporary_password}</li>
        </ul>
        <p>Please login and change your password immediately.</p>
        <a href="http://127.0.0.1:5000/login" style="background-color:#0044cc;color:#fff;padding:10px 20px;border-radius:5px;text-decoration:none;">Login Now</a>
      </div>
      <div class="footer">
        Welcome aboard!<br><strong>NHRC SOP Portal Team</strong>
      </div>
    </div>
    </body>
    </html>
    """
