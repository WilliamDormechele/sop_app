# emails.py
# 📩 NHRC SOP Portal - Email Templates

# 🔒 Password Reset Email
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
        <h2 class="title">{subject}</h2>
      </div>
      <div class="content">
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>Your password has been automatically reset. Here is your new password:</p>
        <div class="password-box">
          🔑 {random_password}
        </div>
        <p>Please log in and change it immediately for your account security.</p>
        <a href="http://127.0.0.1:5000/login" class="button">Login Now</a>
        <p style="margin-top: 30px;">If you did not request this reset, please contact the administrator immediately.</p>
      </div>
      <div class="footer">
        Best regards,<br>
        <strong>NHRC SOP Portal Team</strong><br>
        © 2025 NHRC SOP Portal
      </div>
    </div>
    </body>
    </html>
    """

# 💼 Welcome Email
def build_welcome_email(user, temporary_password, subject=" 💼 Welcome to NHRC SOP Portal"):
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
          padding: 0;
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .header {{
          text-align: center;
          padding: 20px;
          border-bottom: 1px solid #dddddd;
        }}
        .header img {{
          width: 80px;
          margin-bottom: 10px;
        }}
        .title {{
          color: #0044cc;
          margin: 0;
        }}
        .content {{
          padding: 30px;
          color: #333;
          font-size: 16px;
          text-align: left;
        }}
        .info-box {{
          background-color: #f0f0f0;
          padding: 15px;
          margin: 15px 0;
          border-radius: 6px;
          font-size: 16px;
          font-weight: bold;
          text-align: center;
          color: #333;
        }}
        .button {{
          display: inline-block;
          margin-top: 20px;
          padding: 10px 20px;
          background-color: #0044cc;
          color: #fff;
          text-decoration: none;
          border-radius: 5px;
          font-size: 16px;
        }}
        .footer {{
          text-align: center;
          font-size: 12px;
          color: #888;
          padding: 15px;
          border-top: 1px solid #dddddd;
        }}
        .footer img {{
          max-width: 100px;
          height: auto;
          margin-top: 10px;
        }}
      </style>
    </head>
    <body>
    <div class="container">
      <div class="header">
        <img src="https://i.imgur.com/hpElnau.png" alt="NHRC SOP Portal Logo">
        <h2 class="title">{subject}</h2>
      </div>
      <div class="content">
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>Your NHRC-eSOP System account has been created successfully. Here are your login details:</p>
        <div class="info-box">
          Username: {user.username}
        </div>
        <div class="info-box">
          Temporary Password: {temporary_password}
        </div>
        <p>Please login and change your password immediately.</p>
        <a href="http://127.0.0.1:5000/login" class="button">Login Now</a>
        <p style="margin-top: 30px;">If you have any issues, please contact NHRC-IT.</p>
      </div>
      <div class="footer"><br>
        Welcome aboard!<br><strong>NHRC SOP Portal Team</strong>
        © 2025 NHRC SOP Portal
      </div>
    </div>
    </body>
    </html>
    """

# 📄 SOP Assignment Email
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
      <h2>{subject}</h2>
      <p>Dear <strong>{user.username}</strong>,</p>
      <p>You have been assigned a new SOP: <strong>{sop_title}</strong>.</p>
      <p>Please review and acknowledge it.</p>
      <a href="http://127.0.0.1:5000/login" style="background:#0044cc;color:white;padding:10px 20px;border-radius:5px;text-decoration:none;">View SOP</a>
      <div class="footer"><br>
        Best regards,<br><strong>NHRC SOP Portal Team</strong>
        © 2025 NHRC SOP Portal
      </div>
    </div>
    </body>
    </html>
    """

# ⏰ SOP Due Reminder Email
def build_due_reminder_email(user, sop_title, subject="⏰ SOP Due Reminder"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>{subject}</title></head>
    <body style="font-family: Arial, sans-serif;">
      <div style="max-width: 600px; margin: auto; padding: 20px; background: #fff;">
        <h2 style="color: #ff6600;">{subject}</h2>
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>This is a reminder that your SOP <strong>{sop_title}</strong> is due.</p>
        <a href="http://127.0.0.1:5000/login" style="background:#ff6600;color:#fff;padding:10px 20px;text-decoration:none;border-radius:5px;">View SOP</a><br>
        <p style="color: #888; font-size: 12px; margin-top: 20px;">NHRC SOP Portal Team</p>
        © 2025 NHRC SOP Portal
      </div>
    </body>
    </html>
    """

# 🛠 Amendment Closed Notification
def build_amendment_closed_email(user, sop_title, amendment_details, subject="🛠 Amendment Closed Notification"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>{subject}</title></head>
    <body style="font-family: Arial, sans-serif;">
      <div style="max-width: 600px; margin: auto; padding: 20px; background: #fff;">
        <h2 style="color: #28a745;">{subject}</h2>
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>The amendment for <strong>{sop_title}</strong> has been closed.</p>
        <p><strong>Details:</strong> {amendment_details}</p>
        <a href="http://127.0.0.1:5000/login" style="background:#28a745;color:#fff;padding:10px 20px;text-decoration:none;border-radius:5px;">View SOP</a><br>
        <p style="color: #888; font-size: 12px; margin-top: 20px;">NHRC SOP Portal Team</p>
        © 2025 NHRC SOP Portal
      </div>
    </body>
    </html>
    """

# 📩 Amendment Submitted Notification Email


# 📩 Amendment Submitted Notification Email
def build_amendment_submitted_email(user, sop_title, amendment, subject="📩 Amendment Submitted Notification"):
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><title>{subject}</title></head>
    <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
      <div style="max-width: 600px; margin: auto; background: #fff; padding: 20px; border-radius: 8px;">
        <h2 style="color: #0044cc;">{subject}</h2>
        <p>Dear <strong>{user.username}</strong>,</p>
        <p>A new amendment has been submitted for the SOP: <strong>{sop_title}</strong>.</p>
        <p><strong>Submitted by:</strong> {amendment.raised_by}</p>
        <p><strong>Section:</strong> {amendment.sop_section}</p>
        <p><strong>Details:</strong> {amendment.details}</p>
        <p><strong>Suggestion:</strong> {amendment.suggestion}</p>
        <p><strong>Status:</strong> {amendment.status.capitalize()}</p>
        <a href="http://127.0.0.1:5000/login" style="display:inline-block;background:#0044cc;color:#fff;padding:10px 20px;border-radius:5px;text-decoration:none;margin-top:15px;">View Amendment</a>
        <p style="color: #888; font-size: 12px; margin-top: 20px;">NHRC SOP Portal Team<br>© 2025 NHRC SOP Portal</p>
      </div>
    </body>
    </html>
    """

# 📩 Support Ticket Submitted Email (to user)
def build_support_ticket_user_email(name, subject, message, ticket_id):
    return f"""
    <html>
    <body>
      <h2>🆘 Support Ticket Submitted</h2>
      <p>Dear {name},</p>
      <p>Thank you for contacting NHRC SOP Support. We have received your ticket with the following details:</p>
      <ul>
        <li><strong>🆔 Ticket ID:</strong> {ticket_id}</li>
        <li><strong>Subject:</strong> {subject}</li>
        <li><strong>Message:</strong> {message}</li>
      </ul>
      <p>Our support team will get back to you shortly.</p>
      <p>Best regards,<br>NHRC SOP Support Team</p>
    </body>
    </html>
    """

# 📩 Support Ticket Notification Email (to admin)
def build_support_ticket_admin_email(name, email, subject, message, ticket_id):
    return f"""
    <html>
    <body>
      <h2>📢 New Support Ticket Submitted</h2>
      <p>A new support ticket has been submitted:</p>
      <ul>
        <li><strong>🆔 Ticket ID:</strong> {ticket_id}</li>
        <li><strong>Name:</strong> {name}</li>
        <li><strong>Email:</strong> {email}</li>
        <li><strong>Subject:</strong> {subject}</li>
        <li><strong>Message:</strong> {message}</li>
      </ul>
      <p>Please log in to the admin dashboard to respond.</p>
      <p>Best regards,<br>NHRC SOP Support Team</p>
    </body>
    </html>
    """
