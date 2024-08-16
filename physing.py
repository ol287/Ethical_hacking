import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http.server import SimpleHTTPRequestHandler, HTTPServer

class PhishingEmail:
    def __init__(self, sender_email, sender_password, smtp_server, smtp_port):
        """
        Initialize the PhishingEmail class with the sender's email credentials and SMTP server details.
        """
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    def mask_sender_email(self, masked_name, masked_email):
        """
        Returns a formatted string to mask the original sender's email address.
        """
        return f"{masked_name} <{masked_email}>"

    def send_email(self, target_email, subject, body, phishing_link, masked_name, masked_email):
        """
        Sends a phishing email to the target with a masked sender email.
        """
        try:
            # Create the email
            msg = MIMEMultipart()
            msg['From'] = self.mask_sender_email(masked_name, masked_email)
            msg['To'] = target_email
            msg['Subject'] = subject

            # Attach the body of the email
            body = body + f"\n\nClick here to access your account: {phishing_link}"
            msg.attach(MIMEText(body, 'plain'))

            # Log in to the server and send the email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()

            print(f"Phishing email sent to {target_email}")
        except Exception as e:
            print(f"Failed to send email: {e}")

class PhishingPageHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        """
        Serve the phishing notification page when the link is clicked.
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        message = """
        <html>
        <head>
        <title>Phished!</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            .container {
                background-color: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                text-align: center;
            }
            h1 {
                color: #e74c3c;
                font-size: 2.5em;
                margin-bottom: 20px;
            }
            p {
                color: #555;
                font-size: 1.2em;
                margin-bottom: 30px;
            }
            .btn {
                background-color: #e74c3c;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                font-size: 1.2em;
                transition: background-color 0.3s;
            }
            .btn:hover {
                background-color: #c0392b;
            }
        </style>
        </head>
        <body>
        <div class="container">
            <h1>You Have Been Phished!</h1>
            <p>This is a simulation, and you were tricked into clicking a phishing link.<br>
            Please be more careful in the future.</p>
            <a class="btn" href="https://www.yourcompany.com/security-tips">Learn More About Phishing</a>
        </div>
        </body>
        </html>
        """
        self.wfile.write(bytes(message, "utf8"))

def start_phishing_server(server_address=('0.0.0.0', 8080)):
    """
    Start the HTTP server to serve the phishing notification page.
    """
    httpd = HTTPServer(server_address, PhishingPageHandler)
    print(f"Starting phishing server on {server_address[0]}:{server_address[1]}...")
    httpd.serve_forever()

# Usage example:
if __name__ == "__main__":
    # Email configuration
    sender_email = 'youremail@example.com'
    sender_password = 'yourpassword'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    # Target email
    target_email = 'target@example.com'
    subject = 'Important: Action Required'
    body = 'Dear user, please review the attached document and take necessary action.'
    
    # Phishing link
    phishing_link = 'http://localhost:8080'

    # Masked sender details
    masked_name = 'Support Team'
    masked_email = 'support@example.com'

    # Send the phishing email with masked sender details
    phishing_email = PhishingEmail(sender_email, sender_password, smtp_server, smtp_port)
    phishing_email.send_email(target_email, subject, body, phishing_link, masked_name, masked_email)

    # Start the phishing server to handle redirection
    start_phishing_server()
