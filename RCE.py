import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import logging

class CommandExecutor:
    def __init__(self):
        """
        Initializes the CommandExecutor with a list of allowed commands for security.
        """
        self.allowed_commands = ['ls', 'pwd', 'whoami', 'date']

    def execute_command(self, command):
        """
        Execute the command if it's allowed, otherwise return an error message.
        """
        if command in self.allowed_commands:
            try:
                logging.info(f"Executing command: {command}")
                output = os.popen(command).read()
                return output
            except Exception as e:
                logging.error(f"Error executing command: {str(e)}")
                return f"Error executing command: {str(e)}"
        else:
            logging.warning(f"Attempted to execute disallowed command: {command}")
            return "Error: Command not allowed."

class VulnerableServer(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        """
        Initializes the VulnerableServer with an instance of CommandExecutor.
        """
        self.executor = CommandExecutor()
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """
        Handle GET requests, parse the command from the URL, and execute it if allowed.
        """
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)

        if 'cmd' in query:
            command = query['cmd'][0]
            output = self.executor.execute_command(command)
            self._respond(200, f"<html><body><h1>Command Output:</h1><pre>{output}</pre></body></html>")
        else:
            self._respond(400, "<html><body><h1>Error: Missing 'cmd' parameter in URL</h1></body></html>")

    def _respond(self, status_code, content):
        """
        Helper function to send HTTP responses.
        """
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(bytes(content, "utf8"))

def run_vulnerable_server(server_address=('0.0.0.0', 8080)):
    """
    Start the HTTP server to serve the vulnerable service.
    """
    logging.info(f"Starting vulnerable server on {server_address[0]}:{server_address[1]}...")
    httpd = HTTPServer(server_address, VulnerableServer)
    httpd.serve_forever()

if __name__ == "__main__":
    # Set up logging to file and console
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[logging.FileHandler("server.log"),
                                  logging.StreamHandler()])

    # Start the vulnerable server
    run_vulnerable_server()

    # How to execute this code:
    # 1. Save this script as 'vulnerable_server_oop.py'.
    # 2. Run the script in a controlled environment (e.g., virtual machine) using the command:
    #    python vulnerable_server_oop.py
    # 3. Open a web browser or use 'curl' to visit the following URL:
    #    http://localhost:8080/?cmd=ls
    #    This will execute the 'ls' command on the server and return the output.
    # 4. You can replace 'ls' with any other allowed command (e.g., 'pwd', 'whoami', 'date').
    # 5. Check the 'server.log' file for a record of all executed commands and any warnings/errors.
