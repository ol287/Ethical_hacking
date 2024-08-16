import requests
from bs4 import BeautifulSoup
import re

class SecurityWebScraper:
    def __init__(self, target_url):
        """
        Initialize the SecurityWebScraper with the target URL.
        """
        self.target_url = target_url
        self.sensitive_keywords = ['password', 'admin', 'login', 'secret', 'config', 'backup']
        self.sensitive_files = ['.env', 'config.php', 'wp-config.php', '.git', 'backup']
    
    def get_page_content(self):
        """
        Fetch the content of the target URL.
        """
        try:
            response = requests.get(self.target_url)
            response.raise_for_status()  # Raise an exception for HTTP errors
            return response.text
        except requests.RequestException as e:
            print(f"Error fetching the page content: {e}")
            return None
    
    def find_sensitive_keywords(self, content):
        """
        Search for sensitive keywords in the page content.
        """
        found_keywords = []
        for keyword in self.sensitive_keywords:
            if re.search(keyword, content, re.IGNORECASE):
                found_keywords.append(keyword)
        return found_keywords
    
    def find_sensitive_files(self, content):
        """
        Search for references to sensitive files in the page content.
        """
        found_files = []
        soup = BeautifulSoup(content, 'html.parser')
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            for sensitive_file in self.sensitive_files:
                if sensitive_file in href:
                    found_files.append(href)
        return found_files
    
    def scrape(self):
        """
        Perform the web scraping to find security-related information.
        """
        content = self.get_page_content()
        if not content:
            print("Failed to retrieve content from the target URL.")
            return
        
        # Find sensitive keywords
        print("Searching for sensitive keywords...")
        keywords = self.find_sensitive_keywords(content)
        if keywords:
            print(f"Sensitive keywords found: {keywords}")
        else:
            print("No sensitive keywords found.")
        
        # Find sensitive files
        print("Searching for sensitive files...")
        files = self.find_sensitive_files(content)
        if files:
            print(f"Sensitive files found: {files}")
        else:
            print("No sensitive files found.")

# How to use the SecurityWebScraper class:

# 1. Replace 'http://example.com' with the target website you want to scrape.
target_url = 'http://example.com'

# 2. Instantiate the SecurityWebScraper class with the target URL.
scraper = SecurityWebScraper(target_url)

# 3. Run the scraper to find sensitive information.
scraper.scrape()
