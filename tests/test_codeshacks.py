import unittest
import os
import tempfile
import configparser
import logging
from unittest.mock import MagicMock, patch
from codeshacks import CodesHacks

class TestCodesHacks(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        # Redirect output directory to temp
        os.environ['CODESHACKS_OUTPUT_DIR'] = self.temp_dir
        self.ch = CodesHacks()

    def tearDown(self):
        """Clean up test environment"""
        # Clean up temporary directory
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)
        # Remove environment variable
        if 'CODESHACKS_OUTPUT_DIR' in os.environ:
            del os.environ['CODESHACKS_OUTPUT_DIR']

    def test_initialization(self):
        """Test CodesHacks initialization"""
        self.assertIsNotNone(self.ch.version)
        self.assertIsNotNone(self.ch.output_dir)
        self.assertIsNotNone(self.ch.timestamp)
        self.assertIsInstance(self.ch.logger, logging.Logger)

    def test_help_menu(self):
        """Test help menu display"""
        import io
        import sys
        captured_output = io.StringIO()
        sys.stdout = captured_output
        self.ch.help_menu()
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()

        # Check for essential help menu components
        self.assertIn('Advanced Reconnaissance Framework', output)
        self.assertIn('USAGE:', output)
        self.assertIn('QUICK COMMANDS:', output)
        self.assertIn('COMMON FLAGS:', output)

    def test_banner(self):
        """Test banner display"""
        banner = self.ch.get_banner()
        self.assertIn('Advanced Reconnaissance Framework', banner)
        self.assertIn('Author: Raj Shrivastav', banner)
        self.assertIn(f'Version: {self.ch.version}', banner)

    def test_output_dir_creation(self):
        """Test output directory creation"""
        session_dir = self.ch.create_output_dir()
        self.assertTrue(os.path.exists(session_dir))
        self.assertTrue(os.path.isdir(session_dir))

    def test_load_config_with_file(self):
        """Test configuration loading with config file"""
        # Create a test config file
        config_path = os.path.join(self.temp_dir, 'test_config.ini')
        with open(config_path, 'w') as f:
            f.write('''[SETTINGS]
output_dir = test_output
threads = 15
timeout = 20
rate_limit = 30
debug = true

[SCAN_OPTIONS]
top_ports = 200
screenshot_timeout = 15
crawl_depth = 5
passive_only = true
''')

        # Set config file and reload
        self.ch.config_file = config_path
        self.ch.load_config()

        # Check if settings were loaded correctly
        self.assertEqual(self.ch.threads, 15)
        self.assertEqual(self.ch.timeout, 20)
        self.assertEqual(self.ch.rate_limit, 30)
        self.assertTrue(self.ch.debug)
        self.assertEqual(self.ch.top_ports, 200)
        self.assertEqual(self.ch.screenshot_timeout, 15)
        self.assertEqual(self.ch.crawl_depth, 5)
        self.assertTrue(self.ch.passive_only)

    def test_load_config_without_file(self):
        """Test configuration loading without config file"""
        # Set non-existent config file
        self.ch.config_file = 'nonexistent.ini'
        self.ch.load_config()

        # Check if default values were set
        self.assertEqual(self.ch.threads, 10)
        self.assertEqual(self.ch.timeout, 10)
        self.assertEqual(self.ch.rate_limit, 50)
        self.assertFalse(self.ch.debug)
        self.assertEqual(self.ch.top_ports, 100)
        self.assertEqual(self.ch.screenshot_timeout, 10)
        self.assertEqual(self.ch.crawl_depth, 3)
        self.assertFalse(self.ch.passive_only)

    @patch('selenium.webdriver.Chrome')
    def test_setup_browser(self, mock_chrome):
        """Test browser setup for screenshots"""
        # Mock Chrome driver
        mock_driver = MagicMock()
        mock_chrome.return_value = mock_driver

        chrome_options = self.ch.setup_browser()
        self.assertIsNotNone(chrome_options)

    def test_load_api_keys_from_env(self):
        """Test API key loading from environment variables"""
        # Set test API keys in environment
        os.environ['SHODAN_API_KEY'] = 'test_shodan_key'
        os.environ['CENSYS_API_KEY'] = 'test_censys_key'

        self.ch.load_api_keys()
        
        # Check if keys were loaded
        self.assertEqual(self.ch.api_keys.get('shodan'), 'test_shodan_key')
        self.assertEqual(self.ch.api_keys.get('censys'), 'test_censys_key')

        # Clean up environment
        del os.environ['SHODAN_API_KEY']
        del os.environ['CENSYS_API_KEY']

    def test_parse_arguments(self):
        """Test argument parsing"""
        # Test with minimal required arguments
        test_args = ['codeshacks.py', '-d', 'example.com']
        with patch('sys.argv', test_args):
            args = self.ch.parse_arguments()
            self.assertEqual(args.domain, 'example.com')

        # Test with full options
        test_args = [
            'codeshacks.py',
            '-d', 'example.com',
            '--passive',
            '--threads', '20',
            '--timeout', '30',
            '--output', 'test_output',
            '--debug'
        ]
        with patch('sys.argv', test_args):
            args = self.ch.parse_arguments()
            self.assertEqual(args.domain, 'example.com')
            self.assertTrue(args.passive)
            self.assertEqual(args.threads, 20)
            self.assertEqual(args.timeout, 30)
            self.assertEqual(args.output, 'test_output')
            self.assertTrue(args.debug)

if __name__ == "__main__":
    unittest.main()
