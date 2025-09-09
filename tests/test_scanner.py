import unittest
import os
import tempfile
import json
from unittest.mock import MagicMock, patch
from modules.scanner import Scanner
import logging

class TestScanner(unittest.TestCase):
    def setUp(self):
        """Set up test cases"""
        self.temp_dir = tempfile.mkdtemp()
        self.config = {
            'api_keys': {},
            'threads': 5,
            'timeout': 5,
            'rate_limit': 10,
            'output_dir': self.temp_dir
        }
        self.logger = logging.getLogger('test_scanner')
        self.scanner = Scanner(self.config, self.logger)

    def tearDown(self):
        """Clean up after tests"""
        for root, dirs, files in os.walk(self.temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(self.temp_dir)

    def test_init(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.threads, 5)
        self.assertEqual(self.scanner.timeout, 5)
        self.assertEqual(self.scanner.rate_limit, 10)
        self.assertTrue(os.path.exists(self.scanner.results_dir))
        self.assertTrue(os.path.exists(self.scanner.session_dir))

    def test_get_wordlist(self):
        """Test wordlist functionality"""
        # Test with default wordlist
        dirs = self.scanner.get_wordlist('directories')
        self.assertTrue(isinstance(dirs, list))
        self.assertTrue(len(dirs) > 0)
        self.assertIn('admin', dirs)

        # Test with custom wordlist
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('test1\\ntest2\\ntest3')
            custom_file = f.name

        try:
            custom_words = self.scanner.get_wordlist('directories', custom_file)
            self.assertEqual(custom_words, ['test1', 'test2', 'test3'])
        finally:
            os.unlink(custom_file)

    @patch('requests.get')
    def test_check_live_hosts(self, mock_get):
        """Test live host checking"""
        # Mock response for live host
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        # Create test input file
        input_file = os.path.join(self.temp_dir, 'test_hosts.txt')
        output_file = os.path.join(self.temp_dir, 'live_hosts.txt')
        
        with open(input_file, 'w') as f:
            f.write('example.com\\ntest.com')

        self.scanner.check_live_hosts(input_file, output_file)
        
        with open(output_file, 'r') as f:
            results = f.read().splitlines()
        
        self.assertEqual(len(results), 2)
        self.assertIn('http://example.com', results)
        self.assertIn('http://test.com', results)

    @patch('scanner.Scanner.run_tool')
    def test_scan_with_nikto(self, mock_run_tool):
        """Test Nikto scanning functionality"""
        mock_run_tool.return_value = "Nikto scan results"
        output_file = os.path.join(self.temp_dir, 'nikto.txt')
        result = self.scanner.scan_with_nikto('example.com', output_file)
        self.assertTrue(result)
        mock_run_tool.assert_called_once()

    @patch('scanner.Scanner.run_tool')
    def test_scan_with_sqlmap(self, mock_run_tool):
        """Test SQLMap scanning functionality"""
        mock_run_tool.return_value = "SQLMap scan results"
        output_dir = os.path.join(self.temp_dir, 'sqlmap')
        result = self.scanner.scan_with_sqlmap('example.com', output_dir)
        self.assertTrue(result)
        mock_run_tool.assert_called_once()

    def test_generate_payloads(self):
        """Test payload generation"""
        output_dir = os.path.join(self.temp_dir, 'payloads')
        self.scanner.generate_payloads(output_dir)
        
        # Check if payload files were created
        expected_files = [
            'xss_payloads.txt',
            'sqli_payloads.txt',
            'rce_payloads.txt'
        ]
        
        for file in expected_files:
            file_path = os.path.join(output_dir, file)
            self.assertTrue(os.path.exists(file_path))
            with open(file_path, 'r') as f:
                content = f.read()
                self.assertTrue(len(content.splitlines()) >= 100)

    @patch('dns.resolver.resolve')
    def test_passive_recon(self, mock_resolve):
        """Test passive reconnaissance"""
        # Mock DNS resolution
        mock_answer = MagicMock()
        mock_answer.items = ['198.51.100.1']
        mock_resolve.return_value = [mock_answer]

        output_file = self.scanner.passive_recon('example.com', self.temp_dir)
        self.assertTrue(os.path.exists(output_file))
        
        with open(output_file, 'r') as f:
            content = f.read()
            self.assertIn('example.com', content)

    @patch('requests.get')
    def test_analyze_web_server(self, mock_get):
        """Test web server analysis"""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Server': 'nginx/1.18.0',
            'X-Powered-By': 'PHP/7.4.3'
        }
        mock_response.text = '<html><head><title>Test Site</title></head><body></body></html>'
        mock_get.return_value = mock_response

        output_file = os.path.join(self.temp_dir, 'web_analysis.txt')
        self.scanner.analyze_web_server('example.com', output_file)
        
        with open(output_file, 'r') as f:
            content = f.read()
            self.assertIn('nginx', content)
            self.assertIn('PHP', content)
            self.assertIn('Test Site', content)

    def test_generate_report(self):
        """Test report generation"""
        input_file = os.path.join(self.temp_dir, 'findings.txt')
        with open(input_file, 'w') as f:
            f.write('[HIGH] SQL Injection vulnerability\\n')
            f.write('[MEDIUM] XSS vulnerability\\n')
            f.write('[LOW] Missing security header\\n')

        output_file = os.path.join(self.temp_dir, 'report.txt')
        self.scanner.generate_report(input_file, output_file)
        
        with open(output_file, 'r') as f:
            content = f.read()
            self.assertIn('HIGH', content)
            self.assertIn('MEDIUM', content)
            self.assertIn('LOW', content)
            self.assertIn('SQL Injection', content)
            self.assertIn('XSS', content)

if __name__ == '__main__':
    unittest.main()
