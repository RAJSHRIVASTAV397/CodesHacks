class CodesHacks:
    def __init__(self):
        self.version = "1.1.0"
        
    def print_banner(self):
        """Print the banner with version information"""
        print(BANNER.format(version=self.version, author=TOOL_INFO['author']))

    def show_help(self):
        """Display the help menu"""
        help_text = """
=================================================================
         CodesHacks v{version} - Advanced Web Security Scanner         
                  By {author}                  
=================================================================

Usage:
  codeshacks.py -d DOMAIN [-o DIR] [--mode MODE] [options]
  codeshacks.py -h | --help
  codeshacks.py --version

Arguments:
  -d, --domain=DOMAIN     Target domain or IP to scan
  -o, --output=DIR       Output directory [default: ./output]
  --mode=MODE            Scan mode: passive,active,vuln,full [default: full]

Options:
  -h, --help            Show this help
  --version             Show version
  --threads=N          Number of threads [default: 10]
  --timeout=N          Request timeout [default: 10]
  --rate=N             Rate limit [default: 50]
  --scope=PAT          Scan scope pattern
  --exclude=PAT        Exclude pattern
  --verbose, -v        Verbose output
  --debug              Debug logging
  --quiet, -q          Quiet mode
"""
        print(help_text.format(
            version=self.version,
            author=TOOL_INFO['author']
        ))

    def parse_arguments(self):
        """Parse command line arguments"""
        try:
            args = docopt(self.show_help.__doc__, version=self.version)
            return args
        except DocoptExit:
            self.show_help()
            sys.exit(1)
