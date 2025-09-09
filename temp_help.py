def print_banner(self):
    """Print the banner with version information"""
    print(BANNER.format(version=self.version, author=TOOL_INFO['author']))

def parse_arguments(self):
    """Parse command line arguments with comprehensive help"""
    help_text = f"""
