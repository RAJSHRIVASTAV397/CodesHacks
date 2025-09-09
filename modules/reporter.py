import logging
import os
from datetime import datetime

class Reporter:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
    
    def generate_report(self, target, scan_dir, results, output_file):
        """Generate a comprehensive security assessment report"""
        self.logger.info("Generating comprehensive report...")
        
        with open(output_file, 'w') as f:
            f.write("CodesHacks Security Assessment Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Results Directory: {scan_dir}\n\n")
            
            # Include each section's results
            for section, result_file in results:
                f.write(f"\n{section} Results\n")
                f.write("-" * (len(section) + 8) + "\n")
                if os.path.exists(result_file):
                    with open(result_file) as rf:
                        f.write(rf.read())
                f.write("\n" + "=" * 50 + "\n")
        
        self.logger.info(f"Report generated: {output_file}")
        return output_file
