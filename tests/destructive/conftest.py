import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
