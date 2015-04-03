import os
import sys


try:
    __file__
except NameError:
    __file__ = sys.argv[0]

third_party_dir = os.path.dirname(os.path.abspath(__file__))
pylru_dir = os.path.join(third_party_dir, "pylru")
daemon_dir = os.path.join(third_party_dir, "python-daemon")
sys.path.append(pylru_dir)  # workaround for no __init__.py
sys.path.append(daemon_dir)
sys.path.append(third_party_dir)
