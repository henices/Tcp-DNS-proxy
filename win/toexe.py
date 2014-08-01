from distutils.core import setup
import py2exe
import sys
sys.path.append('..')
import third_party


setup(
    version = "1.2",
    description = "tcp dns proxy",
    name = r"tcp dns proxy",
    options = {"py2exe": {"compressed": True,
                          "optimize": 2,
                          "ascii": 0,
                          "dist_dir": ".",
                          "includes": [],
                          "bundle_files": 1,
                          "dll_excludes": ['w9xpopen.exe']
                          }},
    zipfile = None,
    # targets to build
    console = [{
                "script": r"../tcpdns.py",
                "icon_resources":[
                    #(0,"1367526275_127248.ico"),
                    #(1,"1367526275_127248.ico")
                ]
              }],
    )
