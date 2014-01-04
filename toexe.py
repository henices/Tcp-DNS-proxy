from distutils.core import setup
import py2exe
setup(
    version = "",
    description = "tcp dns proxy",
    name = r"tcp dns proxy",
    options = {"py2exe": {"compressed": True,
                          "optimize": 2,
                          "ascii": 0,
                          "includes": [],
                          "bundle_files": 1
                          }},
    zipfile = None,
    # targets to build
    console = [{
                "script": r"tcpdns.py",
                "icon_resources":[
                    #(0,"1367526275_127248.ico"),
                    #(1,"1367526275_127248.ico")
                ]
            }],
    )