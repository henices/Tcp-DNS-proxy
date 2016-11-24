
![Build Status](https://travis-ci.org/henices/Tcp-DNS-proxy.svg?branch=master)

How to use this python script ?
-------------------------------

1.    change your dns server to 127.0.0.1

   ```bash
  $ vi /etc/resolve.conf  
  nameserver 127.0.0.1
  ```
2.    restart the network

  ```bash
  $ sudo /etc/init.d/networking restart
  ```
3.    run the script

  ```bash
  $ sudo python tcpdns.py -f tcpdns.json.example
  ```
4.   stop the daemon process

  ```bash
  $ sudo python tcpdns.py -s
  ```

  
Commandline
----------------------------

```
usage: tcpdns.py [-h] -f CONFIG_JSON [-d]

TCP DNS Proxy

optional arguments:
  -h, --help      show this help message and exit
  -f CONFIG_JSON  Json config file
  -d              Print debug message
  -s              Stop tcp dns proxy daemon
```

  
Configuration file
----------------------------

``` json
{
    "socket_timeout": 20,
    "host": "0.0.0.0",
    "port": 53,
    "tcp_dns_server": ["8.8.8.8:53",
                       "8.8.4.4:53",
                       "156.154.70.1:53",
                       "156.154.71.1:53",
                       "208.67.222.222:53",
                       "208.67.220.220:53",
                       "209.244.0.3:53"],
    "udp_dns_server": ["208.67.222.222:5353"],
    "enable_server_switch": true,
    "speed_test": true,
    "enable_lru_cache": true,
    "lru_cache_size"  : 500,
    "udp_mode"        : false,
    "daemon_process"  : false,
    "internal_dns_server": ["192.168.1.1:53"],
    "internal_domain": ["*intra*"],
    "private_host"    : {"*google.com": "203.117.34.162"}
}
```
* **enable_server_switch**: switch dns servers if network is slow
* **speed_test**          : test dns server speed on startup
* **enable_lru_cache**    : use lru cache to store dns server responses
* **udp_mode**            : use udp dns procotol, default is tcp dns protocol
* **daemon_process**      : daemon process on *nix platform
* **internal_dns_server** : internal dns server on internal network
* **internal_domain**     : internal domains which use internal dns server to get ip address
* **private_host**        : like /etc/hosts on *nix platform

  
Dependencies
----------------------------

### libraries
   * [libev] (http://libevent.org/)

### python moudules
   * [gevent] (https://github.com/surfly/gevent)
   * [pylru] (https://github.com/jlhutch/pylru)
   * [python-daemon] (https://github.com/serverdensity/python-daemon) (Windows does not need)

INSTALL
---------------------

### Super-quick installation

#### Linux system

```bash

  chmod +x ./install.sh
  ./install.sh
```

#### Windows system

Use tcpdns.exe in win directory.


### Manual Installation


#### Ubuntu or Debian installation guide

1. Use the following commands to install python modules

   ```bash
   
     sudo apt-get install libevent-dev
     sudo apt-get install python-pip
     sudo pip install gevent
     sudo pip install python-daemon
   ```

2. Pull the submodule source code.

   ```bash
     cd Tcp-DNS-proxy
     git submodule update --init --recursive
   ```

#### Windows installation guide

   In order to build gevent library you should install Visual Studio, 
   although tcpdns.py can run perfectly without python gevent.
   If you cannot run "C:\Python27\Scripts\pip.exe" in the CMD,
   you can try "C:\Python27\python.exe -m pip".


1. Pull the submodule source code.
   ```bash
     cd Tcp-DNS-proxy
     git submodule update --init --recursive
   ```

2. install python 2.7.9


3. Install pip.exe

   Download get-pip.py from [get-pip.py](https://raw.github.com/pypa/pip/master/contrib/get-pip.py),
   execute the following commands:

   ```
   python get-pip.py
   ```
4. install greenlet

   ```
   C:\Python27\Scripts\pip.exe install greenlet
   ```

5. install Microsoft Visual C++ Compiler for Python 2.7

  [Download link](http://www.microsoft.com/en-us/download/details.aspx?id=44266)

6. Install python gevent

   ```
   C:\Python27\Scripts\pip.exe install gevent
   ```

7. install pyinstaller

   ```
   C:\Python27\Scripts\pip.exe install pyinstaller
   ```
   
8. execute toexe.bat


LICENSE
----------------------

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License 
as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see 
http://www.gnu.org/licenses/
