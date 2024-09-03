
Features
-------------------------------
- DNS query forwarding, supports TCP DNS protocol and UDP DNS protocol
- DNS server speed test, choose the fastest servers
- DNS query local acceleration, use lru cache
- DNS server automatic switching, when multiple query errors, automatically try to switch
- Private Host, equivalent to modifying the hosts file
- Support intranet DNS server, resolve internal domain names

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

Commandline
----------------------------

```
usage: tcpdns.py [-h] -f CONFIG_JSON [-d]

TCP DNS Proxy

optional arguments:
  -h, --help      show this help message and exit
  -f CONFIG_JSON  Json config file
  -d              Print debug message
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
   * [python-daemon] (https://pagure.io/python-daemon/) (Windows does not need)

INSTALL
---------------------


### Linux system

```bash

python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
sudo .venv/bin/python3 tcpdns.py -f tcpdns.json.example -d
```

### Windows system

Use tcpdns.exe in win directory. (I haven't tested it on Windows 10 or 11.)

LICENSE
----------------------

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License 
as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see 
http://www.gnu.org/licenses/
