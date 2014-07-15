
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
  $ sudo python tcpdns.py -f tcpdns.json
  ```
  
Dependencies
----------------------------

### libraries
   * [libev] (http://libevent.org/)

### python moudules
   * [gevent] (https://github.com/surfly/gevent)
   * [pylru] (https://github.com/jlhutch/pylru)
   * [python-daemon] (https://pypi.python.org/pypi/python-daemon)

INSTALL
---------------------

``` bash
  sudo apt-get install libevent-dev
  sudo pip install gevent
  sudo pip install python-daemon
```


![Build Status](https://travis-ci.org/henices/Tcp-DNS-proxy.svg?branch=master)


LICENSE
----------------------

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License 
as published by the Free Software Foundation, either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see 
http://www.gnu.org/licenses/
