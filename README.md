How to use this python script ?
===============================


1. change your dns server to 127.0.0.1
  $ vi /etc/resolve.conf  
nameserver 127.0.0.1

2. restart the network
  $ sudo /etc/init.d/networking restart

3. run the script
  $ sudo python tcpdns.py

## Dependencies

### libraries
* [libev] (http://libevent.org/)

### python moudules

* [gevent] (https://github.com/surfly/gevent)
* [dnspython] (http://www.dnspython.org/)

## INSTALL

```
  sudo apt-get install libevent-dev
  sudo pip install gevent
  sudo pip install dnspython
```
