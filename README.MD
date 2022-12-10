This is a Ruby implementation of PyP100, but severely limited to my usecase of querying a TP-Link Tapo P110 energy monitor.

Encryption and handshake/login works properly, so it can be easily extended based on the PyP100 code.

Based on https://github.com/fishbigger/TapoP100

Tested with Ruby 2.6 and 2.7

How to use:
```
plug = P100.new("10.0.0.100","email@email.org", "password")
plug.handshake()
plug.login()
plug.get_energy_usage()
```
