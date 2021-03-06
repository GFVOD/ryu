<p align="center">
  <a href="https://github.com/GFVOD/ryu">
    <img src="http://osrg.github.io/ryu/css/images/LogoSet02.png" alt="" width=144 height=144>
  </a>

  <h3 align="center">Miles's Ryu</h3>
  <p align="center">
     This framework is just for my personal studying and record some achievements of my teamwork.
      <br>
      <a href="http://osrg.github.io/ryu/resources.html"><strong>Explore Ryu docs »</strong></a>
      <br>
      <br>

What's Ryu
==========
Ryu is a component-based software defined networking framework.

Ryu provides software components with well defined API that make it
easy for developers to create new network management and control
applications. Ryu supports various protocols for managing network
devices, such as OpenFlow, Netconf, OF-config, etc. About OpenFlow,
Ryu supports fully 1.0, 1.2, 1.3, 1.4, 1.5 and Nicira Extensions.

All of the code is freely available under the Apache 2.0 license. Ryu
is fully written in Python.


Quick Start
===========
Installing Ryu is quite easy:
   ```
   % pip install ryu
   ```
If you prefer to install Ryu from the source code:
   ```
   % git clone git://github.com/GFVOD/ryu.git
   % cd ryu; pip install .
   ```
If you want to write your Ryu application, have a look at
[Writing ryu application](http://ryu.readthedocs.io/en/latest/writing_ryu_app.html) document.
After writing your application, just type:
   ```
   % ryu-manager yourapp.py
   ```

Optional Requirements
=====================

Some functionalities of ryu requires extra packages:

- OF-Config requires lxml and ncclient
- NETCONF requires paramiko
- BGP speaker (SSH console) requires paramiko
- Zebra protocol service (database) requires SQLAlchemy

If you want to use the functionalities, please install requirements:
    
    
    % pip install -r tools/optional-requires
    
Please refer to tools/optional-requires for details.


Prerequisites
=============
If you got some error messages at installation step, please confirm
dependencies for building required Python packages.

On Ubuntu(16.04 LTS or later):
  ```
  % apt install gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
  ```

Support
=======
Ryu Official site is <http://osrg.github.io/ryu/>
If you have any
questions, suggestions, and patches, the mailing list is available at
[ryu-devel ML](https://lists.sourceforge.net/lists/listinfo/ryu-devel).
[The ML archive at Gmane](http://dir.gmane.org/gmane.network.ryu.devel)
is also available.
