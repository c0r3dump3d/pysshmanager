
  
What's pySSHManager?
====================

pySSHManager it's a simple Python3 script to manage SSH connection that it's base in two very interesting tools <a href="https://github.com/prompt-toolkit/python-prompt-toolkit">python-prompt-toolkit</a>
and <a href="https://github.com/greymd/tmux-xpanes">xpanes</a>. It works scanning a single host or entire network to detect open ssh service and then manage the host in order to make connections in several forms.
    
Installation:
=============

Previosly we need some python dependences:

```

  pip install prompt_toolkit
  pip install beautifultable
  pip install configparser
  pip install IPy
  
```
And <a href="https://github.com/greymd/tmux-xpanes/wiki/Installation">install xpanes</a>.

Then:

```
  git clone https://github.com/c0r3dump3d/pysshmanager.git
```

Configuration:
=============

pySSHManager has configuration file (`pySSHManager.conf`) where you can defined some variables:

```
  #Default TCP port for SSH service
  port=22 

  #Terminal to use, supported are gnome-terminal, terminator, mate-terminal, xterm, termite and konsole terminals. 
  terminal=mate-terminal 

  #Default user to connect SSH
  user=root

  #Default group of hosts

  group=default

  #The path of CSV file to save the host(s) information
  hostfile=hostfile.csv
```
Usage:
======

Simply you can run the script:

```
   cd pysshmanager
   ./pysshmangerpysshmgr>
```

Now you can interact with the prompt, for example:
* Scan for a single host or network (CIDR) and assing to a group of hosts:
```
    pysshmgr> scan 192.168.1.16
    pysshmgr> scan 192.168.1.0/24 Home_network
    
 ```

 * You can list the host(s) detected:
 ```
    pysshmgr> list hots
    
+----+----------------+------+-----------------------------------------------------+---------------+
| ID |       IP       | PORT |                        FQDN                         |     GROUP     |
+----+----------------+------+-----------------------------------------------------+---------------+
| 1  |  10.100.208.1  |  22  |        compterhome1.domain                          | Home_network  |
+----+----------------+------+-----------------------------------------------------+---------------+
| 2  |  10.100.208.2  |  22  |        computerhome2.domain                         | Home_network  |
+----+----------------+------+-----------------------------------------------------+---------------+
| 3  |  10.100.208.3  |  22  |        computerhome3.domain                         | Home_network  |
+----+----------------+------+-----------------------------------------------------+---------------+

 ```
 
 * Now you can manage the connection with the host(s), by single ID, ID range, several ID or searching for a string:

```
   pysshmgr> connect 1
   pysshmgr> connect 1/3
   pysshmgr> connect 1,3
   pysshmgr> connect computerhome

```
 * Thank's to xpane you can open several ssh terminals with synchronization:
 
 ```
   pysshmgr> connect comuterhome sync
 ```
 
 * You can delete the host(s) form list by single ID, ID range, several ID or searching for a string:
 
 ```
   pysshmgr> delete 1
   pysshmgr> delete 1/3
   pysshmgr> delete 1,3
   pysshmgr> delete comuterhome
```

* In order to save the change in the list of host(s) you run `save` command or `exit`.  
 
 
 
