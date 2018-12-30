
  
What's pySSHManager?
====================

pySSHManager it's a simple Python3 script to manage SSH connection that it's base in two very interesting tools <a href="https://github.com/prompt-toolkit/python-prompt-toolkit">python-prompt-toolkit</a>
and <a href="https://github.com/greymd/tmux-xpanes">xpanes</a>. With pySSHManager you can manage hosts and connect with them in several forms.
    
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

Configuration:
=============

pySSHManager has configuration file where you can defined some variables:

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
