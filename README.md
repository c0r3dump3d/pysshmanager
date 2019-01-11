
  
What's pySSHManager?
====================

pySSHManager it's a simple Python3 script to manage SSH connection that it's base in two very interesting tools for Unix/Linux sysadmin, <a href="https://github.com/prompt-toolkit/python-prompt-toolkit">python-prompt-toolkit</a>
and <a href="https://github.com/greymd/tmux-xpanes">xpanes</a>. It works scanning a single host or entire network to detect open ssh service and then manage the hosts and make ssh connections with several systems.
    
Installation:
=============

Previosly we need some python dependences:

```

  $ sudo pip install prompt_toolkit
  $ sudo pip install beautifultable
  $ sudo pip install configparser
  $ sudo pip install IPy
  
```
Now <a href="https://github.com/greymd/tmux-xpanes/wiki/Installation">install xpanes</a>.

Then:

```
  $ git clone https://github.com/c0r3dump3d/pysshmanager.git
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
If you have not previously used tmux a good configuration tmux file (.tmux.conf) is:

```
setw -g mouse on
bind -n WheelUpPane if-shell -F -t = "#{mouse_any_flag}" "send-keys -M" "if -Ft= '#{pane_in_mode}' 'send-keys -M' 'select-pane -t=; copy-mode -e; send-keys -M'"
bind -n WheelDownPane select-pane -t= \; send-keys -M
bind -n C-WheelUpPane select-pane -t= \; copy-mode -e \; send-keys -M
bind -T copy-mode-vi    C-WheelUpPane   send-keys -X halfpage-up
bind -T copy-mode-vi    C-WheelDownPane send-keys -X halfpage-down
bind -T copy-mode-emacs C-WheelUpPane   send-keys -X halfpage-up
bind -T copy-mode-emacs C-WheelDownPane send-keys -X halfpage-down

# To copy, left click and drag to highlight text in yellow, 
# once you release left click yellow text will disappear and will automatically be available in clibboard
# # Use vim keybindings in copy mode
setw -g mode-keys vi
# Update default binding of `Enter` to also use copy-pipe
unbind -T copy-mode-vi Enter
bind-key -T copy-mode-vi Enter send-keys -X copy-pipe-and-cancel "xclip -selection c"
bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "xclip -in -selection clipboard"
bind -T copy-mode-vi DoubleClick1Pane select-pane\; send -X select-word\; send -X stop-selection
```
A good <a href='https://danielmiessler.com/study/tmux/'>tmux tutorial</a>.

Usage:
======

Simply you can run the script:

```
   $ cd pysshmanager
   $ ./pySSHManager.py 
```

Now you can interact with the prompt, for example:
* Scan for a single host or network (CIDR) and assing to a group of hosts:
```
    pysshmgr> scan 192.168.1.16
    pysshmgr> scan 192.168.1.0/24 Home_network
    
 ```

 * You can list the host(s) detected:
 ```
    pysshmgr> list 
    
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

 * You can change several options during the execution of the script:

 ```
   pysshmgr> set port 2222 
   pysshmgr> set user admin 
   pysshmgr> set terminal termite 
   pysshmgr> set group Hosting-computers 

 ```

 * And show the values of the options:

 ```
   pysshmgr> show 
   ++++++++++++++++++++++++++++
   +       Otions values      +
   ++++++++++++++++++++++++++++

   [+] TCP Port: 22
   [+] User: root
   [+] Default group: default
   [+] Hosts file: hostfile.csv
   [+] Terminal: mate-terminal
   ++++++++++++++++++++++++++++
 ```


 * In order to save the change in the list of host(s) you run `save` command or `exit`:  

 ```
   pysshmgr> save 
   pysshmgr> exit 
 ```

 * You can reset the list of host(s) with `reset` command:  

 ```
   pysshmgr> reset 
 ```
 
 
 
