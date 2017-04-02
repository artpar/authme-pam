Intro
=====

This PAM modules enabled you to use AuthMe to login your servers and protect them from password breaches.

To build, either use the build scripts or use these commands:

**Requirements**

curl-dev
`apt-get install libcurl4-openssl-dev`


**Build the PAM module**

`gcc -fPIC -lcurl -fno-stack-protector -c src/authme_pam.c`

`sudo ld -lcurl -x --shared -o /lib/security/authme_pam.so authme_pam.o`

The first command builds the object file in the current directory and the second links it with PAM. Since it's a shared library, PAM can use it on the fly without having to restart.

**Build Test**

`g++ -o pam_test src/authme_pam_test.c -lpam -lpam_misc`

OR

`gcc -o pam_test src/authme_pam_test.c -lpam -lpam_misc`

The test program is valid C, so it could be compiled using gcc or g++.

Simple Usage
------------

PAM module for Linux x64 (tested with ubuntu 14.04/16.04/16.10)

Couple of notes
---------------

### Domain
The users on the system will me mapped to the domain. So if my linux account username is "```user1```" and authme pam is configured with ```domain``` "```gmail.com```", then swipe will go to ```user1@gmail.com```

### Root User
AuthMe will not proceed for root users. Have explicitly disabled it for username: root

### ApiKey/ApiSecret
It is recommended to use new set of api keys for each installation.
You can generate any number of keys from (Authme)[https://account.authme.authme.host]

### No Swipe/Failure
The flow will go to other auth(password) mechanism if swipe failed. 


## Steps to Install

1. Copy authme_pam.so to /lib/security/authme_pam.so (create /lib/security if it doesn't already exists)

```scp /lib/security/authme_pam.so root@<YOUR_MACHINE_IP>:/lib/security/authme_pam.so```

2. Enable AuthMe in PAM

```nano /etc/pam.d/common-auth```

Add this line
```
auth sufficient authme_pam.so apikey=<API-KEY> apisecret=<API-SECRET> baseurl=https://api.authme.authme.host domain=gmail.com
```
3. Enable Challenge Response Authentication for SSH

nano /etc/ssh/sshd_config

Change line

```ChallengeResponseAuthentication no```

to 

```ChallengeResponseAuthentication yes```


4. Restart sshd

```service ssh restart ```



Resources
=========

I found these resources especially helpful:

O'Reilly Guides:
----------------

These guides give brief overviews about PAM and how to write modules.  This is useful if you already have a little knowledge.

* [Writing PAM Modules, Part One](http://linuxdevcenter.com/pub/a/linux/2002/05/02/pam_modules.html)
* [Writing PAM Modules, Part Two](http://linuxdevcenter.com/pub/a/linux/2002/05/23/pam_modules.html)
* [Writing PAM Modules, Part Three](http://linuxdevcenter.com/pub/a/linux/2002/05/30/pam_modules.html)

Others
------

Good example for simple authentication.  I adapted this one in my simple PAM module.

[2-factor authentication & writing PAM modules](http://ben.akrin.com/?p=1068)

Gives an example program that uses PAM. I adapted this for testing my PAM module.

[Example PAM application](http://www.kernel.org/pub/linux/libs/pam/Linux-PAM-html/adg-example.html)
