EnigmaBridge VPN Authenticator
==============================

`EnigmaBridge <https://enigmabridge.com>`__ python authentication server enables VPN authentication of users connected to the VPN.


Mac OSX installation
--------------------

For new OSX versions (El Capitan and above) the default system python
installation cannot be modified with standard means. There are some
workarounds, but one can also use ``--user`` switch for pip.

::

    pip install --user cryptography

PIP update appdirs error
------------------------

Pip may have a problem with updating appdirs due to missing directory. It helps to update this package manually

::

    pip install --upgrade --no-cache appdirs


Database setup
--------------

State is stored in MySQL database.


.. code:: sql

    CREATE DATABASE vpnauth CHARACTER SET utf8 COLLATE utf8_general_ci;
    GRANT ALL PRIVILEGES ON vpnauth.* TO 'vpnauth'@'localhost' IDENTIFIED BY 'vpnauth_passwd';
    FLUSH PRIVILEGES;

