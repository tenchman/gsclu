<link href="github.css" type="text/css" rel="stylesheet"></link>

# Gernots Small Command Line Utils

Nothing really special here. There are billions of better implementations. Except *sievectl* maybe.

### Home brewed software 

* gtget     :: HTTP(S) downloader
* ps        :: *p*oor man*s* ps
* mimencode :: small mime encoder
* sievectl  :: managed sieve client

### Software from others (with some modifications)

* tunectl   :: Create, delete tun devices
* wakelan   :: Wake up a host with a wake-on-lan packet
* sstrip    :: Discard all nonessential bytes from an executable

## Sievectl

    Usage: sievectl [ options ] command [ name ]

    Options:
      -s <server>   Server to operate on
      -p <port>     Port to connect to
      -a <account>  Accountname
      -u <user>     Username
      -w <pass>     passWord
      -n <name>     local fileName (get, put, check)
      -v            Display the version number.

    Commands:
      get           get script from server
      check         check script on server.
      put           submit script to the server.
      ls            list the scripts on the server
      rm            remove script from server
      set           set a script active

### Config files:

* ~/.config/sievectl/sievectl.conf
* /etc/sievectl/sievectl.conf

### Fileformat:

      server    bla.fasel.de
      port      2000
      account   someuser@somedomain.de
      password  XXXXXX
      starttls  1
      tlsverify 1

## Gtget

    Usage: gtget [ options ] URL

    Options:
      -0            use HTTP 1.0
      -5            force Content-MD5 checking
      -c <dir>      path to configuration directory - /etc/gtget
      -C <file>     SSL: client certificate file - <confdir>/clientcert.pem
      -h            this help text
      -i            SSL: insecure, allow to connect to SSL sites without certs
      -K <file>     SSL: private key file name - <confdir>/clientkey.pem
      -o <file>     write output to 'file', use '-o -' to write to stdout
      -p <@file>    use POST instead of GET and send postdata from 'file'
      -p <string>   use POST instead of GET and send postdata from 'string'
      -q            quiet operation (overwrites -v)
      -s            open output for synchronous I/O
      -S <file>     SSL: CA certificate to verify peer - <confdir>/cacerts.pem
      -t <seconds>  timeout for connect/read/write attempts
      -v            verbose output

There are some really special features in there, things which nobody needs. More on this later...
