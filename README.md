# Get HTTPS for free!

**WARNING: THE LET'S ENCRYPT CERTIFICATE AUTHORITY IS ONLY IN BETA! YOU MUST
HAVE A WHITELISTED DOMAIN DURING BETA. GENERAL AVAILABILITY WILL BE SOON!**

Website: https://diafygi.github.io/gethttpsforfree/

This is a project that allows you to get a free HTTPS certificate without
having to install any software or having to share your private keys with anyone.
It uses the non-profit [Let's Encrypt](https://letsencrypt.org/) certificate
authority to issue the free certificates. Hooray for free certs!

##Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

##How to use this website

Go to: https://diafygi.github.io/gethttpsforfree/

The website works by generating commands for you to run in your terminal, then
making requests to the Let's Encrypt ACME API to issue your certificate. Simply
visit the above website and follow the steps! If you don't know how to do
something, try clicking the help links that explain how to complete the step. If
you're still confused, please create an issue and I'll address your issue ASAP!

Requirements for your local machine:
* openssl
* echo
* base64

Requirements for your server:
* python

These should all be installed by default in Linux and Mac OSX. If you're
running Windows, you might need to install [Cygwin](https://cygwin.com/install.html)
to get openssl, echo, and base64 working on Windows.

##Privacy

This website is entirely static files and only makes ajax requests to the
Let's Encrypt API. It does not track or remember anything when you leave.
It is written with minimal extra libraries and styling to ensure that you
can read through and audit the source code.

##Feedback/Contributing

I'd love to receive feedback, issues, and pull requests to make this script
better. The main script itself, `js/index.js`, is less than 800 lines of code, so
feel free to read through it! I tried to comment things well and make it crystal
clear what it's doing.

TODO (pull requests welcome):
* `renew.html` - A page with steps for renewing certificates
* `revoke.html` - A page with steps for revoking certificates
* Alternative file-based command instead of python server
* Installation instructions for Apache
* Accept GPG public keys as account public keys

##What's NOT on the Roadmap

* Third party libraries (asn1.js is the only one)
* Fonts or images
* CSS more than 5 kilobytes
* Javascript that only changes UI
* HTML that decreases source readability (added wrapping divs, etc.)

This website is supposed to [work](http://motherfuckingwebsite.com/), nothing more.

