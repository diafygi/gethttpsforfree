# Get HTTPS for free!

Website: https://gethttpsforfree.com

This is a project that allows you to get a free HTTPS certificate without
having to install any software or having to share your private keys with anyone.
It uses the non-profit [Let's Encrypt](https://letsencrypt.org/) certificate
authority to issue the free certificates. Hooray for free certs!

##Donate

If this script is useful to you, please donate to the EFF. I don't work there,
but they do fantastic work.

[https://eff.org/donate/](https://eff.org/donate/)

##How to use this website

Go to: https://gethttpsforfree.com

The website works by generating commands for you to run in your terminal, then
making requests to the Let's Encrypt ACME API to issue your certificate. Simply
visit the above website and follow the steps! If you don't know how to do
something, try clicking the help links that explain how to complete the step. If
you're still confused, please create an issue and I'll address your issue ASAP!

Requirements for your local machine:
* openssl
* echo

Requirements for your server:
* python or any webserver that can serve a static file

These should all be installed by default in Linux and Mac OSX. If you're
running Windows, you might need to install [Cygwin](https://cygwin.com/install.html)
to get openssl and echo working on Windows.

##How this website works

This website works by making requests to the Let's Encrypt [API](https://acme-v01.api.letsencrypt.org)
(using the [ACME](https://github.com/ietf-wg-acme/acme) protocol). There's 5 steps to the process,
which are explained below. Also, I encourage you to read the source code (it's not that long) and
pop open your browser's debugger to see the ajax requests that are going on. Please, audit this!

###Step 1: Account Info

First, the ACME protocol requires you register a public key and contact information
so you can sign all the requests you make to the API. In this step, you need to
put in an email and a public key. The javascript for this section then converts the
public key to a JSON Web Key ([JWK](https://tools.ietf.org/html/rfc7517)). NOTE:
currently only RSA 2048 and 4096 bit public keys are accepted by Let's Encrypt.

So if you paste it in this public key:
```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5aok6d72rkrGpOPAICSS
3JPrA0tbVs3mYPWmG7c5tGEY+w1slyI+3V64NsLw8p9YqNLyX/YDsnmkOUMUx6Bu
vx43daBrl//wz3hIOvidXyV4z65Nbrlto9qtLpfi+9lbEEYt2PLhr+KjguqjqOQj
qi2PgqdITGG+BZkU8xIrPzZCR/UPBotV/dGBj9vO1whTGlzpkihvXLf4rEFoJoEE
eOPMtqbxUp1KS41EgX2xFav9JHPVI1hm66K0eqlJrBl407j3xRNlekl4xorwfCkA
xC7xclofg3JZ7RIhv3DdaNe07IZ0QYup9dDufIcCKruAgu0hwYMwDHmZNrrWxMia
GQwagxs61mla6f7c1bvYY92PhfgpkQAN99MXdaTtvBbzDuY018QP+TVzzVH/hpjK
aFx4JlYkcVGqbYamUiP7il4Hldqp6Mm65IH/8nxuZFrN4tJ5VyMeWeZ5sKBBrXZE
1Je8524COYnvljGnaFAVaDRhAcTSEykveY8jx/r6MB95LkWcue7FXIQyX0D3/2lU
KTu/wrBCmhriqNa4FHcccLMyQkiMbs8mEoldNCwYDxvF5lYc19UDlleE855lME00
E/ogStmazzFrNWCzEJ+Pa9JVlTQonKRgWqi+9cWwV+AMd+s2F3wO+H2tlexe8pLo
Vw/42S44tHz4VuZuhpZvn3kCAwEAAQ==
-----END PUBLIC KEY-----
```

This step converts it to this JWK:
```
{
  "alg": "RS256",
  "jwk": {
    "e": "AQAB",
    "kty": "RSA",
    "n": "5aok6d72rkrGpOPAICSS3JPrA0tbVs3mYPWmG7c5tGEY-w1slyI-3V64NsLw8p9YqNLyX_YDsnmkOUMUx6Buvx43daBrl__wz3hIOvidXyV4z65Nbrlto9qtLpfi-9lbEEYt2PLhr-KjguqjqOQjqi2PgqdITGG-BZkU8xIrPzZCR_UPBotV_dGBj9vO1whTGlzpkihvXLf4rEFoJoEEeOPMtqbxUp1KS41EgX2xFav9JHPVI1hm66K0eqlJrBl407j3xRNlekl4xorwfCkAxC7xclofg3JZ7RIhv3DdaNe07IZ0QYup9dDufIcCKruAgu0hwYMwDHmZNrrWxMiaGQwagxs61mla6f7c1bvYY92PhfgpkQAN99MXdaTtvBbzDuY018QP-TVzzVH_hpjKaFx4JlYkcVGqbYamUiP7il4Hldqp6Mm65IH_8nxuZFrN4tJ5VyMeWeZ5sKBBrXZE1Je8524COYnvljGnaFAVaDRhAcTSEykveY8jx_r6MB95LkWcue7FXIQyX0D3_2lUKTu_wrBCmhriqNa4FHcccLMyQkiMbs8mEoldNCwYDxvF5lYc19UDlleE855lME00E_ogStmazzFrNWCzEJ-Pa9JVlTQonKRgWqi-9cWwV-AMd-s2F3wO-H2tlexe8pLoVw_42S44tHz4VuZuhpZvn3k"
  }
}
```

###Step 2: Certificate Signing Request

Second, you need to specify the domains you want certificates for. That's done
through a certificate signing request ([CSR](https://en.wikipedia.org/wiki/Certificate_signing_request)).
The javascript in this section uses the [ASN1.js](https://lapo.it/asn1js/) library
to parse the CSR and read the domains. NOTE: the private key for the domain cert
cannot be the same as your account private key, according to ACME.

###Step 3: Sign API Requests

Third, you need tell the Let's Encrypt API that you want to register and get certs
for some domains. These requests must be signed with your account private key, so
this steps compiles the request payloads that need signatures. You need to ask for
challenges for each domain, so if you want both `example.com` and `www.example.com`, you
need to make two new-authz calls.

Here's the list of requests that need to be made to the API:
* `/acme/new-reg` - Register the account public key (discarded if already registered)
* `/acme/new-authz` - Asks for challenges for the domain for which you want a cert.
* `/acme/new-authz` - (...needs to be called for each domain)
* `/acme/new-cert` - Asking for your CSR to be signed.

NOTE: Each request also requires an anti-replay nonce, so the javascript gets
those by making ajax requests to the `/directory` endpoint.

For each request the payload must be signed, and since this website doesn't ask
for your private keys, you must copy-and-paste the signature commands into your
terminal.

These commands are structured like this:
```
PRIV_KEY=./account.key; \                      #set the location of your account private key (change this location if different)
    echo -n "<request_payload_data>" | \       #pipe the payload into openssl
    openssl dgst -sha256 -hex -sign $PRIV_KEY  #sign the payload using your private key and output hex
```

Once these signatures are pasted back into the inputs, the javascript makes the
ajax requests to the above endpoints for `new-reg` and each `new-authz`. If the
account public key has already been registered the `new-reg` response is a 409
Conflict, which is ignored.

###Step 4: Verify Ownership

The response for each `/new-authz` has some challenges you need perform to
prove you own the domain. The challenge that this website chooses is "http-01",
which requires that you host a specific file at a specific location. So, for
each domain, this step shows you the file you need to host and the url you need
to host it at.

After the file is being hosted, you need to tell Let's Encrypt to check the
verify the challenge for that domain. That request must also be signed so
there's one more signature that must be performed. The reason why this wasn't
included in step 3 is because the payload contains something in the response of
`/new-authz`.

There's two options this website offers as copy-and-paste commands: python and
file-based. The python command is a mini server you can copy-and-paste into your
server's command line (NOTE: this needs sudo permissions!). The file-base option
just lists the url where the challenge will check and the file contents that the
file needs to contain. It's up to you to figure out how to make that happen.

When you confirm that you're hosting the files, an ajax request is made to the
challenge url to tell Let's Encrypt to verify the domain. Once this is done for
all the domains in your CSR, an ajax request is made to `/new-cert` with the
previously signed payload from step 3.

###Step 5: Install Certificate

The response from `/new-cert` should be your new certificate! Congrats! This
step prints the certificate and also prints the intermediate certificate you
need to chain this certificate to the root certificate.

##Privacy

This website is entirely static files and only makes ajax requests to the
Let's Encrypt API. It does not track or remember anything when you leave.
It is written with minimal extra libraries and styling to ensure that you
can read through and audit the source code.

Finally, since this website is completely static, it's un-hostable! Just
right-click and "Save Page As...", save the complete website to your local
computer, then open it in a browser. It still works when hosted locally!

##Feedback/Contributing

I'd love to receive feedback, issues, and pull requests to make this script
better. The main script itself, `js/index.js`, is less than 800 lines of code, so
feel free to read through it! I tried to comment things well and make it crystal
clear what it's doing.

TODO (pull requests welcome):
* `renew.html` - A page with steps for renewing certificates
* `revoke.html` - A page with steps for revoking certificates
* ~~Alternative file-based command instead of python server~~
* ~~Installation instructions for Apache~~
* Accept GPG public keys as account public keys

##What's NOT on the Roadmap

* Third party libraries (asn1.js is the only one)
* Fonts or images
* CSS more than 5 kilobytes
* Javascript that only changes UI
* HTML that decreases source readability (added wrapping divs, etc.)

This website is supposed to [work](http://motherfuckingwebsite.com/), nothing more.

