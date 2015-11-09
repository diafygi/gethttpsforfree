/*
 * This file contains the functions needed to run index.html
 */

// global variables
var ACCOUNT_EMAIL, // "bar@foo.com"
    ACCOUNT_PUBKEY, // {
                    //   "pubkey": "-----BEGIN PUBLIC KEY...",
                    //   "jwk": {...},
                    //   "data": "deadbeef...",
                    //   "sig": "deadbeef..."
                    // }
    CSR, // {
         //   "csr": "-----BEGIN CERTIFICATE REQUEST...",
         //   "data": "deadbeef...",
         //   "sig": "deadbeef...",
         // }
    DOMAINS, // {
             //   "www.foo.com": {
             //     "request_data": "deadbeef...",
             //     "request_sig": "deadbeef...",
             //     "response_data": "deadbeef...",
             //     "response_sig": "deadbeef...",
             //     "confirm": True,
             //     "verify_data": "deadbeef...",
             //     "verify_sig": "deadbeef...",
             //   },
             //   ...
             // }
    SIGNED_CERT; // "-----BEGIN CERTIFICATE..."

// hide/show the help content
function helpContent(e){
    e.preventDefault();
    var help = document.getElementById(e.target.id + "_content");
    help.style.display = help.style.display === "none" ? "" : "none";
}
function bindHelps(elems){
    for(var i = 0; i < elems.length; i++){
        elems[i].addEventListener("click", helpContent);
    }
}
bindHelps(document.querySelectorAll(".help"));

// validate account info
function validateAccount(e){
    var status = document.getElementById("validate_account_status");
    function fail(msg){
        ACCOUNT_EMAIL = undefined;
        ACCOUNT_PUBKEY = undefined;
        status.style.display = "inline";
        status.className = "error";
        status.innerHTML = "";
        status.appendChild(document.createTextNode("Error: " + msg));
    }

    // clear previous status
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "validating...";

    // validate email
    var email_re = /^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i;
    var email = document.getElementById("email").value;
    if(!email_re.test(email)){
        return fail("Account email doesn't look valid.");
    }

    // parse account public key
    var pubkey = document.getElementById("pubkey").value;
    if(pubkey === ""){
        return fail("You need to include an account public key.");
    }
    var unarmor = /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\/=\s]+)-----END PUBLIC KEY-----/;
    if(!unarmor.test(pubkey)){
        return fail("Your public key isn't formatted correctly.");
    }

    // find RSA modulus and exponent
    try{
        var pubkeyAsn1 = ASN1.decode(Base64.decode(unarmor.exec(pubkey)[1]));
        var modulusRaw = pubkeyAsn1.sub[1].sub[0].sub[0];
        var modulusStart = modulusRaw.header + modulusRaw.stream.pos + 1;
        var modulusEnd = modulusRaw.length + modulusRaw.stream.pos + modulusRaw.header;
        var modulusHex = modulusRaw.stream.hexDump(modulusStart, modulusEnd);
        var modulus = Hex.decode(modulusHex);
        var exponentRaw = pubkeyAsn1.sub[1].sub[0].sub[1];
        var exponentStart = exponentRaw.header + exponentRaw.stream.pos;
        var exponentEnd = exponentRaw.length + exponentRaw.stream.pos + exponentRaw.header;
        var exponentHex = exponentRaw.stream.hexDump(exponentStart, exponentEnd);
        var exponent = Hex.decode(exponentHex);
    }
    catch(err){
        console.error(err);
        // TODO: also try reading GPG public key
        return fail("Failed validating RSA public key.");
    }


    // generate the jwk header
    var modulus64 = window.btoa(String.fromCharCode.apply(null, new Uint8Array(modulus)));
    var modulusJWK = modulus64.replace("/", "_").replace("+", "+").replace("=", "");
    var exponent64 = window.btoa(String.fromCharCode.apply(null, new Uint8Array(exponent)));
    var exponentJWK = exponent64.replace("/", "_").replace("+", "+").replace("=", "");

    // update the globals
    ACCOUNT_EMAIL = email;
    ACCOUNT_PUBKEY = {
        pubkey: pubkey,
        jwk: {
            alg: "RS256",
            jwk: {
                "e": exponentJWK,
                "kty": "RSA",
                "n": modulusJWK,
            }
        }
    };

    // show the success text (simulate a delay so it looks like we thought hard)
    window.setTimeout(function(){
        status.style.display = "inline";
        status.className = "";
        status.innerHTML = "Looks good! Proceed to Step 2!";
    }, 500);
}
document.getElementById("validate_account").addEventListener("click", validateAccount);

// validate CSR
function validateCSR(e){
    console.log("validateCSR");
}
document.getElementById("validate_csr").addEventListener("click", validateCSR);

// validate initial signatures
function validateInitialSigs(e){
    console.log("validateInitialSigs");
}
document.getElementById("validate_initial_sigs").addEventListener("click", validateInitialSigs);

// confirm domain check is running
function confirmDomainCheckIsRunning(e){
    console.log("confirmDomainCheckIsRunning");
}

// verify ownership
function verifyOwnership(e){
    console.log("verifyOwnership");
}

// request to sign certificate
function signCertificate(e){
    console.log("signCertificate");
}

