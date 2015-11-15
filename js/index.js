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

// show warning if no webcrypto digest
window.crypto = window.crypto || window.msCrypto; //for IE11
if(window.crypto && window.crypto.webkitSubtle){
    window.crypto.subtle = window.crypto.webkitSubtle; //for Safari
}
var DIGEST = window.crypto ? (window.crypto.subtle ? window.crypto.subtle.digest : undefined) : undefined;
document.getElementById("digest_error").style.display = DIGEST ? "none" : "block";

// SHA-256 shim for standard promise-based and IE11 event-based
function sha256(bytes, callback){
    var hash = window.crypto.subtle.digest({name: "SHA-256"}, bytes);
    // IE11
    if(hash.oncomplete){
        hash.oncomplete = function(e){
            callback(new Uint8Array(e.target.result));
        };
        hash.onerror = function(e){
            callback(undefined, e);
        };
    }
    // standard promise-based
    else{
        hash.then(function(result){
            callback(new Uint8Array(result));
        })
        .catch(function(error){
            callback(undefined, error);
        });
    }
}

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
        status.innerHTML = "";
        status.appendChild(document.createTextNode("Looks good! Proceed to Step 2!"));
    }, 300);
}
document.getElementById("validate_account").addEventListener("click", validateAccount);

// validate CSR
function validateCSR(e){
    var status = document.getElementById("validate_csr_status");
    function fail(msg){
        CSR = undefined;
        DOMAINS = undefined;
        status.style.display = "inline";
        status.className = "error";
        status.innerHTML = "";
        status.appendChild(document.createTextNode("Error: " + msg));
    }

    // clear previous status
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "validating...";

    // make sure there's an account public key and email
    if(!(ACCOUNT_EMAIL && ACCOUNT_PUBKEY)){
        return fail("Need to complete Step 1 first.");
    }

    // parse csr
    var csr = document.getElementById("csr").value;
    if(csr === ""){
        return fail("You need to include a CSR.");
    }
    var unarmor = /-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE REQUEST-----/;
    if(!unarmor.test(csr)){
        return fail("Your CSR isn't formatted correctly.");
    }

    // find domains in the csr
    var domains = [];
    try{
        var csrAsn1 = ASN1.decode(Base64.decode(unarmor.exec(csr)[1]));

        // look for commonName in attributes
        if(csrAsn1.sub[0].sub[1].sub){
            var csrIds = csrAsn1.sub[0].sub[1].sub;
            for(var i = 0; i < csrIds.length; i++){
                var oidRaw = csrIds[i].sub[0].sub[0];
                var oidStart = oidRaw.header + oidRaw.stream.pos;
                var oidEnd = oidRaw.length + oidRaw.stream.pos + oidRaw.header;
                var oid = oidRaw.stream.parseOID(oidStart, oidEnd, Infinity);
                if(oid === "2.5.4.3"){
                    var cnRaw = csrIds[i].sub[0].sub[1];
                    var cnStart = cnRaw.header + cnRaw.stream.pos;
                    var cnEnd = cnRaw.length + cnRaw.stream.pos + cnRaw.header;
                    domains.push(cnRaw.stream.parseStringUTF(cnStart, cnEnd));
                }
            }
        }

        // look for subjectAltNames
        if(csrAsn1.sub[0].sub[3].sub){

            // find the PKCS#9 ExtensionRequest
            var xtns = csrAsn1.sub[0].sub[3].sub;
            for(var i = 0; i < xtns.length; i++){
                var oidRaw = xtns[i].sub[0];
                var oidStart = oidRaw.header + oidRaw.stream.pos;
                var oidEnd = oidRaw.length + oidRaw.stream.pos + oidRaw.header;
                var oid = oidRaw.stream.parseOID(oidStart, oidEnd, Infinity);
                if(oid === "1.2.840.113549.1.9.14"){

                    // find any subjectAltNames
                    for(var j = 0; j < xtns[i].sub[1].sub.length ? xtns[i].sub[1].sub : 0; j++){
                        for(var k = 0; k < xtns[i].sub[1].sub[j].sub.length ? xtns[i].sub[1].sub[j].sub : 0; k++){
                            var oidRaw = xtns[i].sub[1].sub[j].sub[k].sub[0];
                            var oidStart = oidRaw.header + oidRaw.stream.pos;
                            var oidEnd = oidRaw.length + oidRaw.stream.pos + oidRaw.header;
                            var oid = oidRaw.stream.parseOID(oidStart, oidEnd, Infinity);
                            if(oid === "2.5.29.17"){

                                // add each subjectAltName
                                var sans = xtns[i].sub[1].sub[j].sub[k].sub[1].sub[0].sub;
                                for(var s = 0; s < sans.length; s++){
                                    var sanRaw = sans[s];
                                    var sanStart = sanRaw.header + sanRaw.stream.pos;
                                    var sanEnd = sanRaw.length + sanRaw.stream.pos + sanRaw.header;
                                    domains.push(sanRaw.stream.parseStringUTF(sanStart, sanEnd));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    catch(err){
        return fail("Failed validating CSR.");
    }

    // update the globals
    CSR = {csr: csr};
    DOMAINS = {};
    var domainString = "";
    for(var d = 0; d < domains.length; d++){
        DOMAINS[domains[d]] = {};
        domainString += (d === 0 ? "" : ", ") + domains[d];
    }

    // TODO: Request nonces for all the signatures and build the data payloads

    //Wait for all the data payloads to finish building
    window.setTimeout(function(){

        // TODO: check to see if all the data payloads are built

        // TODO: show step 3

        // show the success text (simulate a delay so it looks like we thought hard)
        status.style.display = "inline";
        status.className = "";
        status.innerHTML = "";
        status.appendChild(document.createTextNode(
            "Found domains! Proceed to Step 3! (" + domainString + ")"));
    }, 300);
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

