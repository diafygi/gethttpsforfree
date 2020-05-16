/*
 * This file contains the functions needed to run index.html
 */

// global variables
var DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";
//var DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
var DIRECTORY = {
//  "keyChange": "https://...
//  "meta": {
//      "termsOfService": "https://..."
//  },
//  "newAccount": "https://...",
//  "newNonce": "https://...",
//  "newOrder": "https://...",
//  "revokeCert": "https://...",
};
var ACCOUNT = {
//  "pubkey": "-----BEGIN PUBLIC KEY...",
//  "alg": "RS256",
//  "jwk": {"e": "deadbeef...", "kty": "RSA", "n": "deadbeef..."},
//  "thumbprint": "deadbeef...",
//  "account_uri": "https://...",
//
//  // newAccount - account registration (or to get the account_uri)
//  "registration_payload_json": {"termsOfServiceAgreed": true},
//  "registration_payload_b64": "deadbeef...",
//  "registration_protected_json": {"url": "...", "alg": "...", "nonce": "...", "jwk": {...}},
//  "registration_protected_b64": "deadbeef...",
//  "registration_sig": "deadbeef...",
//  "registration_response": {"status": "valid", "contact": [..], "termsOfServiceAgreed": true, "orders": "..."},
//
//  // account contact update
//  "update_payload_json": {"contact": ["mailto:..."]},
//  "update_payload_b64": "deadbeef...",
//  "update_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//  "update_protected_b64": "deadbeef...",
//  "update_sig": "deadbeef...",
//  "update_response": {"status": "valid", "contact": [..], "termsOfServiceAgreed": true, "orders": "..."},
};
var ORDER = {
//  "csr_pem": "-----BEGIN CERTIFICATE REQUEST...",
//  "csr_der": "deadbeef...", (DER encoded)
//
//  // create order for identifiers
//  "order_payload_json": {"identifiers": [{"type": "dns", "value": "aaa.com"}, ...]},
//  "order_payload_b64": "deadbeef...",
//  "order_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//  "order_protected_b64": "deadbeef...",
//  "order_sig": "deadbeef...",
//  "order_response": {"status": "valid", "identifiers": [...], "authorizations": [...], "finalize": "...", ...},
//  "order_uri": "https://...",
//
//  // get csr signed
//  "finalize_uri": "https://...",
//  "finalize_payload_json": {"csr": "..."},
//  "finalize_payload_b64": "deadbeef...",
//  "finalize_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//  "finalize_protected_b64": "deadbeef...",
//  "finalize_sig": "deadbeef...",
//  "finalize_response": {"status": "pending", "certificate": "...", ...},
//
//  // re-check order after finalizing
//  "recheck_order_payload_json": "", // GET-as-POST has an empty payload
//  "recheck_order_payload_b64": "",  // GET-as-POST has an empty payload
//  "recheck_order_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//  "recheck_order_protected_b64": "deadbeef...",
//  "recheck_order_sig": "deadbeef...",
//  "recheck_order_response": {"status": "valid", "certificate": "...", ...},
//
//  // download the generated certificate
//  "cert_payload_json": "", // GET-as-POST has an empty payload
//  "cert_payload_b64": "",  // GET-as-POST has an empty payload
//  "cert_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//  "cert_protected_b64": "deadbeef...",
//  "cert_sig": "deadbeef...",
//  "cert_response": "-----BEGIN CERTIFICATE-----...",
//  "cert_uri": "https://...",
};
var AUTHORIZATIONS = {
//  // one authorization for each domain
//  "https://...": {
//      // get authorization initially
//      "auth_payload_json": "", // GET-as-POST has an empty payload
//      "auth_payload_b64": "",  // GET-as-POST has an empty payload
//      "auth_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//      "auth_protected_b64": "deadbeef...",
//      "auth_sig": "deadbeef...",
//      "auth_response": {"status": "valid", "identifier": {...}, "challenges": [...], "wildcard": false, ...},
//
//      // python server HTTP challenge
//      "python_challenge_uri": "https://...",
//      "python_challenge_object": {"type": "http-01", ...},
//      "python_challenge_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//      "python_challenge_protected_b64": "deadbeef...",
//      "python_challenge_sig": "deadbeef...",
//      "python_challenge_response": {"type": "http-01", "url": "...", "token": "..."},
//
//      // file-based HTTP challenge
//      "file_challenge_uri": "https://...",
//      "file_challenge_object": {"type": "http-01", ...},
//      "file_challenge_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//      "file_challenge_protected_b64": "deadbeef...",
//      "file_challenge_sig": "deadbeef...",
//      "file_challenge_response": {"type": "http-01", "url": "...", "token": "..."},
//
//      // DNS challenge
//      "dns_challenge_uri": "https://...",
//      "dns_challenge_object": {"type": "dns-01", ...},
//      "dns_challenge_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//      "dns_challenge_protected_b64": "deadbeef...",
//      "dns_challenge_sig": "deadbeef...",
//      "dns_challenge_response": {"type": "dns-01", "url": "...", "token": "..."},
//
//      // post-challenge authorization check
//      "recheck_auth_payload_json": "", // GET-as-POST has an empty payload
//      "recheck_auth_payload_b64": "",  // GET-as-POST has an empty payload
//      "recheck_auth_protected_json": {"url": "...", "alg": "...", "nonce": "...", "kid": "..."},
//      "recheck_auth_protected_b64": "deadbeef...",
//      "recheck_auth_sig": "deadbeef...",
//      "recheck_auth_response": {"status": "valid", "identifier": {...}, "challenges": [...], "wildcard": false, ...},
//  },
//  ...
};
var RESULT_PLACEHOLDER = "Paste the hex output here (e.g. \"(stdin)= f2cf67e4...\")";

/*
 * Helper Functions
 */

// display errors
function fail(status_element, error_message){
    // debug
    if(window.location.search.indexOf("debug") !== -1 && console){
        console.log("DIRECTORY_URL", DIRECTORY_URL);
        console.log("DIRECTORY", DIRECTORY);
        console.log("ACCOUNT", ACCOUNT);
        console.log("ORDER", ORDER);
        console.log("AUTHORIZATIONS", AUTHORIZATIONS);
    }
    status_element.style.display = "inline";
    status_element.className = status_element.className + " error";
    status_element.innerHTML = "";
    status_element.appendChild(document.createTextNode("Error: " + error_message));
}

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
    if(!hash.then){
        hash.oncomplete = function(e){
            callback(new Uint8Array(e.target.result), undefined);
        };
        hash.onerror = function(e){
            callback(undefined, e);
        };
    }
    // standard promise-based
    else{
        hash.then(function(result){
            callback(new Uint8Array(result), undefined);
        })
        .catch(function(error){
            callback(undefined, error);
        });
    }
}

// url-safe base64 encoding
function b64(bytes){
    var str64 = typeof(bytes) === "string" ? window.btoa(bytes) : window.btoa(String.fromCharCode.apply(null, bytes));
    return str64.replace(/\//g, "_").replace(/\+/g, "-").replace(/=/g, "");
}
function b64decode(b64string){
    try { return window.atob(b64string.replace(/_/g, "/").replace(/-/g, "+") + "=="); }
    catch (err) {
        if(err.name === "InvalidCharacterError"){
            return window.atob(b64string.replace(/_/g, "/").replace(/-/g, "+") + "="); // only need one trailing equals
        } else {
            throw err;
        }
    }
}

// parse openssl hex output
var OPENSSL_HEX = /(?:\(stdin\)= |)([a-f0-9]{512,1024})/
function hex2b64(hex){
    if(!OPENSSL_HEX.test(hex)){
        return null;
    }
    hex = OPENSSL_HEX.exec(hex)[1];
    var bytes = [];
    while(hex.length >= 2){
        bytes.push(parseInt(hex.substring(0, 2), 16));
        hex = hex.substring(2, hex.length);
    }
    return b64(new Uint8Array(bytes));
}

// url-safe base64 encoding
function cachebuster(){
    return "cachebuster=" + b64(window.crypto.getRandomValues(new Uint8Array(8)));
}

// helper function to get a nonce via an ajax request to the ACME directory
function getNonce(callback){
    var xhr = new XMLHttpRequest();
    xhr.open("GET", DIRECTORY['newNonce'] + "?" + cachebuster());
    xhr.onload = function(){
        callback(xhr.getResponseHeader("Replay-Nonce"), undefined);
    };
    xhr.onerror = function(){
        callback(undefined, xhr);
    };
    xhr.send();
}

/*
 * Step 0: Let's Encrypt Directory
 */

// get the directory with links to all the other endpoints
function populateDirectory(){
    var xhr = new XMLHttpRequest();
    xhr.open("GET", DIRECTORY_URL + "?" + cachebuster());
    xhr.onload = function(){
        // set the directory urls
        DIRECTORY = JSON.parse(xhr.responseText);
        // set the terms of service links
        document.getElementById("tos").setAttribute("href", DIRECTORY['meta']['termsOfService']);
        document.getElementById("howto_tos").setAttribute("href", DIRECTORY['meta']['termsOfService']);
        // enable buttons so user can continue
        document.getElementById("validate_account").addEventListener("submit", validateAccount);
        document.getElementById("validate_account_submit").removeAttribute("disabled");
        document.getElementById("validate_csr").addEventListener("submit", validateCSR);
        document.getElementById("validate_csr_submit").removeAttribute("disabled");
        document.getElementById("validate_registration").addEventListener("submit", validateRegistration);
        document.getElementById("validate_update").addEventListener("submit", validateUpdate);
        document.getElementById("validate_order").addEventListener("submit", validateOrder);
        document.getElementById("validate_finalize").addEventListener("submit", validateFinalize);
        document.getElementById("validate_recheck_order").addEventListener("submit", recheckOrder);
        document.getElementById("validate_cert").addEventListener("submit", getCertificate);
    };
    xhr.onerror = function(){
        fail(document.getElementById("validate_account_status"), "Let's Encrypt appears to be down. Please try again later.");
    };
    xhr.send();
}
populateDirectory();

/*
 * Step 1: Account Info
 */

// validate account info
function validateAccount(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_account_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "validating...";

    // validate email
    var email_re = /^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i;
    var email = document.getElementById("email").value;
    if(!email_re.test(email)){
        return fail(status, "Account email doesn't look valid.");
    }

    // update email in interface
    document.getElementById("account_email").innerHTML = "";
    document.getElementById("account_email").appendChild(document.createTextNode(email));

    // parse account public key
    var pubkey = document.getElementById("pubkey").value;
    if(pubkey === ""){
        return fail(status, "You need to include an account public key.");
    }
    var unarmor = /-----BEGIN PUBLIC KEY-----([A-Za-z0-9+\/=\s]+)-----END PUBLIC KEY-----/;
    if(!unarmor.test(pubkey)){
        return fail(status, "Your public key isn't formatted correctly.");
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
        return fail(status, "Failed validating RSA public key.");
    }

    // generate the jwk header and bytes
    var jwk = {
        "e": b64(new Uint8Array(exponent)),
        "kty": "RSA",
        "n": b64(new Uint8Array(modulus)),
    }
    var jwk_json = JSON.stringify(jwk);
    var jwk_bytes = [];
    for(var i = 0; i < jwk_json.length; i++){
        jwk_bytes.push(jwk_json.charCodeAt(i));
    }

    // calculate thumbprint
    sha256(new Uint8Array(jwk_bytes), function(hash, err){
        if(err){
            return fail(status, "Thumbprint failed: " + err.message);
        }

        // update the global account object
        var registration_payload = {"termsOfServiceAgreed": true};
        var account_payload = {"contact": ["mailto:" + email]};
        ACCOUNT = {
            "pubkey": pubkey,
            "alg": "RS256",
            "jwk": jwk,
            "thumbprint": b64(hash),
            "account_uri": undefined,

            // newAccount - account registration (or to get the account_url)
            "registration_payload_json": registration_payload,
            "registration_payload_b64": b64(JSON.stringify(registration_payload)),
            "registration_protected_json": undefined,
            "registration_protected_b64": undefined,
            "registration_sig": undefined,
            "registration_response": undefined,

            // account contact update
            "update_payload_json": account_payload,
            "update_payload_b64": b64(JSON.stringify(account_payload)),
            "update_protected_json": undefined,
            "update_protected_b64": undefined,
            "update_sig": undefined,
            "update_response": undefined,
        };

        // show the success text (simulate a delay so it looks like we thought hard)
        window.setTimeout(function(){
            status.style.display = "inline";
            status.className = "";
            status.innerHTML = "";
            status.appendChild(document.createTextNode("Looks good! Proceed to Step 2!"));
        }, 300);
    });
}

/*
 * Step 2: CSR
 */

// validate CSR
function validateCSR(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_csr_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "validating...";

    // hide following steps
    document.getElementById("step3").style.display = "none";
    document.getElementById("step3_pending").style.display = "inline";
    document.getElementById("step4").style.display = "none";
    document.getElementById("step4_pending").style.display = "inline";
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset registration status
    document.getElementById("validate_registration_sig_status").style.display = "none";
    document.getElementById("validate_registration_sig_status").className = "";
    document.getElementById("validate_registration_sig_status").innerHTML = "";

    // reset account update signature
    document.getElementById("update_sig_cmd").value = "waiting until terms are accepted...";
    document.getElementById("update_sig_cmd").removeAttribute("readonly");
    document.getElementById("update_sig_cmd").setAttribute("disabled", "");
    document.getElementById("update_sig").value = "";
    document.getElementById("update_sig").setAttribute("placeholder", "waiting until terms are accepted...");
    document.getElementById("update_sig").setAttribute("disabled", "");
    document.getElementById("validate_update_sig").setAttribute("disabled", "");
    document.getElementById("validate_update_sig_status").style.display = "none";
    document.getElementById("validate_update_sig_status").className = "";
    document.getElementById("validate_update_sig_status").innerHTML = "";

    // reset new order signature
    document.getElementById("order_sig_cmd").value = "waiting until account contact is updated...";
    document.getElementById("order_sig_cmd").removeAttribute("readonly");
    document.getElementById("order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("order_sig").value = "";
    document.getElementById("order_sig").setAttribute("placeholder", "waiting until account contact is updated...");
    document.getElementById("order_sig").setAttribute("disabled", "");
    document.getElementById("validate_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_order_sig_status").style.display = "none";
    document.getElementById("validate_order_sig_status").className = "";
    document.getElementById("validate_order_sig_status").innerHTML = "";

    // make sure there's an account public key and email
    if(ACCOUNT['pubkey'] === undefined){
        return fail(status, "Need to complete Step 1 first.");
    }

    // parse csr
    var csr = document.getElementById("csr").value;
    if(csr === ""){
        return fail(status, "You need to include a CSR.");
    }
    var unarmor = /-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE REQUEST-----/;
    if(!unarmor.test(csr)){
        return fail(status, "Your CSR isn't formatted correctly.");
    }
    var csr_der = b64(new Uint8Array(Base64.decode(unarmor.exec(csr)[1])));

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
                                    var tag = sanRaw.tag.tagNumber;
                                    if(tag !== 2)
                                        continue; // ignore any other subjectAltName type than dNSName (2)
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
        return fail(status, "Failed validating CSR.");
    }

    // reject CSRs with no domains
    if(domains.length === 0){
        return fail(status, "Couldn't find any domains in the CSR.");
    }

    // build order payload
    var finalize_payload = {"csr": csr_der};
    var order_payload = {"identifiers": []};
    for(var i = 0; i < domains.length; i++){
        order_payload['identifiers'].push({"type": "dns", "value": domains[i]});
    }

    // update the globals
    ORDER = {
        "csr_pem": csr,
        "csr_der": csr_der,

        // order for identifiers
        "order_payload_json": order_payload,
        "order_payload_b64": b64(JSON.stringify(order_payload)),
        "order_protected_json": undefined,
        "order_protected_b64": undefined,
        "order_sig": undefined,
        "order_response": undefined,
        "order_uri": undefined,

        // order finalizing
        "finalize_uri": undefined,
        "finalize_payload_json": finalize_payload,
        "finalize_payload_b64": b64(JSON.stringify(finalize_payload)),
        "finalize_protected_json": undefined,
        "finalize_protected_b64": undefined,
        "finalize_sig": undefined,
        "finalize_response": undefined,

        // order checking after finalizing
        "recheck_order_payload_json": "", // GET-as-POST has an empty payload
        "recheck_order_payload_b64": "",  // GET-as-POST has an empty payload
        "recheck_order_protected_json": undefined,
        "recheck_order_protected_b64": undefined,
        "recheck_order_sig": undefined,
        "recheck_order_response": undefined,

        // certificate downloading
        "cert_payload_json": "", // GET-as-POST has an empty payload
        "cert_payload_b64": "",  // GET-as-POST has an empty payload
        "cert_protected_json": undefined,
        "cert_protected_b64": undefined,
        "cert_sig": undefined,
        "cert_response": undefined,
        "cert_uri": undefined,
    };

    // set the shortest domain for the ssl test at the end
    var shortest_domain = domains[0];
    for(var d = 0; d < domains.length; d++){
        if(shortest_domain.length > domains[d].length){
            shortest_domain = domains[d];
        }
    }
    document.getElementById("ssltest_domain").value = shortest_domain;

    // get nonce for registration
    getNonce(function(nonce, err){
        if(err){
            return fail(status, "Failed terms nonce request (code: " + err.status + "). " + err.responseText);
        }

        // populate registration signature (payload populated in validateAccount())
        ACCOUNT['registration_protected_json'] = {
            "url": DIRECTORY['newAccount'],
            "alg": ACCOUNT['alg'],
            "nonce": nonce,
            "jwk": ACCOUNT['jwk'],
        }
        ACCOUNT['registration_protected_b64'] = b64(JSON.stringify(ACCOUNT['registration_protected_json']));
        document.getElementById("registration_sig_cmd").value = "" +
            "PRIV_KEY=./account.key; " +
            "echo -n \"" + ACCOUNT['registration_protected_b64'] + "." + ACCOUNT['registration_payload_b64'] + "\" | " +
            "openssl dgst -sha256 -hex -sign $PRIV_KEY";
        document.getElementById("registration_sig").value = "";
        document.getElementById("registration_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);

        // show step 3
        status.style.display = "inline";
        status.className = "";
        status.innerHTML = "";
        status.appendChild(document.createTextNode("Found domains! Proceed to Step 3! (" + domains.join(", ") + ")"));
        document.getElementById("step3").style.display = "block";
        document.getElementById("step3_pending").style.display = "none";
    });
}

/*
 * Step 3a: Register Account (POST /newAccount)
 */
function validateRegistration(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_registration_sig_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "accepting...";

    // hide following steps
    document.getElementById("step4").style.display = "none";
    document.getElementById("step4_pending").style.display = "inline";
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset account update signature
    document.getElementById("update_sig_cmd").value = "waiting until terms are accepted...";
    document.getElementById("update_sig_cmd").removeAttribute("readonly");
    document.getElementById("update_sig_cmd").setAttribute("disabled", "");
    document.getElementById("update_sig").value = "";
    document.getElementById("update_sig").setAttribute("placeholder", "waiting until terms are accepted...");
    document.getElementById("update_sig").setAttribute("disabled", "");
    document.getElementById("validate_update_sig").setAttribute("disabled", "");
    document.getElementById("validate_update_sig_status").style.display = "none";
    document.getElementById("validate_update_sig_status").className = "";
    document.getElementById("validate_update_sig_status").innerHTML = "";

    // reset new order signature
    document.getElementById("order_sig_cmd").value = "waiting until account contact is updated...";
    document.getElementById("order_sig_cmd").removeAttribute("readonly");
    document.getElementById("order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("order_sig").value = "";
    document.getElementById("order_sig").setAttribute("placeholder", "waiting until account contact is updated...");
    document.getElementById("order_sig").setAttribute("disabled", "");
    document.getElementById("validate_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_order_sig_status").style.display = "none";
    document.getElementById("validate_order_sig_status").className = "";
    document.getElementById("validate_order_sig_status").innerHTML = "";

    // validate registration payload exists
    if(ACCOUNT['registration_payload_b64'] === undefined){
        return fail(status, "Terms payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var registration_sig = hex2b64(document.getElementById("registration_sig").value);
    if(registration_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ACCOUNT['registration_sig'] = registration_sig;

    // send newAccount request to CA
    var registration_xhr = new XMLHttpRequest();
    registration_xhr.open("POST", DIRECTORY['newAccount']);
    registration_xhr.setRequestHeader("Content-Type", "application/jose+json");
    registration_xhr.onreadystatechange = function(){
        if(registration_xhr.readyState === 4){

            // successful registration
            if(registration_xhr.status === 200 || registration_xhr.status === 201 || registration_xhr.status === 204){

                // set account_uri
                ACCOUNT['account_uri'] = registration_xhr.getResponseHeader("Location");

                // get nonce for account update
                getNonce(function(nonce, err){
                    if(err){
                        return fail(status, "Failed update nonce request (code: " + err.status + "). " + err.responseText);
                    }

                    // populate update signature (payload populated in validateAccount())
                    ACCOUNT['update_protected_json'] = {
                        "url": ACCOUNT['account_uri'],
                        "alg": ACCOUNT['alg'],
                        "nonce": nonce,
                        "kid": ACCOUNT['account_uri'],
                    }
                    ACCOUNT['update_protected_b64'] = b64(JSON.stringify(ACCOUNT['update_protected_json']));
                    document.getElementById("update_sig_cmd").value = "" +
                        "PRIV_KEY=./account.key; " +
                        "echo -n \"" + ACCOUNT['update_protected_b64'] + "." + ACCOUNT['update_payload_b64'] + "\" | " +
                        "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                    document.getElementById("update_sig_cmd").setAttribute("readonly", "");
                    document.getElementById("update_sig_cmd").removeAttribute("disabled");
                    document.getElementById("update_sig").value = "";
                    document.getElementById("update_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);
                    document.getElementById("update_sig").removeAttribute("disabled");
                    document.getElementById("validate_update_sig").removeAttribute("disabled");

                    // complete step 3a
                    status.innerHTML = "Accepted! Proceed to next command below.";
                });
            }

            // error registering
            else{
                return fail(status, "Account registration failed. Please start back at Step 1. " + registration_xhr.responseText);
            }
        }
    };
    registration_xhr.send(JSON.stringify({
        "protected": ACCOUNT['registration_protected_b64'],
        "payload": ACCOUNT['registration_payload_b64'],
        "signature": ACCOUNT['registration_sig'],
    }));
}

/*
 * Step 3b: Update Account Contact (POST /ACCOUNT['account_uri'])
 */
function validateUpdate(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_update_sig_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "updating...";

    // hide following steps
    document.getElementById("step4").style.display = "none";
    document.getElementById("step4_pending").style.display = "inline";
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset new order signature
    document.getElementById("order_sig_cmd").value = "waiting until account contact is updated...";
    document.getElementById("order_sig_cmd").removeAttribute("readonly");
    document.getElementById("order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("order_sig").value = "";
    document.getElementById("order_sig").setAttribute("placeholder", "waiting until account contact is updated...");
    document.getElementById("order_sig").setAttribute("disabled", "");
    document.getElementById("validate_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_order_sig_status").style.display = "none";
    document.getElementById("validate_order_sig_status").className = "";
    document.getElementById("validate_order_sig_status").innerHTML = "";

    // validate update payload exists
    if(ACCOUNT['update_payload_b64'] === undefined){
        return fail(status, "Update payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var update_sig = hex2b64(document.getElementById("update_sig").value);
    if(update_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ACCOUNT['update_sig'] = update_sig;

    // send update request to CA account_uri
    var update_xhr = new XMLHttpRequest();
    update_xhr.open("POST", ACCOUNT['account_uri']);
    update_xhr.setRequestHeader("Content-Type", "application/jose+json");
    update_xhr.onreadystatechange = function(){
        if(update_xhr.readyState === 4){

            // successful update
            if(update_xhr.status === 200){

                // get nonce for new order
                getNonce(function(nonce, err){
                    if(err){
                        return fail(status, "Failed order nonce request (code: " + err.status + "). " + err.responseText);
                    }

                    // populate order signature (payload populated in validateCSR())
                    ORDER['order_protected_json'] = {
                        "url": DIRECTORY['newOrder'],
                        "alg": ACCOUNT['alg'],
                        "nonce": nonce,
                        "kid": ACCOUNT['account_uri'],
                    }
                    ORDER['order_protected_b64'] = b64(JSON.stringify(ORDER['order_protected_json']));
                    document.getElementById("order_sig_cmd").value = "" +
                        "PRIV_KEY=./account.key; " +
                        "echo -n \"" + ORDER['order_protected_b64'] + "." + ORDER['order_payload_b64'] + "\" | " +
                        "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                    document.getElementById("order_sig_cmd").setAttribute("readonly", "");
                    document.getElementById("order_sig_cmd").removeAttribute("disabled");
                    document.getElementById("order_sig").value = "";
                    document.getElementById("order_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);
                    document.getElementById("order_sig").removeAttribute("disabled");
                    document.getElementById("validate_order_sig").removeAttribute("disabled");

                    // complete step 3b
                    status.innerHTML = "Updated! Proceed to next command below.";
                });
            }

            // error registering
            else{
                return fail(status, "Account contact update failed. Please start back at Step 1. " + update_xhr.responseText);
            }
        }
    };
    update_xhr.send(JSON.stringify({
        "protected": ACCOUNT['update_protected_b64'],
        "payload": ACCOUNT['update_payload_b64'],
        "signature": ACCOUNT['update_sig'],
    }));
}

/*
 * Step 3c: Create New Order (POST /newOrder)
 */
function validateOrder(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_order_sig_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "ordering...";

    // hide following steps
    document.getElementById("step4").style.display = "none";
    document.getElementById("step4_pending").style.display = "inline";
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // validate order payload exists
    if(ORDER['order_payload_b64'] === undefined){
        return fail(status, "Order payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var order_sig = hex2b64(document.getElementById("order_sig").value);
    if(order_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ORDER['order_sig'] = order_sig;

    // send newOrder request to CA
    var order_xhr = new XMLHttpRequest();
    order_xhr.open("POST", DIRECTORY['newOrder']);
    order_xhr.setRequestHeader("Content-Type", "application/jose+json");
    order_xhr.onreadystatechange = function(){
        if(order_xhr.readyState === 4){

            // successful order
            if(order_xhr.status === 200 || order_xhr.status === 201){

                // set order response and uri
                ORDER['order_response'] = JSON.parse(order_xhr.responseText);
                ORDER['order_uri'] = order_xhr.getResponseHeader("Location");
                ORDER['finalize_uri'] = ORDER['order_response']['finalize'];

                // clear out any previous authorizations and challenge forms
                AUTHORIZATIONS = {};
                document.getElementById("auths").innerHTML = "";

                // add a new challenge section per authorization url
                for(var i = 0; i < ORDER['order_response']['authorizations'].length; i++){

                    // populate the authorization object
                    var auth_url = ORDER['order_response']['authorizations'][i];
                    var auth_b64 = b64(auth_url);
                    AUTHORIZATIONS[auth_url] = {
                        // load authorization
                        "auth_payload_json": "", // GET-as-POST has an empty payload
                        "auth_payload_b64": "",  // GET-as-POST has an empty payload
                        "auth_protected_json": undefined,
                        "auth_protected_b64": undefined,
                        "auth_sig": undefined,
                        "auth_response": undefined,

                        // python server HTTP challenge
                        "python_challenge_uri": undefined,
                        "python_challenge_object": undefined,
                        "python_challenge_protected_json": undefined,
                        "python_challenge_protected_b64": undefined,
                        "python_challenge_sig": undefined,
                        "python_challenge_response": undefined,

                        // file-based HTTP challenge
                        "file_challenge_uri": undefined,
                        "file_challenge_object": undefined,
                        "file_challenge_protected_json": undefined,
                        "file_challenge_protected_b64": undefined,
                        "file_challenge_sig": undefined,
                        "file_challenge_response": undefined,

                        // DNS challenge
                        "dns_challenge_uri": undefined,
                        "dns_challenge_object": undefined,
                        "dns_challenge_protected_json": undefined,
                        "dns_challenge_protected_b64": undefined,
                        "dns_challenge_sig": undefined,
                        "dns_challenge_response": undefined,

                        // post-challenge authorization check
                        "recheck_auth_payload_json": "", // GET-as-POST has an empty payload
                        "recheck_auth_payload_b64": "",  // GET-as-POST has an empty payload
                        "recheck_auth_protected_json": undefined,
                        "recheck_auth_protected_b64": undefined,
                        "recheck_auth_sig": undefined,
                        "recheck_auth_response": undefined,
                    };

                    // copy template for this authorization
                    var template = document.getElementById("auth_template").cloneNode(true);
                    template.querySelector(".auth_i").innerHTML = (i + 1);
                    template.querySelector(".auth_count").innerHTML = ORDER['order_response']['authorizations'].length;

                    // set unique ids for this authorization section
                    template.setAttribute("id", "auth_" + auth_b64);
                    template.querySelector(".auth_form").setAttribute("id", "auth_" + auth_b64 + "_form");
                    template.querySelector(".howto_auth_sig").setAttribute("id", "howto_" + auth_b64 + "_auth_sig");
                    template.querySelector(".howto_auth_sig_label").setAttribute("for", "howto_" + auth_b64 + "_auth_sig");
                    template.querySelector(".howto_auth_sig").setAttribute("id", "howto_" + auth_b64 + "_auth_sig");
                    template.querySelector(".howto_auth_sig_label").setAttribute("for", "howto_" + auth_b64 + "_auth_sig");
                    template.querySelector(".auth_sig_cmd").setAttribute("id", auth_b64 + "_auth_sig_cmd");
                    template.querySelector(".auth_sig").setAttribute("id", auth_b64 + "_auth_sig");
                    template.querySelector(".validate_auth_sig").setAttribute("id", "validate_" + auth_b64 + "_auth_sig");
                    template.querySelector(".validate_auth_sig_status").setAttribute("id", "validate_" + auth_b64 + "_auth_sig_status");
                    template.querySelector(".challenges").setAttribute("id", "challenges_" + auth_b64);

                    // append auth template to page
                    template.style.display = "block";
                    document.getElementById("auths").appendChild(template);
                }

                // populate the first authorization request
                buildAuthorization(0, status, function(){

                    // show step 4
                    document.getElementById("step4").style.display = "block";
                    document.getElementById("step4_pending").style.display = "none";

                    // complete step 3c
                    status.innerHTML = "Ordered! Proceed to Step 4!";
                });

            }

            // error registering
            else{
                return fail(status, "Order failed. Please start back at Step 1. " + order_xhr.responseText);
            }
        }
    };
    order_xhr.send(JSON.stringify({
        "protected": ORDER['order_protected_b64'],
        "payload": ORDER['order_payload_b64'],
        "signature": ORDER['order_sig'],
    }));
}

/*
 * Step 4a: Sign request for getting an Authorization
 */
function buildAuthorization(n, status, callback){

    // get the authorization from global order
    var auth_url = ORDER['order_response']['authorizations'][n];
    var auth_b64 = b64(auth_url);

    // form fields
    var validate_form = document.getElementById("auth_" + auth_b64 + "_form");
    var validate_cmd = document.getElementById(auth_b64 + "_auth_sig_cmd");
    var validate_input = document.getElementById(auth_b64 + "_auth_sig");
    var validate_submit = document.getElementById("validate_" + auth_b64 + "_auth_sig");

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // hide challenges section until loaded
    var challenges = document.getElementById("challenges_" + auth_b64);
    challenges.style.display = "none";

    // reset finalize signature
    document.getElementById("finalize_sig_cmd").value = "waiting until challenges are done...";
    document.getElementById("finalize_sig_cmd").removeAttribute("readonly");
    document.getElementById("finalize_sig_cmd").setAttribute("disabled", "");
    document.getElementById("finalize_sig").value = "";
    document.getElementById("finalize_sig").setAttribute("placeholder", "waiting until challenges are done...");
    document.getElementById("finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig_status").style.display = "none";
    document.getElementById("validate_finalize_sig_status").className = "";
    document.getElementById("validate_finalize_sig_status").innerHTML = "";

    // reset recheck_order signature
    document.getElementById("recheck_order_sig_cmd").value = "waiting until order is finalized...";
    document.getElementById("recheck_order_sig_cmd").removeAttribute("readonly");
    document.getElementById("recheck_order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("recheck_order_sig").value = "";
    document.getElementById("recheck_order_sig").setAttribute("placeholder", "waiting until order is finalized...");
    document.getElementById("recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig_status").style.display = "none";
    document.getElementById("validate_recheck_order_sig_status").className = "";
    document.getElementById("validate_recheck_order_sig_status").innerHTML = "";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // status update
    status.innerHTML = "loading nonce...";

    // get nonce for loading the authorization request
    getNonce(function(nonce, err){
        if(err){
            return fail(status, "Failed authorization nonce request (auth: " + auth_url + ") (code: " + err.status + "). " + err.responseText);
        }

        // populate authorization request signature (payload is empty "")
        var protected_json = {
            "url": auth_url,
            "alg": ACCOUNT['alg'],
            "nonce": nonce,
            "kid": ACCOUNT['account_uri'],
        };
        var protected_b64 = b64(JSON.stringify(protected_json));
        AUTHORIZATIONS[auth_url]['auth_protected_json'] = protected_json
        AUTHORIZATIONS[auth_url]['auth_protected_b64'] = protected_b64;
        validate_cmd.value = "" +
            "PRIV_KEY=./account.key; " +
            "echo -n \"" + protected_b64 + "." + AUTHORIZATIONS[auth_url]['auth_payload_b64'] + "\" | " +
            "openssl dgst -sha256 -hex -sign $PRIV_KEY";
        validate_cmd.setAttribute("readonly", "");
        validate_cmd.removeAttribute("disabled");
        validate_input.value = "";
        validate_input.setAttribute("placeholder", RESULT_PLACEHOLDER);
        validate_input.removeAttribute("disabled");
        validate_submit.removeAttribute("disabled");

        // set data properties so validateAuthorization() knows which challenge this is
        validate_form.dataset.authurl = auth_url;
        validate_form.addEventListener("submit", validateAuthorization);

        // let the caller know loading the nonce and populating the form is done
        callback();
    });
}


/*
 * Step 4b: Load the Authorization to get its challenges (GET-as-POST /auth['url'])
 */
function validateAuthorization(e){
    e.preventDefault();

    // clear previous status
    var auth_url = e.target.dataset.authurl;
    var auth_b64 = b64(auth_url);
    var status = document.getElementById("validate_" + auth_b64 + "_auth_sig_status");
    var section_id = "auth_" + auth_b64;
    var auth_section = document.getElementById(section_id);
    status.style.display = "inline";
    status.className = "validate_auth_sig_status";
    status.innerHTML = "Loading challenges...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // hide challenges section until re-populated
    var challenges = document.getElementById("challenges_" + auth_b64);
    challenges.style.display = "none";

    // reset finalize signature
    document.getElementById("finalize_sig_cmd").value = "waiting until challenges are done...";
    document.getElementById("finalize_sig_cmd").removeAttribute("readonly");
    document.getElementById("finalize_sig_cmd").setAttribute("disabled", "");
    document.getElementById("finalize_sig").value = "";
    document.getElementById("finalize_sig").setAttribute("placeholder", "waiting until challenges are done...");
    document.getElementById("finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig_status").style.display = "none";
    document.getElementById("validate_finalize_sig_status").className = "";
    document.getElementById("validate_finalize_sig_status").innerHTML = "";

    // reset recheck_order signature
    document.getElementById("recheck_order_sig_cmd").value = "waiting until order is finalized...";
    document.getElementById("recheck_order_sig_cmd").removeAttribute("readonly");
    document.getElementById("recheck_order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("recheck_order_sig").value = "";
    document.getElementById("recheck_order_sig").setAttribute("placeholder", "waiting until order is finalized...");
    document.getElementById("recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig_status").style.display = "none";
    document.getElementById("validate_recheck_order_sig_status").className = "";
    document.getElementById("validate_recheck_order_sig_status").innerHTML = "";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // validate auth payload exists
    if(AUTHORIZATIONS[auth_url]['auth_payload_b64'] === undefined){
        return fail(status, "Update payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var auth_sig = hex2b64(document.getElementById(auth_b64 + "_auth_sig").value);
    if(auth_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    AUTHORIZATIONS[auth_url]['auth_sig'] = auth_sig;

    // send request to CA to get the authorization
    var auth_xhr = new XMLHttpRequest();
    auth_xhr.open("POST", auth_url);
    auth_xhr.setRequestHeader("Content-Type", "application/jose+json");
    auth_xhr.onreadystatechange = function(){
        if(auth_xhr.readyState === 4){

            // successful load
            if(auth_xhr.status === 200){

                // set auth response and uri
                var auth_obj = JSON.parse(auth_xhr.responseText);
                AUTHORIZATIONS[auth_url]['auth_response'] = auth_obj;

                // clear stale challenge objects
                AUTHORIZATIONS[auth_url]['python_challenge_uri'] = undefined;
                AUTHORIZATIONS[auth_url]['python_challenge_object'] = undefined;
                AUTHORIZATIONS[auth_url]['file_challenge_uri'] = undefined;
                AUTHORIZATIONS[auth_url]['file_challenge_object'] = undefined;
                AUTHORIZATIONS[auth_url]['dns_challenge_uri'] = undefined;
                AUTHORIZATIONS[auth_url]['dns_challenge_object'] = undefined;

                // update challenges in global
                var challenge_dicts = AUTHORIZATIONS[auth_url]['auth_response']['challenges'];
                for(var i = 0; i < challenge_dicts.length; i++){
                    var challenge_dict = challenge_dicts[i];

                    // HTTP challenge
                    if(challenge_dict['type'] === "http-01"){
                        AUTHORIZATIONS[auth_url]['python_challenge_uri'] = challenge_dict['url'];
                        AUTHORIZATIONS[auth_url]['python_challenge_object'] = challenge_dict;
                        AUTHORIZATIONS[auth_url]['file_challenge_uri'] = challenge_dict['url'];
                        AUTHORIZATIONS[auth_url]['file_challenge_object'] = challenge_dict;
                    }

                    // DNS challenge
                    if(challenge_dict['type'] === "dns-01"){
                        AUTHORIZATIONS[auth_url]['dns_challenge_uri'] = challenge_dict['url'];
                        AUTHORIZATIONS[auth_url]['dns_challenge_object'] = challenge_dict;
                    }
                }

                // figure out which domain this authorization is checking
                var domain = auth_obj['identifier']['value']; // domain name (e.g. foo.com)

                // domain name
                challenges.querySelector(".domain").innerHTML = "";
                challenges.querySelector(".domain").appendChild(document.createTextNode(auth_obj['wildcard'] ? "*." + domain : domain));

                // tabs
                challenges.querySelector("input.challenge_python").setAttribute("name", "radio_" + auth_b64);
                challenges.querySelector("input.challenge_python").setAttribute("id", "radio_" + auth_b64 + "_python");
                challenges.querySelector("label.challenge_python").setAttribute("for", "radio_" + auth_b64 + "_python");
                challenges.querySelector("label.challenge_python").style.display = "none";
                challenges.querySelector("input.challenge_file").setAttribute("name", "radio_" + auth_b64);
                challenges.querySelector("input.challenge_file").setAttribute("id", "radio_" + auth_b64 + "_file");
                challenges.querySelector("label.challenge_file").setAttribute("for", "radio_" + auth_b64 + "_file");
                challenges.querySelector("label.challenge_file").style.display = "none";
                challenges.querySelector("input.challenge_dns").setAttribute("name", "radio_" + auth_b64);
                challenges.querySelector("input.challenge_dns").setAttribute("id", "radio_" + auth_b64 + "_dns");
                challenges.querySelector("label.challenge_dns").setAttribute("for", "radio_" + auth_b64 + "_dns");
                challenges.querySelector("label.challenge_dns").style.display = "none";

                // help texts
                challenges.querySelector(".howto_python").setAttribute("id", "howto_" + auth_b64 + "_python");
                challenges.querySelector(".howto_python_label").setAttribute("for", "howto_" + auth_b64 + "_python");
                challenges.querySelector(".howto_python_sig").setAttribute("id", "howto_" + auth_b64 + "_python_sig");
                challenges.querySelector(".howto_python_sig_label").setAttribute("for", "howto_" + auth_b64 + "_python_sig");
                challenges.querySelector(".howto_recheck_auth_python_sig").setAttribute("id", "howto_" + auth_b64 + "_recheck_auth_python_sig");
                challenges.querySelector(".howto_recheck_auth_python_sig_label").setAttribute("for", "howto_" + auth_b64 + "_recheck_auth_python_sig");
                challenges.querySelector(".howto_file").setAttribute("id", "howto_" + auth_b64 + "_file");
                challenges.querySelector(".howto_file_label").setAttribute("for", "howto_" + auth_b64 + "_file");
                challenges.querySelector(".howto_file_sig").setAttribute("id", "howto_" + auth_b64 + "_file_sig");
                challenges.querySelector(".howto_file_sig_label").setAttribute("for", "howto_" + auth_b64 + "_file_sig");
                challenges.querySelector(".howto_recheck_auth_file_sig").setAttribute("id", "howto_" + auth_b64 + "_recheck_auth_file_sig");
                challenges.querySelector(".howto_recheck_auth_file_sig_label").setAttribute("for", "howto_" + auth_b64 + "_recheck_auth_file_sig");
                challenges.querySelector(".howto_dns").setAttribute("id", "howto_" + auth_b64 + "_dns");
                challenges.querySelector(".howto_dns_label").setAttribute("for", "howto_" + auth_b64 + "_dns");
                challenges.querySelector(".howto_dns_sig").setAttribute("id", "howto_" + auth_b64 + "_dns_sig");
                challenges.querySelector(".howto_dns_sig_label").setAttribute("for", "howto_" + auth_b64 + "_dns_sig");
                challenges.querySelector(".howto_recheck_auth_dns_sig").setAttribute("id", "howto_" + auth_b64 + "_recheck_auth_dns_sig");
                challenges.querySelector(".howto_recheck_auth_dns_sig_label").setAttribute("for", "howto_" + auth_b64 + "_recheck_auth_dns_sig");

                // event listeners
                challenges.querySelector(".confirm_python").addEventListener("submit", confirmChallenge);
                challenges.querySelector(".confirm_file").addEventListener("submit", confirmChallenge);
                challenges.querySelector(".confirm_dns").addEventListener("submit", confirmChallenge);
                challenges.querySelector(".validate_python_sig").addEventListener("submit", validateChallenge);
                challenges.querySelector(".validate_file_sig").addEventListener("submit", validateChallenge);
                challenges.querySelector(".validate_dns_sig").addEventListener("submit", validateChallenge);
                challenges.querySelector(".validate_recheck_auth_python_sig").addEventListener("submit", checkAuthorization);
                challenges.querySelector(".validate_recheck_auth_file_sig").addEventListener("submit", checkAuthorization);
                challenges.querySelector(".validate_recheck_auth_dns_sig").addEventListener("submit", checkAuthorization);

                // python option data
                if(AUTHORIZATIONS[auth_url]['python_challenge_object'] !== undefined){

                    // populate values
                    var token = AUTHORIZATIONS[auth_url]['python_challenge_object']['token'];
                    var keyauth = token + "." + ACCOUNT['thumbprint'];
                    var link = "http://" + domain + "/.well-known/acme-challenge/" + token;
                    challenges.querySelector(".python_link").innerHTML = "";
                    challenges.querySelector(".python_link").appendChild(document.createTextNode(link));
                    challenges.querySelector(".python_link").setAttribute("href", link);
                    challenges.querySelector(".python_domain").innerHTML = "";
                    challenges.querySelector(".python_domain").appendChild(document.createTextNode(domain));
                    challenges.querySelector(".python_server").value = "" +
                        "sudo python2 -c \"import BaseHTTPServer; \\\n" +
                        "    h = BaseHTTPServer.BaseHTTPRequestHandler; \\\n" +
                        "    h.do_GET = lambda r: r.send_response(200) or r.end_headers() " +
                                "or r.wfile.write('" + keyauth + "'); \\\n" +
                        "    s = BaseHTTPServer.HTTPServer(('0.0.0.0', 80), h); \\\n" +
                        "    s.serve_forever()\"";
                    challenges.querySelector(".confirm_python_submit").value = "I'm now running this command on " + domain;
                    challenges.querySelector(".validate_python_sig_submit").value = "Submit challenge for " + domain;
                    challenges.querySelector("label.challenge_python").style.display = "inline-block";

                    // set data attributes
                    var challenge_url = AUTHORIZATIONS[auth_url]['python_challenge_object']['url'];
                    challenges.querySelector(".confirm_python").dataset.option = "python";
                    challenges.querySelector(".confirm_python").dataset.section = section_id;
                    challenges.querySelector(".confirm_python").dataset.auth = auth_url;
                    challenges.querySelector(".confirm_python").dataset.challenge = challenge_url;
                }

                // file-based option data
                if(AUTHORIZATIONS[auth_url]['file_challenge_object'] !== undefined){

                    // populate values
                    var token = AUTHORIZATIONS[auth_url]['file_challenge_object']['token'];

                    var keyauth = token + "." + ACCOUNT['thumbprint'];
                    var link = "http://" + domain + "/.well-known/acme-challenge/" + token;
                    var server_config = "" +
                        "#nginx example\n" +
                        "location /.well-known/acme-challenge/ {\n" +
                        "    alias /path/to/www/;\n" +
                        "    try_files $uri =404;\n" +
                        "}\n\n" +
                        "#apache example\n" +
                        "Alias /.well-known/acme-challenge /path/to/www/.well-known/acme-challenge";
                    var echo = "echo -n \"" + keyauth + "\" > /path/to/www/.well-known/acme-challenge/" + token;
                    challenges.querySelector(".file_config").innerHTML = "";
                    challenges.querySelector(".file_config").appendChild(document.createTextNode(server_config));
                    challenges.querySelector(".file_echo").innerHTML = "";
                    challenges.querySelector(".file_echo").appendChild(document.createTextNode(echo));
                    challenges.querySelector(".file_link").innerHTML = "";
                    challenges.querySelector(".file_link").appendChild(document.createTextNode(link));
                    challenges.querySelector(".file_link").setAttribute("href", link);
                    challenges.querySelector(".file_url").value = link;
                    challenges.querySelector(".file_data").value = keyauth;
                    challenges.querySelector(".confirm_file_submit").value = "I'm now serving this file on " + domain;
                    challenges.querySelector(".validate_file_sig_submit").value = "Submit challenge for " + domain;
                    challenges.querySelector("label.challenge_file").style.display = "inline-block";

                    // set data attributes
                    var challenge_url = AUTHORIZATIONS[auth_url]['file_challenge_object']['url'];
                    challenges.querySelector(".confirm_file").dataset.option = "file";
                    challenges.querySelector(".confirm_file").dataset.section = section_id;
                    challenges.querySelector(".confirm_file").dataset.auth = auth_url;
                    challenges.querySelector(".confirm_file").dataset.challenge = challenge_url;
                }

                // DNS option data
                if(AUTHORIZATIONS[auth_url]['dns_challenge_object'] !== undefined){

                    // SHA-256 digest of keyauth
                    var token = AUTHORIZATIONS[auth_url]['dns_challenge_object']['token'];
                    var keyauth = token + "." + ACCOUNT['thumbprint'];
                    var keyauth_bytes = [];
                    for(var i = 0; i < keyauth.length; i++){
                        keyauth_bytes.push(keyauth.charCodeAt(i));
                    }
                    sha256(new Uint8Array(keyauth_bytes), function(hash, err){
                        if(err){
                            return fail(status, "Generating DNS data failed: " + err.message);
                        }
                        var dns_data = b64(hash);

                        // populate dns option
                        var dig = "dig +short @ns.yournameserver.com _acme-challenge." + domain + " TXT";
                        challenges.querySelector(".dns_dig").innerHTML = "";
                        challenges.querySelector(".dns_dig").appendChild(document.createTextNode(dig));
                        challenges.querySelector(".dns_domain").innerHTML = "";
                        challenges.querySelector(".dns_domain").appendChild(document.createTextNode(domain));
                        challenges.querySelector(".dns_value").innerHTML = "";
                        challenges.querySelector(".dns_value").appendChild(document.createTextNode(dns_data));
                        challenges.querySelector(".dns_subdomain").value = "_acme-challenge." + domain;
                        challenges.querySelector(".dns_data").value = dns_data;
                        challenges.querySelector(".confirm_dns_submit").value = "I can see the TXT record for " + domain;
                        challenges.querySelector(".validate_dns_sig_submit").value = "Submit challenge for " + domain;
                        challenges.querySelector("label.challenge_dns").style.display = "inline-block";

                        // data attributes
                        var challenge_url = AUTHORIZATIONS[auth_url]['dns_challenge_object']['url'];
                        challenges.querySelector(".confirm_dns").dataset.option = "dns";
                        challenges.querySelector(".confirm_dns").dataset.section = section_id;
                        challenges.querySelector(".confirm_dns").dataset.auth = auth_url;
                        challenges.querySelector(".confirm_dns").dataset.challenge = challenge_url;

                        // auto-select Option 3 if no other options
                        if(AUTHORIZATIONS[auth_url]['python_challenge_object'] === undefined
                        && AUTHORIZATIONS[auth_url]['file_challenge_object'] === undefined){
                            challenges.querySelector("input.challenge_python").removeAttribute("checked");
                            challenges.querySelector("input.challenge_dns").setAttribute("checked", "");
                            challenges.querySelector("label.challenge_dns").innerHTML = "Option 1 - DNS record (wildcard)";
                        }

                        // show the challenges
                        status.innerHTML = "Challenges loaded! Choose a challenge option below.";
                        challenges.style.display = "block";
                        auth_section.querySelector(".challenges-status").style.display = "none";
                    });
                }

                // no DNS option, so show the challenges without hashing anything
                else{
                    // show the challenges
                    status.innerHTML = "Challenges loaded! Choose a challenge option below.";
                    challenges.style.display = "block";
                    auth_section.querySelector(".challenges-status").style.display = "none";
                }
            }

            // error loading authorization
            else{
                return fail(status, "Loading challenges failed. Please start back at Step 1. " + auth_xhr.responseText);
            }
        }
    };
    auth_xhr.send(JSON.stringify({
        "protected": AUTHORIZATIONS[auth_url]['auth_protected_b64'],
        "payload": AUTHORIZATIONS[auth_url]['auth_payload_b64'],
        "signature": AUTHORIZATIONS[auth_url]['auth_sig'],
    }));
}


/*
 * Step 4c: Confirm Challenge
 */
function confirmChallenge(e){
    e.preventDefault();

    // find the relevant resources
    var section_id = e.target.dataset.section; // auth_...
    var option = e.target.dataset.option; // "python", "file", or "dns"
    var auth_url = e.target.dataset.auth;
    var domain = AUTHORIZATIONS[auth_url]['auth_response']['identifier']['value'];
    var challenge_url = e.target.dataset.challenge;
    var section = document.getElementById(section_id);
    var status = section.querySelector(".confirm_" + option + "_status");
    var validate_form = section.querySelector(".validate_" + option + "_sig");
    var validate_submit = section.querySelector(".validate_" + option + "_sig_submit");
    var validate_cmd = section.querySelector("." + option + "_sig_cmd");
    var validate_input = section.querySelector("." + option + "_sig");
    var validate_status_class = option + "_sig_status"
    var validate_status = section.querySelector("." + validate_status_class);

    // clear previous status
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "confirming...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset validate challenge signature
    validate_cmd.value = "waiting until confirmation is done...";
    validate_cmd.removeAttribute("readonly");
    validate_cmd.setAttribute("disabled", "");
    validate_input.value = "";
    validate_input.setAttribute("placeholder", "waiting until confirmation is done...");
    validate_input.setAttribute("disabled", "");
    validate_submit.setAttribute("disabled", "");
    validate_status.style.display = "none";
    validate_status.className = validate_status_class;
    validate_status.innerHTML = "";

    // reset authorization check signature
    section.querySelector(".recheck_auth_" + option + "_sig_cmd").value = "waiting until you submit the challenge above...";
    section.querySelector(".recheck_auth_" + option + "_sig_cmd").removeAttribute("readonly");
    section.querySelector(".recheck_auth_" + option + "_sig_cmd").setAttribute("disabled", "");
    section.querySelector(".recheck_auth_" + option + "_sig").value = "";
    section.querySelector(".recheck_auth_" + option + "_sig").setAttribute("placeholder", "waiting until challenges are done...");
    section.querySelector(".recheck_auth_" + option + "_sig").setAttribute("disabled", "");
    section.querySelector(".validate_recheck_auth_" + option + "_sig_submit").setAttribute("disabled", "");
    section.querySelector(".validate_recheck_auth_" + option + "_sig_status").style.display = "none";
    section.querySelector(".validate_recheck_auth_" + option + "_sig_status").className = "validate_recheck_auth_" + option + "_sig_status";
    section.querySelector(".validate_recheck_auth_" + option + "_sig_status").innerHTML = "";

    // reset finalize signature
    document.getElementById("finalize_sig_cmd").value = "waiting until challenges are done...";
    document.getElementById("finalize_sig_cmd").removeAttribute("readonly");
    document.getElementById("finalize_sig_cmd").setAttribute("disabled", "");
    document.getElementById("finalize_sig").value = "";
    document.getElementById("finalize_sig").setAttribute("placeholder", "waiting until challenges are done...");
    document.getElementById("finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig_status").style.display = "none";
    document.getElementById("validate_finalize_sig_status").className = "";
    document.getElementById("validate_finalize_sig_status").innerHTML = "";

    // reset recheck_order signature
    document.getElementById("recheck_order_sig_cmd").value = "waiting until order is finalized...";
    document.getElementById("recheck_order_sig_cmd").removeAttribute("readonly");
    document.getElementById("recheck_order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("recheck_order_sig").value = "";
    document.getElementById("recheck_order_sig").setAttribute("placeholder", "waiting until order is finalized...");
    document.getElementById("recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig_status").style.display = "none";
    document.getElementById("validate_recheck_order_sig_status").className = "";
    document.getElementById("validate_recheck_order_sig_status").innerHTML = "";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // get nonce for challenge
    getNonce(function(nonce, err){
        if(err){
            return fail(status, "Failed challenge nonce request (domain: " + domain + ") (code: " + err.status + "). " + err.responseText);
        }

        // populate challenge signature (payload is empty {})
        var protected_json = {
            "url": challenge_url,
            "alg": ACCOUNT['alg'],
            "nonce": nonce,
            "kid": ACCOUNT['account_uri'],
        };
        var protected_b64 = b64(JSON.stringify(protected_json));
        AUTHORIZATIONS[auth_url][option + '_protected_json'] = protected_json
        AUTHORIZATIONS[auth_url][option + '_protected_b64'] = protected_b64;
        validate_cmd.value = "" +
            "PRIV_KEY=./account.key; " +
            "echo -n \"" + protected_b64 + "." + b64(JSON.stringify({})) + "\" | " +
            "openssl dgst -sha256 -hex -sign $PRIV_KEY";
        validate_cmd.setAttribute("readonly", "");
        validate_cmd.removeAttribute("disabled");
        validate_input.value = "";
        validate_input.setAttribute("placeholder", RESULT_PLACEHOLDER);
        validate_input.removeAttribute("disabled");
        validate_submit.removeAttribute("disabled");

        // set data properties so validateChallenge() knows which challenge this is
        validate_form.dataset.option = option;
        validate_form.dataset.section = section_id;
        validate_form.dataset.auth = auth_url;
        validate_form.dataset.challenge = challenge_url;

        // complete step 4a
        status.innerHTML = "Ready for the next command!";
    });
}

/*
 * Step 4d: Verify Ownership (POST /challenge['url'], ...)
 */
function validateChallenge(e){
    e.preventDefault();

    // find the relevant resources
    var section_id = e.target.dataset.section; // auth_...
    var option = e.target.dataset.option; // "python", "file", or "dns"
    var auth_url = e.target.dataset.auth;
    var domain = AUTHORIZATIONS[auth_url]['auth_response']['identifier']['value'];
    var challenge_url = e.target.dataset.challenge;
    var section = document.getElementById(section_id);
    var status_class = option + "_sig_status";
    var status = section.querySelector("." + status_class);
    var sig_input = section.querySelector("." + option + "_sig");
    var recheck_form = section.querySelector(".validate_recheck_auth_" + option + "_sig");
    var recheck_submit = section.querySelector(".validate_recheck_auth_" + option + "_sig_submit");
    var recheck_cmd = section.querySelector(".recheck_auth_" + option + "_sig_cmd");
    var recheck_input = section.querySelector(".recheck_auth_" + option + "_sig");
    var recheck_status_class = "validate_recheck_auth_" + option + "_sig_status";
    var recheck_status = section.querySelector("." + recheck_status_class);

    // clear previous status
    status.style.display = "inline";
    status.className = status_class;
    status.innerHTML = "submitting...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset authorization check signature
    section.querySelector(".recheck_auth_" + option + "_sig_cmd").value = "waiting until you submit the challenge above...";
    section.querySelector(".recheck_auth_" + option + "_sig_cmd").removeAttribute("readonly");
    section.querySelector(".recheck_auth_" + option + "_sig_cmd").setAttribute("disabled", "");
    section.querySelector(".recheck_auth_" + option + "_sig").value = "";
    section.querySelector(".recheck_auth_" + option + "_sig").setAttribute("placeholder", "waiting until challenges are done...");
    section.querySelector(".recheck_auth_" + option + "_sig").setAttribute("disabled", "");
    section.querySelector(".validate_recheck_auth_" + option + "_sig_submit").setAttribute("disabled", "");
    section.querySelector(".validate_recheck_auth_" + option + "_sig_status").style.display = "none";
    section.querySelector(".validate_recheck_auth_" + option + "_sig_status").className = recheck_status_class;
    section.querySelector(".validate_recheck_auth_" + option + "_sig_status").innerHTML = "";

    // reset finalize signature
    document.getElementById("finalize_sig_cmd").value = "waiting until challenges are done...";
    document.getElementById("finalize_sig_cmd").removeAttribute("readonly");
    document.getElementById("finalize_sig_cmd").setAttribute("disabled", "");
    document.getElementById("finalize_sig").value = "";
    document.getElementById("finalize_sig").setAttribute("placeholder", "waiting until challenges are done...");
    document.getElementById("finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig_status").style.display = "none";
    document.getElementById("validate_finalize_sig_status").className = "";
    document.getElementById("validate_finalize_sig_status").innerHTML = "";

    // reset recheck_order signature
    document.getElementById("recheck_order_sig_cmd").value = "waiting until order is finalized...";
    document.getElementById("recheck_order_sig_cmd").removeAttribute("readonly");
    document.getElementById("recheck_order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("recheck_order_sig").value = "";
    document.getElementById("recheck_order_sig").setAttribute("placeholder", "waiting until order is finalized...");
    document.getElementById("recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig_status").style.display = "none";
    document.getElementById("validate_recheck_order_sig_status").className = "";
    document.getElementById("validate_recheck_order_sig_status").innerHTML = "";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // validate challenge protected exists
    if(AUTHORIZATIONS[auth_url][option + '_protected_b64'] === undefined){
        return fail(status, "Update payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var challenge_sig = hex2b64(sig_input.value);
    if(challenge_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    AUTHORIZATIONS[auth_url][option + '_challenge_sig'] = challenge_sig;

    // submit challenge to CA
    var challenge_xhr = new XMLHttpRequest();
    challenge_xhr.open("POST", challenge_url);
    challenge_xhr.setRequestHeader("Content-Type", "application/jose+json");
    challenge_xhr.onreadystatechange = function(){
        if(challenge_xhr.readyState === 4){

            // successful challenge submission
            if(challenge_xhr.status === 200){

                // set challenge response
                AUTHORIZATIONS[auth_url][option + '_challenge_response'] = JSON.parse(challenge_xhr.responseText);

                // update status message before loading nonce
                status.innerHTML = "Submitted! Loading next step...";

                // get nonce for checking the authorization status
                getNonce(function(nonce, err){
                    if(err){
                        return fail(status, "Failed challenge verify nonce request (domain: " + domain + ") (code: " + err.status + "). " + err.responseText);
                    }

                    // populate authorization request signature (payload is empty "")
                    var protected_json = {
                        "url": auth_url,
                        "alg": ACCOUNT['alg'],
                        "nonce": nonce,
                        "kid": ACCOUNT['account_uri'],
                    };
                    var protected_b64 = b64(JSON.stringify(protected_json));
                    AUTHORIZATIONS[auth_url]['recheck_auth_protected_json'] = protected_json
                    AUTHORIZATIONS[auth_url]['recheck_auth_protected_b64'] = protected_b64;
                    recheck_cmd.value = "" +
                        "PRIV_KEY=./account.key; " +
                        "echo -n \"" + protected_b64 + "." + AUTHORIZATIONS[auth_url]['recheck_auth_payload_b64'] + "\" | " +
                        "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                    recheck_cmd.setAttribute("readonly", "");
                    recheck_cmd.removeAttribute("disabled");
                    recheck_input.value = "";
                    recheck_input.setAttribute("placeholder", RESULT_PLACEHOLDER);
                    recheck_input.removeAttribute("disabled");
                    recheck_submit.removeAttribute("disabled");

                    // set data properties so checkAuthorization() knows which auth this is
                    recheck_form.dataset.option = option;
                    recheck_form.dataset.section = section_id;
                    recheck_form.dataset.auth = auth_url;

                    // update status
                    status.innerHTML = "Challenge submitted! Proceed to next command below.";
                });
            }

            // error submitting challenge
            else{
                return fail(status, "Challenge submission failed. Please start back at Step 1. " + challenge_xhr.responseText);
            }
        }
    };
    challenge_xhr.send(JSON.stringify({
        "protected": AUTHORIZATIONS[auth_url][option + '_protected_b64'],
        "payload": b64(JSON.stringify({})), // always empty payload
        "signature": AUTHORIZATIONS[auth_url][option + '_challenge_sig'],
    }));
}

/*
 * Step 4e: Check authorization status after submitting the challenge (GET-as-POST /auth['url'])
 */
function checkAuthorization(e){
    e.preventDefault();

    // find the relevant resources
    var section_id = e.target.dataset.section; // auth_...
    var option = e.target.dataset.option; // "python", "file", or "dns"
    var auth_url = e.target.dataset.auth;
    var domain = AUTHORIZATIONS[auth_url]['auth_response']['identifier']['value'];
    var section = document.getElementById(section_id);
    var status_class = "validate_recheck_auth_" + option + "_sig_status";
    var status = section.querySelector("." + status_class);
    var sig_input = section.querySelector(".recheck_auth_" + option + "_sig");
    var recheck_submit = section.querySelector(".validate_recheck_auth_" + option + "_sig_submit");
    var recheck_cmd = section.querySelector(".recheck_auth_" + option + "_sig_cmd");
    var recheck_input = section.querySelector(".recheck_auth_" + option + "_sig");

    // clear previous status
    status.style.display = "inline";
    status.className = status_class;
    status.innerHTML = "checking...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset finalize signature
    document.getElementById("finalize_sig_cmd").value = "waiting until challenges are done...";
    document.getElementById("finalize_sig_cmd").removeAttribute("readonly");
    document.getElementById("finalize_sig_cmd").setAttribute("disabled", "");
    document.getElementById("finalize_sig").value = "";
    document.getElementById("finalize_sig").setAttribute("placeholder", "waiting until challenges are done...");
    document.getElementById("finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig").setAttribute("disabled", "");
    document.getElementById("validate_finalize_sig_status").style.display = "none";
    document.getElementById("validate_finalize_sig_status").className = "";
    document.getElementById("validate_finalize_sig_status").innerHTML = "";

    // reset recheck_order signature
    document.getElementById("recheck_order_sig_cmd").value = "waiting until order is finalized...";
    document.getElementById("recheck_order_sig_cmd").removeAttribute("readonly");
    document.getElementById("recheck_order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("recheck_order_sig").value = "";
    document.getElementById("recheck_order_sig").setAttribute("placeholder", "waiting until order is finalized...");
    document.getElementById("recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig_status").style.display = "none";
    document.getElementById("validate_recheck_order_sig_status").className = "";
    document.getElementById("validate_recheck_order_sig_status").innerHTML = "";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // validate recheck_auth protected exists
    if(AUTHORIZATIONS[auth_url]['recheck_auth_protected_b64'] === undefined){
        return fail(status, "Status check payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var recheck_auth_sig = hex2b64(sig_input.value);
    if(recheck_auth_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    AUTHORIZATIONS[auth_url]['recheck_auth_sig'] = recheck_auth_sig;

    // send request to CA to get the authorization
    var recheck_auth_xhr = new XMLHttpRequest();
    recheck_auth_xhr.open("POST", auth_url);
    recheck_auth_xhr.setRequestHeader("Content-Type", "application/jose+json");
    recheck_auth_xhr.onreadystatechange = function(){
        if(recheck_auth_xhr.readyState === 4){

            // successful load
            if(recheck_auth_xhr.status === 200){

                // set recheck_auth response
                var auth_obj = JSON.parse(recheck_auth_xhr.responseText);
                AUTHORIZATIONS[auth_url]['recheck_auth_response'] = auth_obj;

                // authorization pending, so ask the user to check again
                if(auth_obj['status'] === "pending"){

                    // update the status before getting another nonce
                    status.innerHTML = "loading...";

                    // clear the existing signature
                    AUTHORIZATIONS[auth_url]['recheck_auth_sig'] = undefined;

                    // get nonce for checking the authorization status, again
                    getNonce(function(nonce, err){
                        if(err){
                            return fail(status, "Failed status nonce request (domain: " + domain + ") (code: " + err.status + "). " + err.responseText);
                        }

                        // populate authorization request signature (payload is empty "")
                        var protected_json = {
                            "url": auth_url,
                            "alg": ACCOUNT['alg'],
                            "nonce": nonce,
                            "kid": ACCOUNT['account_uri'],
                        };
                        var protected_b64 = b64(JSON.stringify(protected_json));
                        AUTHORIZATIONS[auth_url]['recheck_auth_protected_json'] = protected_json
                        AUTHORIZATIONS[auth_url]['recheck_auth_protected_b64'] = protected_b64;
                        recheck_cmd.value = "" +
                            "PRIV_KEY=./account.key; " +
                            "echo -n \"" + protected_b64 + "." + AUTHORIZATIONS[auth_url]['recheck_auth_payload_b64'] + "\" | " +
                            "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                        recheck_cmd.setAttribute("readonly", "");
                        recheck_cmd.removeAttribute("disabled");
                        recheck_input.value = "";
                        recheck_input.setAttribute("placeholder", RESULT_PLACEHOLDER);
                        recheck_input.removeAttribute("disabled");
                        recheck_submit.removeAttribute("disabled");

                        // update status
                        status.innerHTML = "Challenge still pending. Copy and run the command again to check again.";
                    });
                }

                // authorization valid, so proceed to next set of challenges or finalize
                else if(auth_obj['status'] === "valid"){

                    // find the next authorization that doesn't have a recheck status
                    var next_auth_i = undefined;
                    for(var i = 0; i < ORDER['order_response']['authorizations'].length; i++){
                        var a_url = ORDER['order_response']['authorizations'][i];
                        if(AUTHORIZATIONS[a_url]['recheck_auth_response'] === undefined){
                            next_auth_i = i;
                            break;
                        }
                    }

                    // load the next authorization command
                    if(next_auth_i !== undefined){
                        buildAuthorization(next_auth_i, status, function(){
                            status.innerHTML = "Challenge complete! Proceed to load next set of challenges.";
                        });
                    }

                    // all authorizations done! so finalize the order
                    else{
                        status.innerHTML = "loading nonce...";

                        // get nonce for finalizing
                        getNonce(function(nonce, err){
                            if(err){
                                return fail(status, "Failed finalize nonce request (code: " + err.status + "). " + err.responseText);
                            }

                            // populate order finalize signature (payload populated in validateCSR())
                            ORDER['finalize_protected_json'] = {
                                "url": ORDER['finalize_uri'],
                                "alg": ACCOUNT['alg'],
                                "nonce": nonce,
                                "kid": ACCOUNT['account_uri'],
                            }
                            ORDER['finalize_protected_b64'] = b64(JSON.stringify(ORDER['finalize_protected_json']));
                            document.getElementById("finalize_sig_cmd").value = "" +
                                "PRIV_KEY=./account.key; " +
                                "echo -n \"" + ORDER['finalize_protected_b64'] + "." + ORDER['finalize_payload_b64'] + "\" | " +
                                "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                            document.getElementById("finalize_sig_cmd").setAttribute("readonly", "");
                            document.getElementById("finalize_sig_cmd").removeAttribute("disabled");
                            document.getElementById("finalize_sig").value = "";
                            document.getElementById("finalize_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);
                            document.getElementById("finalize_sig").removeAttribute("disabled");
                            document.getElementById("validate_finalize_sig").removeAttribute("disabled");

                            // proceed finalize order
                            status.innerHTML = "Challenge complete! Proceed to finalize certificate order.";
                        });
                    }
                }

                // authorization failed, so show an error
                else{
                    return fail(status, "Domain challenge failed. Please start back at Step 1. " + JSON.stringify(auth_obj));
                }
            }
            // error loading authorization
            else{
                return fail(status, "Loading challenge status failed. Please start back at Step 1. " + recheck_auth_xhr.responseText);
            }
        }
    };
    recheck_auth_xhr.send(JSON.stringify({
        "protected": AUTHORIZATIONS[auth_url]['recheck_auth_protected_b64'],
        "payload": AUTHORIZATIONS[auth_url]['recheck_auth_payload_b64'],
        "signature": AUTHORIZATIONS[auth_url]['recheck_auth_sig'],
    }));

}

/*
 * Step 4f: Issue Certificate (POST /order['finalize'])
 */
function validateFinalize(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_finalize_sig_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "finalizing...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset recheck_order signature
    document.getElementById("recheck_order_sig_cmd").value = "waiting until order is finalized...";
    document.getElementById("recheck_order_sig_cmd").removeAttribute("readonly");
    document.getElementById("recheck_order_sig_cmd").setAttribute("disabled", "");
    document.getElementById("recheck_order_sig").value = "";
    document.getElementById("recheck_order_sig").setAttribute("placeholder", "waiting until order is finalized...");
    document.getElementById("recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig").setAttribute("disabled", "");
    document.getElementById("validate_recheck_order_sig_status").style.display = "none";
    document.getElementById("validate_recheck_order_sig_status").className = "";
    document.getElementById("validate_recheck_order_sig_status").innerHTML = "";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // validate registration payload exists
    if(ORDER['finalize_payload_b64'] === undefined){
        return fail(status, "Finalize payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var finalize_sig = hex2b64(document.getElementById("finalize_sig").value);
    if(finalize_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ORDER['finalize_sig'] = finalize_sig;

    // send update request to CA finalize_uri
    var finalize_xhr = new XMLHttpRequest();
    finalize_xhr.open("POST", ORDER['finalize_uri']);
    finalize_xhr.setRequestHeader("Content-Type", "application/jose+json");
    finalize_xhr.onreadystatechange = function(){
        if(finalize_xhr.readyState === 4){

            // successful finalizing the order
            if(finalize_xhr.status === 200){

                // set finalize response
                ORDER['finalize_response'] = JSON.parse(finalize_xhr.responseText);

                // get nonce for rechecking the order
                getNonce(function(nonce, err){
                    if(err){
                        return fail(status, "Failed order checking nonce request (code: " + err.status + "). " + err.responseText);
                    }

                    // populate recheck_order signature
                    ORDER['recheck_order_protected_json'] = {
                        "url": ORDER['order_uri'],
                        "alg": ACCOUNT['alg'],
                        "nonce": nonce,
                        "kid": ACCOUNT['account_uri'],
                    }
                    ORDER['recheck_order_protected_b64'] = b64(JSON.stringify(ORDER['recheck_order_protected_json']));
                    document.getElementById("recheck_order_sig_cmd").value = "" +
                        "PRIV_KEY=./account.key; " +
                        "echo -n \"" + ORDER['recheck_order_protected_b64'] + "." + ORDER['recheck_order_payload_b64'] + "\" | " +
                        "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                    document.getElementById("recheck_order_sig_cmd").setAttribute("readonly", "");
                    document.getElementById("recheck_order_sig_cmd").removeAttribute("disabled");
                    document.getElementById("recheck_order_sig").value = "";
                    document.getElementById("recheck_order_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);
                    document.getElementById("recheck_order_sig").removeAttribute("disabled");
                    document.getElementById("validate_recheck_order_sig").removeAttribute("disabled");

                    // complete step 4f
                    status.innerHTML = "Finalized! Proceed to next command below.";
                });
            }

            // error registering
            else{
                return fail(status, "Finalizing failed. Please start back at Step 1. " + finalize_xhr.responseText);
            }
        }
    };
    finalize_xhr.send(JSON.stringify({
        "protected": ORDER['finalize_protected_b64'],
        "payload": ORDER['finalize_payload_b64'],
        "signature": ORDER['finalize_sig'],
    }));
}

/*
 * Step 4g: Check Order Status (GET-as-POST /order['order_uri'])
 */
function recheckOrder(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_recheck_order_sig_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "checking status...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // reset get cert signature
    document.getElementById("cert_sig_cmd").value = "waiting until certificate is generated...";
    document.getElementById("cert_sig_cmd").removeAttribute("readonly");
    document.getElementById("cert_sig_cmd").setAttribute("disabled", "");
    document.getElementById("cert_sig").value = "";
    document.getElementById("cert_sig").setAttribute("placeholder", "waiting until certificate is generated...");
    document.getElementById("cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig").setAttribute("disabled", "");
    document.getElementById("validate_cert_sig_status").style.display = "none";
    document.getElementById("validate_cert_sig_status").className = "";
    document.getElementById("validate_cert_sig_status").innerHTML = "";

    // validate registration payload exists
    if(ORDER['recheck_order_payload_b64'] === undefined){
        return fail(status, "Order checking payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var recheck_order_sig = hex2b64(document.getElementById("recheck_order_sig").value);
    if(recheck_order_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ORDER['recheck_order_sig'] = recheck_order_sig;

    // send update request to CA finalize_uri
    var recheck_order_xhr = new XMLHttpRequest();
    recheck_order_xhr.open("POST", ORDER['order_uri']);
    recheck_order_xhr.setRequestHeader("Content-Type", "application/jose+json");
    recheck_order_xhr.onreadystatechange = function(){
        if(recheck_order_xhr.readyState === 4){

            // successful finalizing the order
            if(recheck_order_xhr.status === 200){

                // set recheck_order response
                var order = JSON.parse(recheck_order_xhr.responseText)
                ORDER['recheck_order_response'] = order;

                // order still processing
                if(order['status'] === "pending" || order['status'] === "processing" || order['status'] === "ready"){

                    // update the status before getting another nonce
                    status.innerHTML = "processing...";

                    // clear the existing signature
                    ORDER['recheck_order_sig'] = undefined;

                    // get nonce for checking the order status, again
                    getNonce(function(nonce, err){
                        if(err){
                            return fail(status, "Failed order status nonce request (code: " + err.status + "). " + err.responseText);
                        }

                        // populate recheck_order signature
                        ORDER['recheck_order_protected_json'] = {
                            "url": ORDER['order_uri'],
                            "alg": ACCOUNT['alg'],
                            "nonce": nonce,
                            "kid": ACCOUNT['account_uri'],
                        }
                        ORDER['recheck_order_protected_b64'] = b64(JSON.stringify(ORDER['recheck_order_protected_json']));
                        document.getElementById("recheck_order_sig_cmd").value = "" +
                            "PRIV_KEY=./account.key; " +
                            "echo -n \"" + ORDER['recheck_order_protected_b64'] + "." + ORDER['recheck_order_payload_b64'] + "\" | " +
                            "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                        document.getElementById("recheck_order_sig_cmd").setAttribute("readonly", "");
                        document.getElementById("recheck_order_sig_cmd").removeAttribute("disabled");
                        document.getElementById("recheck_order_sig").value = "";
                        document.getElementById("recheck_order_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);
                        document.getElementById("recheck_order_sig").removeAttribute("disabled");
                        document.getElementById("validate_recheck_order_sig").removeAttribute("disabled");

                        // update status
                        status.innerHTML = "Order still processing. Copy and run the command again to check again.";
                    });
                }

                // order is ready for finalizing
                else if(order['status'] === "valid"){

                    // set the certificate uri
                    ORDER['cert_uri'] = order['certificate'];

                    // update the status before getting another nonce
                    status.innerHTML = "loading nonce...";

                    // get nonce for getting the certificate
                    getNonce(function(nonce, err){
                        if(err){
                            return fail(status, "Failed certificate nonce request (code: " + err.status + "). " + err.responseText);
                        }

                        // populate cert retrieval signature
                        ORDER['cert_protected_json'] = {
                            "url": ORDER['cert_uri'],
                            "alg": ACCOUNT['alg'],
                            "nonce": nonce,
                            "kid": ACCOUNT['account_uri'],
                        }
                        ORDER['cert_protected_b64'] = b64(JSON.stringify(ORDER['cert_protected_json']));
                        document.getElementById("cert_sig_cmd").value = "" +
                            "PRIV_KEY=./account.key; " +
                            "echo -n \"" + ORDER['cert_protected_b64'] + "." + ORDER['cert_payload_b64'] + "\" | " +
                            "openssl dgst -sha256 -hex -sign $PRIV_KEY";
                        document.getElementById("cert_sig_cmd").setAttribute("readonly", "");
                        document.getElementById("cert_sig_cmd").removeAttribute("disabled");
                        document.getElementById("cert_sig").value = "";
                        document.getElementById("cert_sig").setAttribute("placeholder", RESULT_PLACEHOLDER);
                        document.getElementById("cert_sig").removeAttribute("disabled");
                        document.getElementById("validate_cert_sig").removeAttribute("disabled");

                        // complete step 4g
                        status.innerHTML = "Certificate ready! Proceed to next command below.";
                    });
                }

                // order invalid
                else{
                    return fail(status, "Order processing failed. Please start back at Step 1. " + recheck_order_xhr.responseText);
                }
            }

            // error checking order
            else{
                return fail(status, "Account registration failed. Please start back at Step 1. " + recheck_order_xhr.responseText);
            }
        }
    };
    recheck_order_xhr.send(JSON.stringify({
        "protected": ORDER['recheck_order_protected_b64'],
        "payload": ORDER['recheck_order_payload_b64'],
        "signature": ORDER['recheck_order_sig'],
    }));
}

/*
 * Step 4h: Get Certificate (GET-as-POST /order['cert_uri'])
 */
function getCertificate(e){
    e.preventDefault();

    // clear previous status
    var status = document.getElementById("validate_cert_sig_status");
    status.style.display = "inline";
    status.className = "";
    status.innerHTML = "retrieving certificate...";

    // hide following steps
    document.getElementById("step5").style.display = "none";
    document.getElementById("step5_pending").style.display = "inline";

    // validate registration payload exists
    if(ORDER['cert_payload_b64'] === undefined){
        return fail(status, "Certificate payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var cert_sig = hex2b64(document.getElementById("cert_sig").value);
    if(cert_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ORDER['cert_sig'] = cert_sig;

    // send update request to CA finalize_uri
    var cert_xhr = new XMLHttpRequest();
    cert_xhr.open("POST", ORDER['cert_uri']);
    cert_xhr.setRequestHeader("Content-Type", "application/jose+json");
    cert_xhr.onreadystatechange = function(){
        if(cert_xhr.readyState === 4){

            // successful finalizing the order
            if(cert_xhr.status === 200){

                // format cert into PEM format
                document.getElementById("crt").value = cert_xhr.responseText;

                // proceed step 5
                document.getElementById("step5").style.display = "block";
                document.getElementById("step5_pending").style.display = "none";
                status.innerHTML = "Certificate retrieved! Proceed to next step.";

                // alert when navigating away
                window.onbeforeunload = function(){
                    return "Be sure to save your signed certificate! " +
                           "It will be lost if you navigate away from this " +
                           "page before saving it, and you might not be able " +
                           "to get another one issued!";
                };
            }

            // error geting certificate
            else{
                return fail(status, "Certificate retrieval failed. Please start back at Step 1. " + cert_xhr.responseText);
            }
        }
    };
    cert_xhr.send(JSON.stringify({
        "protected": ORDER['cert_protected_b64'],
        "payload": ORDER['cert_payload_b64'],
        "signature": ORDER['cert_sig'],
    }));
}

