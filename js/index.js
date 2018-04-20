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
//  "finalize_response": {"status": "valid", "certificate": "...", ...},
};
var AUTHORIZATIONS = {
//  // one authorization for each domain
//  "https://...": {
//      "authorization": {"status": "valid", "identifier": {...}, "challenges": [...], "wildcard": false, ...},
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

// helper function to get an authorization
function getAuthorization(auth_url, callback){
    var xhr = new XMLHttpRequest();
    xhr.open("GET", auth_url + "?" + cachebuster());
    xhr.onload = function(){

        // update authorization
        AUTHORIZATIONS[auth_url]['authorization'] = JSON.parse(xhr.responseText);

        // clear stale challenge objects
        AUTHORIZATIONS[auth_url]['python_challenge_uri'] = undefined;
        AUTHORIZATIONS[auth_url]['python_challenge_object'] = undefined;
        AUTHORIZATIONS[auth_url]['file_challenge_uri'] = undefined;
        AUTHORIZATIONS[auth_url]['file_challenge_object'] = undefined;
        AUTHORIZATIONS[auth_url]['dns_challenge_uri'] = undefined;
        AUTHORIZATIONS[auth_url]['dns_challenge_object'] = undefined;

        // update challenges
        var challenges = AUTHORIZATIONS[auth_url]['authorization']['challenges'];
        for(var i = 0; i < challenges.length; i++){
            var challenge = challenges[i];

            // HTTP challenge
            if(challenge['type'] === "http-01"){
                AUTHORIZATIONS[auth_url]['python_challenge_uri'] = challenge['url'];
                AUTHORIZATIONS[auth_url]['python_challenge_object'] = challenge;
                AUTHORIZATIONS[auth_url]['file_challenge_uri'] = challenge['url'];
                AUTHORIZATIONS[auth_url]['file_challenge_object'] = challenge;
            }

            // DNS challenge
            if(challenge['type'] === "dns-01"){
                AUTHORIZATIONS[auth_url]['dns_challenge_uri'] = challenge['url'];
                AUTHORIZATIONS[auth_url]['dns_challenge_object'] = challenge;
            }
        }

        // make the callback with the updated authorization
        callback(AUTHORIZATIONS[auth_url]['authorization'], undefined);
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
                document.getElementById("challenge_domains").innerHTML = "";

                // recursively render authorizations since asynchronous
                function buildAuthorization(n, callback){
                    var auth_url = ORDER['order_response']['authorizations'][n];
                    AUTHORIZATIONS[auth_url] = {};
                    getAuthorization(auth_url, function(auth_obj, err){
                        if(err){
                            return fail(status, "Failed auth #" + n + " lookup (code: " + err.status + "). " + err.responseText);
                        }

                        // figure out which domain this authorization is checking
                        var d = auth_obj['identifier']['value']; // domain name (e.g. foo.com)
                        var d_ = d.replace(/[\.]/g, "_"); // id-friendly domain name (e.g. foo_com)

                        // distinguish wildcard cert authorizations
                        if(auth_obj['wildcard']){
                            d_ = "__" + d_;
                        }

                        // make challenge section for this authorization
                        var template = document.getElementById("challenge_examplecom_template").cloneNode(true);

                        // section
                        var section_id = "challenge_" + d_;
                        template.setAttribute("id", section_id);
                        template.style.display = "block";
                        template.querySelector(".domain").innerHTML = "";
                        template.querySelector(".domain").appendChild(document.createTextNode(auth_obj['wildcard'] ? "*." + d : d));

                        // tabs
                        template.querySelector("input.challenge_python").setAttribute("name", "radio_" + d_);
                        template.querySelector("input.challenge_python").setAttribute("id", "radio_" + d_ + "_python");
                        template.querySelector("label.challenge_python").setAttribute("for", "radio_" + d_ + "_python");
                        template.querySelector("label.challenge_python").style.display = "none";
                        template.querySelector("input.challenge_file").setAttribute("name", "radio_" + d_);
                        template.querySelector("input.challenge_file").setAttribute("id", "radio_" + d_ + "_file");
                        template.querySelector("label.challenge_file").setAttribute("for", "radio_" + d_ + "_file");
                        template.querySelector("label.challenge_file").style.display = "none";
                        template.querySelector("input.challenge_dns").setAttribute("name", "radio_" + d_);
                        template.querySelector("input.challenge_dns").setAttribute("id", "radio_" + d_ + "_dns");
                        template.querySelector("label.challenge_dns").setAttribute("for", "radio_" + d_ + "_dns");
                        template.querySelector("label.challenge_dns").style.display = "none";

                        // help texts
                        template.querySelector(".howto_python").setAttribute("id", "howto_" + d_ + "_python");
                        template.querySelector(".howto_python_label").setAttribute("for", "howto_" + d_ + "_python");
                        template.querySelector(".howto_python_sig").setAttribute("id", "howto_" + d_ + "_python_sig");
                        template.querySelector(".howto_python_sig_label").setAttribute("for", "howto_" + d_ + "_python_sig");
                        template.querySelector(".howto_file").setAttribute("id", "howto_" + d_ + "_file");
                        template.querySelector(".howto_file_label").setAttribute("for", "howto_" + d_ + "_file");
                        template.querySelector(".howto_file_sig").setAttribute("id", "howto_" + d_ + "_file_sig");
                        template.querySelector(".howto_file_sig_label").setAttribute("for", "howto_" + d_ + "_file_sig");
                        template.querySelector(".howto_dns").setAttribute("id", "howto_" + d_ + "_dns");
                        template.querySelector(".howto_dns_label").setAttribute("for", "howto_" + d_ + "_dns");
                        template.querySelector(".howto_dns_sig").setAttribute("id", "howto_" + d_ + "_dns_sig");
                        template.querySelector(".howto_dns_sig_label").setAttribute("for", "howto_" + d_ + "_dns_sig");

                        // event listeners
                        template.querySelector(".confirm_python").addEventListener("submit", confirmChallenge);
                        template.querySelector(".confirm_file").addEventListener("submit", confirmChallenge);
                        template.querySelector(".confirm_dns").addEventListener("submit", confirmChallenge);
                        template.querySelector(".validate_python_sig").addEventListener("submit", validateChallenge);
                        template.querySelector(".validate_file_sig").addEventListener("submit", validateChallenge);
                        template.querySelector(".validate_dns_sig").addEventListener("submit", validateChallenge);

                        // python option data
                        if(AUTHORIZATIONS[auth_url]['python_challenge_object'] !== undefined){

                            // populate values
                            var token = AUTHORIZATIONS[auth_url]['python_challenge_object']['token'];
                            var keyauth = token + "." + ACCOUNT['thumbprint'];
                            var link = "http://" + d + "/.well-known/acme-challenge/" + token;
                            template.querySelector(".python_link").innerHTML = "";
                            template.querySelector(".python_link").appendChild(document.createTextNode(link));
                            template.querySelector(".python_link").setAttribute("href", link);
                            template.querySelector(".python_domain").innerHTML = "";
                            template.querySelector(".python_domain").appendChild(document.createTextNode(d));
                            template.querySelector(".python_server").value = "" +
                                "sudo python2 -c \"import BaseHTTPServer; \\\n" +
                                "    h = BaseHTTPServer.BaseHTTPRequestHandler; \\\n" +
                                "    h.do_GET = lambda r: r.send_response(200) or r.end_headers() " +
                                        "or r.wfile.write('" + keyauth + "'); \\\n" +
                                "    s = BaseHTTPServer.HTTPServer(('0.0.0.0', 80), h); \\\n" +
                                "    s.serve_forever()\"";
                            template.querySelector(".confirm_python_submit").value = "I'm now running this command on " + d;
                            template.querySelector(".validate_python_sig_submit").value = "Submit challenge for " + d;
                            template.querySelector("label.challenge_python").style.display = "inline";

                            // set data attributes
                            var challenge_url = AUTHORIZATIONS[auth_url]['python_challenge_object']['url'];
                            template.querySelector(".confirm_python").dataset.option = "python";
                            template.querySelector(".confirm_python").dataset.section = section_id;
                            template.querySelector(".confirm_python").dataset.auth = auth_url;
                            template.querySelector(".confirm_python").dataset.challenge = challenge_url;
                        }

                        // file-based option data
                        if(AUTHORIZATIONS[auth_url]['file_challenge_object'] !== undefined){

                            // populate values
                            var token = AUTHORIZATIONS[auth_url]['file_challenge_object']['token'];

                            var keyauth = token + "." + ACCOUNT['thumbprint'];
                            var link = "http://" + d + "/.well-known/acme-challenge/" + token;
                            var server_config = "" +
                                "#nginx example\n" +
                                "location /.well-known/acme-challenge/ {\n" +
                                "    alias /path/to/www/;\n" +
                                "    try_files $uri =404;\n" +
                                "}\n\n" +
                                "#apache example\n" +
                                "Alias /.well-known/acme-challenge /path/to/www/.well-known/acme-challenge";
                            var echo = "echo -n \"" + keyauth + "\" > /path/to/www/.well-known/acme-challenge/" + token;
                            template.querySelector(".file_config").innerHTML = "";
                            template.querySelector(".file_config").appendChild(document.createTextNode(server_config));
                            template.querySelector(".file_echo").innerHTML = "";
                            template.querySelector(".file_echo").appendChild(document.createTextNode(echo));
                            template.querySelector(".file_link").innerHTML = "";
                            template.querySelector(".file_link").appendChild(document.createTextNode(link));
                            template.querySelector(".file_link").setAttribute("href", link);
                            template.querySelector(".file_url").value = link;
                            template.querySelector(".file_data").value = keyauth;
                            template.querySelector(".confirm_file_submit").value = "I'm now serving this file on " + d;
                            template.querySelector(".validate_file_sig_submit").value = "Submit challenge for " + d;
                            template.querySelector("label.challenge_file").style.display = "inline";

                            // set data attributes
                            var challenge_url = AUTHORIZATIONS[auth_url]['file_challenge_object']['url'];
                            template.querySelector(".confirm_file").dataset.option = "file";
                            template.querySelector(".confirm_file").dataset.section = section_id;
                            template.querySelector(".confirm_file").dataset.auth = auth_url;
                            template.querySelector(".confirm_file").dataset.challenge = challenge_url;
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
                                var dig = "dig +short @ns.yournameserver.com _acme-challenge." + d + " TXT";
                                template.querySelector(".dns_dig").innerHTML = "";
                                template.querySelector(".dns_dig").appendChild(document.createTextNode(dig));
                                template.querySelector(".dns_domain").innerHTML = "";
                                template.querySelector(".dns_domain").appendChild(document.createTextNode(d));
                                template.querySelector(".dns_value").innerHTML = "";
                                template.querySelector(".dns_value").appendChild(document.createTextNode(dns_data));
                                template.querySelector(".dns_subdomain").value = "_acme-challenge." + d;
                                template.querySelector(".dns_data").value = dns_data;
                                template.querySelector(".confirm_dns_submit").value = "I can see the TXT record for " + d;
                                template.querySelector(".validate_dns_sig_submit").value = "Submit challenge for " + d;
                                template.querySelector("label.challenge_dns").style.display = "inline";

                                // data attributes
                                var challenge_url = AUTHORIZATIONS[auth_url]['dns_challenge_object']['url'];
                                template.querySelector(".confirm_dns").dataset.option = "dns";
                                template.querySelector(".confirm_dns").dataset.section = section_id;
                                template.querySelector(".confirm_dns").dataset.auth = auth_url;
                                template.querySelector(".confirm_dns").dataset.challenge = challenge_url;

                                // auto-select Option 3 if no other options
                                if(AUTHORIZATIONS[auth_url]['python_challenge_object'] === undefined
                                && AUTHORIZATIONS[auth_url]['file_challenge_object'] === undefined){
                                    template.querySelector("input.challenge_python").removeAttribute("checked");
                                    template.querySelector("input.challenge_dns").setAttribute("checked", "");
                                    template.querySelector("label.challenge_dns").innerHTML = "Option 1 - DNS record (wildcard)";
                                }

                                // recurse if needed
                                document.getElementById("challenge_domains").appendChild(template);
                                if((n + 1) < ORDER['order_response']['authorizations'].length){
                                    return buildAuthorization(n + 1, callback);
                                }
                                else{
                                    return callback();
                                }
                            });
                        }

                        // no DNS option, so recurse without hashing anything
                        else{
                            document.getElementById("challenge_domains").appendChild(template);
                            if((n + 1) < ORDER['order_response']['authorizations'].length){
                                return buildAuthorization(n + 1, callback);
                            }
                            else{
                                return callback();
                            }
                        }
                    });
                }

                // kickoff rendering authorization html
                buildAuthorization(0, function(){

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
 * Step 4a: Confirm Challenge
 */
function confirmChallenge(e){
    e.preventDefault();

    // find the relevant resources
    var section_id = e.target.dataset.section // challenge_examplecom
    var option = e.target.dataset.option; // "python", "file", or "dns"
    var auth_url = e.target.dataset.auth;
    var d = AUTHORIZATIONS[auth_url]['authorization']['identifier']['value'];
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

    // get nonce for challenge
    getNonce(function(nonce, err){
        if(err){
            return fail(status, "Failed challenge nonce request (domain: " + d + ") (code: " + err.status + "). " + err.responseText);
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
 * Step 4b: Verify Ownership (POST /challenge['url'], ...)
 */
function validateChallenge(e){
    e.preventDefault();

    // find the relevant resources
    var section_id = e.target.dataset.section; // challenge_examplecom
    var option = e.target.dataset.option; // "python", "file", or "dns"
    var auth_url = e.target.dataset.auth;
    var d = AUTHORIZATIONS[auth_url]['authorization']['identifier']['value'];
    var challenge_url = e.target.dataset.challenge;
    var section = document.getElementById(section_id);
    var status_class = option + "_sig_status";
    var status = section.querySelector("." + status_class);
    var sig_input = section.querySelector("." + option + "_sig");

    // clear previous status
    status.style.display = "inline";
    status.className = status_class;
    status.innerHTML = "submitting...";

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

                // poll to watch the authorization for status === "valid"
                function checkAuthorization(){
                    status.innerHTML = "checking...";

                    // poll authorization
                    getAuthorization(auth_url, function(auth_obj, err){

                        // authorization failed
                        if(err){
                            return fail(status, "Authorization failed. Please start back at Step 1. " + err.responseText);
                        }

                        // authorization still pending, so wait a second and check again
                        if(auth_obj['status'] === "pending"){
                            status.innerHTML = "waiting...";
                            window.setTimeout(checkAuthorization, 1000);
                        }

                        // authorization valid
                        else if(auth_obj['status'] === "valid"){

                            // see if all the authorizations are valid
                            var all_valid = true;
                            for(var a_url in AUTHORIZATIONS){
                                if(AUTHORIZATIONS[a_url]['authorization']['status'] !== "valid"){
                                    all_valid = false;
                                }
                            }
                            if(all_valid){

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
                                    status.innerHTML = "Domain verified! Go to next command.";
                                });
                            }

                            // proceed to next authorization
                            else{
                                status.innerHTML = "Domain verified! Go to next command.";
                            }
                        }

                        // authorization failed
                        else{
                            return fail(status, "Domain challenge failed. Please start back at Step 1. " + JSON.stringify(auth_obj));
                        }
                    });
                }
                // start polling authorization
                checkAuthorization();
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
 * Step 4c: Issue Certificate (POST /order['finalize'])
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

    // validate update payload exists
    if(ORDER['finalize_protected_b64'] === undefined){
        return fail(status, "Finalize payload not found. Please go back to Step 1.");
    }

    // validate the signature
    var finalize_sig = hex2b64(document.getElementById("finalize_sig").value);
    if(finalize_sig === null){
        return fail(status, "You need to run the above commands and paste the output in the text boxes below each command.");
    }
    ORDER['finalize_sig'] = finalize_sig;

    // send update request to CA account_uri
    var finalize_xhr = new XMLHttpRequest();
    finalize_xhr.open("POST", ORDER['finalize_uri']);
    finalize_xhr.setRequestHeader("Content-Type", "application/jose+json");
    finalize_xhr.onreadystatechange = function(){
        if(finalize_xhr.readyState === 4){

            // successful update
            if(finalize_xhr.status === 200){

                // set finalize response
                ORDER['finalize_response'] = JSON.parse(finalize_xhr.responseText);

                // poll to watch the order for status === "valid"
                function checkForCert(){
                    status.innerHTML = "checking...";

                    // poll order for certificate
                    var poll_cert_xhr = new XMLHttpRequest();
                    poll_cert_xhr.open("GET", ORDER['order_uri'] + "?" + cachebuster());
                    poll_cert_xhr.onload = function(){
                        var order = JSON.parse(poll_cert_xhr.responseText)
                        ORDER['order_response'] = order;

                        // order still processing
                        if(order['status'] === "pending" || order['status'] === "processing" || order['status'] === "ready"){
                            status.innerHTML = "processing...";
                            window.setTimeout(checkForCert, 1000);
                        }

                        // order is ready for finalizing
                        else if(order['status'] === "valid"){

                            // no certificate url
                            if(order['certificate'] === undefined){
                                return fail(status, "Certificate not provided. Please start back at Step 1. " + poll_cert_xhr.responseText);
                            }

                            // get certificate
                            var cert_xhr = new XMLHttpRequest();
                            cert_xhr.open("GET", order['certificate']);
                            cert_xhr.onload = function(){

                                // format cert into PEM format
                                document.getElementById("crt").value = cert_xhr.responseText;

                                // proceed step 5
                                document.getElementById("step5").style.display = "block";
                                document.getElementById("step5_pending").style.display = "none";
                                status.innerHTML = "Certificate signed! Proceed to next step.";

                                // alert when navigating away
                                window.onbeforeunload = function(){
                                    return "Be sure to save your signed certificate! " +
                                           "It will be lost if you navigate away from this " +
                                           "page before saving it, and you might not be able " +
                                           "to get another one issued!";
                                };
                            };

                            // certificate download error
                            cert_xhr.onerror = function(){
                                return fail(status, "Order request failed. Please start back at Step 1. " + cert_xhr.responseText);
                            };
                            cert_xhr.send();
                        }

                        // order invalid
                        else{
                            return fail(status, "Order processing failed. Please start back at Step 1. " + poll_cert_xhr.responseText);
                        }
                    };

                    // order poll error
                    poll_cert_xhr.onerror = function(){
                        return fail(status, "Order request failed. Please start back at Step 1. " + poll_cert_xhr.responseText);
                    };
                    poll_cert_xhr.send();
                }
                // start polling order
                checkForCert();
            }

            // error finalizing
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

