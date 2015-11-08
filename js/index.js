
// global variables
var CONTACT_EMAIL, // "bar@foo.com"
    CONTACT_PUBKEY, // {
                    //   "pubkey": "-----BEGIN PUBLIC KEY...",
                    //   "sig": "deadbeef...",
                    //   "jwk": {...}
                    // }
    CSR, // {
         //   "csr": "-----BEGIN CERTIFICATE REQUEST...",
         //   "nonce": "deadbeef...",
         //   "sig": "deadbeef...",
         // }
    DOMAINS, // {
             //   "www.foo.com": {
             //     "request_nonce": "deadbeef...",
             //     "request_sig": "deadbeef...",
             //     "response_nonce": "deadbeef...",
             //     "response_sig": "deadbeef...",
             //     "confirm": True,
             //     "verify_nonce": "deadbeef...",
             //     "verify_sig": "deadbeef...",
             //   },
             //   ...
             // }
    SIGNED_CERT; // "-----BEGIN CERTIFICATE..."

// hide/show the help content
function helpContent(e){
    e.preventDefault();
    console.log(e.target.id + "_content");
    var help = document.getElementById(e.target.id + "_content");
    help.style.display = help.style.display === "none" ? "" : "none";
}
function bindHelps(elems){
    for(var i = 0; i < elems.length; i++){
        elems[i].addEventListener("click", helpContent);
    }
}
bindHelps(document.querySelectorAll(".help"));

// validate contact info
function validateContact(e){
    e.preventDefault();
    console.log("validateContact");
}
document.getElementById("validate_contact").addEventListener("click", validateContact);

// validate CSR
function validateCSR(e){
    e.preventDefault();
    console.log("validateCSR");
}
document.getElementById("validate_csr").addEventListener("click", validateCSR);

// validate initial signatures
function validateInitialSigs(e){
    e.preventDefault();
    console.log("validateInitialSigs");
}
document.getElementById("validate_initial_sigs").addEventListener("click", validateInitialSigs);

// confirm domain check is running
function confirmDomainCheckIsRunning(e){
    e.preventDefault();
    console.log("confirmDomainCheckIsRunning");
}

// verify ownership
function verifyOwnership(e){
    e.preventDefault();
    console.log("verifyOwnership");
}

// request to sign certificate
function signCertificate(e){
    e.preventDefault();
    console.log("signCertificate");
}

