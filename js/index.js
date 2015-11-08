
// global variables
var CONTACT_EMAIL, // "bar@foo.com"
    CONTACT_PUBKEY, // {
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
    console.log("validateAccount");
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

