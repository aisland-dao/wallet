// Vault is the module taking care of encryption/decryption of the private keys and
// applying the signatures
// Communication with the UI is done in http on 127.0.0.1 interface.
let express = require('express');
let fs=require("fs");
let app = express();

console.log("Vault - v.1.00");
console.log("Listening on port tcp/3000");
mainloop();
// main body of the app
async function mainloop(){
    // function to generate a new random keys, returns a seed phrase and public address
    app.get('/newkey',async function (req, res) {


    });
    // function to sign a transaction
    app.get('/sign',async function (req, res) {


    });

    // listen on port 3000
    let server = app.listen(3000, function () { });

}