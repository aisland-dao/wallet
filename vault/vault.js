// Vault is the module taking care of encryption/decryption of the private keys and
// applying the signatures
// Communication with the UI is done in http on 127.0.0.1 interface.
const express = require('express');
const fs=require("fs");
const aesjs=require("aes-js");
const util_crypto=require("@polkadot/util-crypto"); 
const util=require("@polkadot/util"); 
//const keyring=require("@polkadot/keyring"); 
// set default to local host if not set
const PATH_STORAGE = process.env.PATH_STORAGE;
if (typeof PATH_STORAGE === 'undefined') {
    console.log(Date.now(), "[Error] the environment variable PATH_STORAGE is not set.");
    process.exit(1);
}
let app = express();
console.log("Vault - v.1.00");
console.log("Listening on port tcp/3000");
mainloop();
// main body of the app
async function mainloop(){
    // function to generate a new keys pair, encrypt and store
    // requires a password to encrypt the keys
    // and description of the account
    // returns the account address and the mnemnonic seed for hard copy
    app.get('/newaccount',async function (req, res) {
        const password=req.query.password;
        const description=req.query.description;
        if(typeof password === 'undefined'){
            res.send('{"result":"KO","message":"password parameter is mandatory"}');
            return;
        }
        if(typeof description === 'undefined'){
            res.send('{"result":"KO","message":"description parameter is mandatory"}');
            return;
        }
        // generate random mnemonic seed BIP39 standard. 
        // The standard allows to use the same seed in different wallets not using any derivation
        const mnemonic = util_crypto.mnemonicGenerate(12);
        const encrypted= await encrypt_mnemonic(mnemonic,password);
        // search for free slot
        let fn=""
        let i=0;
        while(1){
            fn=PATH_STORAGE+"/account_"+i.toString();
            if(fs.existsSync(fn)){
                i=i+1;
                continue;
            }
            break;
        }
        let data='{"description":"'+description+'","encrypted":'+encrypted+'}';
        // write encrypted mnemonic
        fs.writeFileSync(fn,data);
        res.send('{"result":"OK","message":"New Account Generated","mnemonic":"'+mnemonic+'","description":"'+description+'"}');
    });
    // function to sign a transaction
    app.get('/sign',async function (req, res) {


    });

    // listen on port 3000
    let server = app.listen(3000, function () { });

}
// function to encrypt and store the secret seed words with 3 layers of symmetric encryption
// returns encrypted structure in json format
async function encrypt_mnemonic(mnemonic,pwd) {

    // get ascii value of first 2 bytes
    const vb1 = pwd.charCodeAt(0);
    const vb2 = pwd.charCodeAt(1);
    const p = vb1 * vb2; // position to derive other 3 passwords of 32 bytes each on
    
    // derive the password used for encryption with an init vector (random string) xx hashes with 3 different algorithms
    // Kekkak,Sha512 and Blake algorythms
    let randomstring = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < 32; i++) {
        randomstring += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    let dpwd1 = '';
    let dpwd2 = '';
    let dpwd3 = '';
    let h = util_crypto.keccakAsU8a(pwd + randomstring);
    // set 1 million the number of hashes, it will take fews seconds...
    for (let i = 0; i < 1000000; i++) {
        h = util_crypto.keccakAsU8a(h);
        if (i == p) {
            dpwd1 = h;
        }
        h = util_crypto.sha512AsU8a(h);
        if (i == p) {
            dpwd2 = h;
        }
        h = util_crypto.blake2AsU8a(h);
        if (i == p) {
            dpwd3 = h;
        }
    }

    // 3 Layers encryption
    // encrypt the secret words in AES256-CFB
    // it generates a random init vector
    let ivf = '';
    for (let i = 0; i < 16; i++) {
        ivf += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    // encryption
    const ivaescfb = aesjs.utils.utf8.toBytes(ivf);
    const keyaescfb = dpwd1.slice(0, 32);
    let aesCfb = new aesjs.ModeOfOperation.cfb(keyaescfb, ivaescfb);
    var mnemonicbytes = aesjs.utils.utf8.toBytes(mnemonic);

    let encryptedaescfb = aesCfb.encrypt(mnemonicbytes);
    // encrypt the outoput of AES256-CFB in AES256-CTR
    let ivs = '';
    for (let i = 0; i < 16; i++) {
        ivs += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    const ivaesctr = aesjs.utils.utf8.toBytes(ivs);
    //const keyaes= aesjs.utils.utf8.toBytes(dpwd2.slice(0,32));
    const keyaesctr = dpwd2.slice(0, 32);
    let aesCtr = new aesjs.ModeOfOperation.ctr(keyaesctr, ivaesctr);
    let encryptedaesctr = aesCtr.encrypt(encryptedaescfb);
    // encrypt the outoput of AES256-CTR in AES256-OFB
    let ivso = '';
    for (let i = 0; i < 16; i++) {
        ivso += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    const ivaesofb = aesjs.utils.utf8.toBytes(ivso);
    const keyaesofb = dpwd3.slice(0, 32);
    let aesOfb = new aesjs.ModeOfOperation.ofb(keyaesofb, ivaesofb);
    let encryptedaesofb = aesOfb.encrypt(encryptedaesctr);
    let encryptedhex = aesjs.utils.hex.fromBytes(encryptedaesofb);
    //convert to Hex json
    let value = '{"iv":"' + randomstring + '","ivaescfb":"' + util.u8aToHex(ivaescfb) + '","ivaesctr":"' + util.u8aToHex(ivaesctr) + '","ivaesofb":"' + util.u8aToHex(ivaesofb) + '","encrypted":"' + encryptedhex + '"}';
    return(value);
}
// function to decrypt the web wallet and return a key pair
async function decrypt_mnemonic(encrypted,pwd){
    // get ascii value of first 2 bytes of password
    const vb1=pwd.charCodeAt(0);
    const vb2=pwd.charCodeAt(1);
    const p=vb1*vb2; // position to derive other 3 passwords
    // derive the password used for encryption with an init vector (random string) and 10000 hashes with 3 different algorithms
    const enc=JSON.parse(encrypted);
    let randomstring = enc.iv;
    let dpwd1='';
    let dpwd2='';
    let dpwd3='';
    let h=util_crypto.keccakAsU8a(pwd+randomstring);
    for (let i = 0; i < 1000000; i++) {
      h=util_crypto.keccakAsU8a(h);
      if (i==p){
        dpwd1=h;
      }
      h=util_crypto.sha512AsU8a(h);
      if (i==p){
        dpwd2=h;
      }
      h=util_crypto.blake2AsU8a(h);
      if (i==p){
        dpwd3=h;
      }
    }
    // decrypt AES-OFB
    const ivaesofb=util.hexToU8a(enc.ivaesofb);
    const keyaesofb= dpwd3.slice(0,32);
    let aesOfb = new aesjs.ModeOfOperation.ofb(keyaesofb, ivaesofb);
    const encryptedhex=enc.encrypted;
    const encryptedaesofb=aesjs.utils.hex.toBytes(encryptedhex);
    let encryptedaesctr = aesOfb.decrypt(encryptedaesofb);
    // decrypt AES-CTR
    const ivaesctr=util.hexToU8a(enc.ivaesctr);
    const keyaesctr= dpwd2.slice(0,32);
    let aesCtr = new aesjs.ModeOfOperation.ctr(keyaesctr, ivaesctr);
    let encryptedaescfb = aesCtr.decrypt(encryptedaesctr);
    // decrypt AES-CFB
    const ivaescfb=util.hexToU8a(enc.ivaescfb);
    const keyaescfb= dpwd1.slice(0,32);
    let aesCfb = new aesjs.ModeOfOperation.cfb(keyaescfb, ivaescfb);
    let decrypted = aesCfb.decrypt(encryptedaescfb);
    let mnemonicdecrypted = aesjs.utils.utf8.fromBytes(decrypted);
    // return empty for wrong password or the decrypte mnemonic
    if(!mnemonicdecrypted)
      return("");
    else 
      return(mnemonicdecrypted);
  }