<script>
import {SHA3} from 'sha3';
import Sodium from './sodium.js';
var crypto_box_keypair;
var crypto_box_seed_keypair;
var crypto_box_seal;
var crypto_box_seal_open;
var from_string;
var to_string;
var to_hex;
var sodium_set = false;
Sodium.sodium.ready.then(function(res, ref){
    crypto_box_keypair = Sodium.sodium.crypto_box_keypair;
    crypto_box_seed_keypair = Sodium.sodium.crypto_box_seed_keypair;
    crypto_box_seal = Sodium.sodium.crypto_box_seal;
    crypto_box_seal_open = Sodium.sodium.crypto_box_seal_open;
    from_string = Sodium.sodium.from_string;
    to_string = Sodium.sodium.to_string;
    to_hex = Sodium.sodium.to_hex;
    sodium_set = true;
});
let username;
let password;
const submit_err_handler = (err) =>{
    console.error(err.message);
    alert(err.message);
};
const submit = () => {
    try{
        if(!sodium_set){console.error('Sodium library not yet loaded');return;};
        let clientSalt;
        let keygenSalt;
        let salts_req = new XMLHttpRequest();
        salts_req.open("POST", "/salts_req", true);
        salts_req.setRequestHeader("Content-Type", "application/json");
        salts_req.send(JSON.stringify({action:'get',username:username}));
        salts_req.onreadystatechange = ()=>{
            if (salts_req.readyState == XMLHttpRequest.DONE){
                if(salts_req.status === 200){
                    let response_obj = JSON.parse(salts_req.response);
                    console.log(response_obj);
                    if(response_obj.hasOwnProperty('error')){
                        submit_err_handler(response_obj.error);
                        return;
                    }
                    clientSalt = response_obj.clientSalt;
                    keygenSalt = response_obj.keygenSalt;
                }
                else{
                    throw new Error('Error with ajax request for salts');
                }
                const client_hash = new SHA3(256);
                client_hash.update(password + clientSalt);
                const keygen_hash = new SHA3(256);
                keygen_hash.update(password + keygenSalt);
                const key_pair = crypto_box_seed_keypair(keygen_hash.digest('ascii'));
                let auth_req = new XMLHttpRequest();
                auth_req.open("POST", "/auth_req", true);
                auth_req.setRequestHeader("Content-Type", "application/json");
                auth_req.send(JSON.stringify({
                    username:username, hash:client_hash.digest('hex'),
                    publicKey:to_hex(key_pair.publicKey)
                }));
                auth_req.onreadystatechange = () => {
                    if(auth_req.readyState == XMLHttpRequest.DONE){
                        if(auth_req.status === 200){
                            let response_obj = JSON.parse(auth_req.response);
                            console.log(response_obj);
                            if(response_obj.hasOwnProperty('error')){
                                return submit_err_handler(new Error(response_obj.error));
                            }
                            localStorage.setItem('authToken', response_obj.authToken);
                            //possibly rethink how private key is stored
                            localStorage.setItem('privateKey', key_pair.privateKey);
                            localStorage.setItem('publicKey', key_pair.publicKey);
                            window.location.href = "/";
                        }
                        else{submit_err_handler(new Error('Error with authentication'));}
                    }
                };
            }
        };
    }
    catch (err){
        //change error handler to be more aesthetic eventually
        submit_err_handler(err);
    }
};
</script>
<h1>Login</h1>
<form on:submit|preventDefault={submit}>
Username:<input type="text" bind:value={username}><br>
Password:<input type="password" bind:value={password}><br>
<button type="sumbit">Log In</button>
</form>
<form action="/create_account">
    <input type="submit" value="Create Account">
</form>
