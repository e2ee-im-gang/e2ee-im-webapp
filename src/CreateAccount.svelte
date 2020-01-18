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
    sodium_set = true;
    crypto_box_keypair = Sodium.sodium.crypto_box_keypair;
    crypto_box_seed_keypair = Sodium.sodium.crypto_box_seed_keypair;
    crypto_box_seal = Sodium.sodium.crypto_box_seal;
    crypto_box_seal_open = Sodium.sodium.crypto_box_seal_open;
    from_string = Sodium.sodium.from_string;
    to_string = Sodium.sodium.to_string;
    to_hex = Sodium.sodium.to_hex;
});
let email;
let email_confirm;
let username;
let password;
let password_confirm;
const submit_err_handler = (err) =>{
	console.error(err.message);
	alert(err.message);
};
const submit = () =>{
    console.log('submitting form');
    if(!sodium_set){console.error('Sodium library not yet loaded');return;};
    try{
        if(email_confirm !== email){throw new Error("emails do not match");}
        if(password_confirm !== password){throw new Error("passwords do not match");}
        let clientSalt;
        let keygenSalt;
        let salts_req = new XMLHttpRequest();
        salts_req.open("POST", "/salts_req", true);
        salts_req.setRequestHeader("Content-Type", "application/json");
        salts_req.send(JSON.stringify({
            action:'new'
        }));
        salts_req.onreadystatechange = () => {
            if(salts_req.readyState != XMLHttpRequest.DONE){return;}
            if(salts_req.status === 200){
                let response_obj = JSON.parse(salts_req.response);
                console.log(response_obj);
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
            let acc_req = new XMLHttpRequest();
            acc_req.open("POST", "/create_account", true);
            acc_req.setRequestHeader("Content-Type", "application/json");
            acc_req.send(JSON.stringify({
                username:username,
                hash:client_hash.digest('hex'),
                publicKey:to_hex(key_pair.publicKey),
                clientSalt:clientSalt,
                keygenSalt:keygenSalt,
                email:email
            }));
            console.log('acc_req sent');
            acc_req.onreadystatechange = () =>{
                if(acc_req.readyState != XMLHttpRequest.DONE){return;}
                console.log('acc_req received');
                if(acc_req.status === 200){
                    let response_obj = JSON.parse(acc_req.response);
                    console.log(response_obj);
                    if(response_obj.hasOwnProperty('authToken')){
                        localStorage.setItem('authToken', response_obj.authToken);
                        localStorage.setItem('privateKey', key_pair.privateKey);
                        localStorage.setItem('publicKey', key_pair.publicKey);
                        window.location.href = "/";
                    }
                    else if(response_obj.hasOwnProperty('error')){
                        submit_err_handler(new Error(response_obj.error));
                    }
                    else{
                        submit_err_handler(new Error('invalid server response'));
                    }
                }
            }
        }
    }
    catch(err){
        submit_err_handler(err);
    }
};
</script>
<h1>Create Account</h1>
<form on:submit|preventDefault={submit}>
Email:<input type="text" bind:value={email}><br>
Confirm Email:<input type="text" bind:value={email_confirm}><br>
Username:<input type="text" bind:value={username}><br>
Password:<input type="password" bind:value={password}><br>
Confirm Password:<input type="password" bind:value={password_confirm}><br>
<button type="submit">Create Account</button>
</form>
