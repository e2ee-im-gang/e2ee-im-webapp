<script>
import {SHA3} from 'sha3';
import Sodium from './sodium.js';
const ajax_json_req = (req_obj, path) =>{
    console.log(path);
    return new Promise((res, rej)=>{
        let req = new XMLHttpRequest();
        req.open("POST", path, true);
        req.setRequestHeader("Content-Type", "application/json");
        req.send(JSON.stringify(req_obj));
        req.onreadystatechange = () =>{
            if(req.readyState != XMLHttpRequest.DONE) return;
            if(req.status !== 200) rej(new Error('Error ' + req.status.toString()));
            let response_obj = JSON.parse(req.response);
            if(response_obj.hasOwnProperty('authStatus')){
                if(response_obj.authStatus !== true){
                    end_session();
                }
            }
            if(response_obj.hasOwnProperty('error')) rej(new Error(response_obj.error));
            res(response_obj);
        };
    }).catch((err)=>{
        //must investigate how to do this properly
        console.error(err.message);
    });
}
let crypto_box_keypair;
let crypto_box_seed_keypair;
let crypto_box_seal;
let crypto_box_seal_open;
let from_string;
let from_hex;
let to_string;
let to_hex;
let sodium_set = false;
let ajax_c_priv_key;
let ajax_c_pub_key;
let ajax_s_pub_key;
let ajax_id_token;
Sodium.sodium.ready.then(async (res, ref)=>{
    crypto_box_keypair = Sodium.sodium.crypto_box_keypair;
    crypto_box_seed_keypair = Sodium.sodium.crypto_box_seed_keypair;
    crypto_box_seal = Sodium.sodium.crypto_box_seal;
    crypto_box_seal_open = Sodium.sodium.crypto_box_seal_open;
    from_string = Sodium.sodium.from_string;
    from_hex = Sodium.sodium.from_hex;
    to_string = Sodium.sodium.to_string;
    to_hex = Sodium.sodium.to_hex;
    sodium_set = true;
    let keypair = crypto_box_keypair();
    ajax_c_priv_key = keypair.privateKey;
    ajax_c_pub_key = keypair.publicKey;
    const req_obj = {
        publicKey:to_hex(ajax_c_pub_key)
    };
    let req = ajax_json_req(req_obj, '/keypair_req');
    let res_obj;
    try{
        res_obj = await req;
    }
    catch(err){
        return console.error(err.message);
    }
    ajax_s_pub_key = from_hex(res_obj.publicKey);
    ajax_id_token = res_obj.idToken;
});
const s_ajax_json_req = (req_obj, path)=>{
    console.log(path);
    if(!sodium_set) return console.error('Sodium library not yet loaded');
    if(!ajax_id_token) return console.error('cannot make secure request without server public key');
    return new Promise((res, rej)=>{
        const make_request = () =>{
            const req_digest = crypto_box_seal(from_string(JSON.stringify(req_obj)), ajax_s_pub_key);
            const to_send = {
                encryptedObject:{
                    idToken:ajax_id_token,
                    digest:to_hex(req_digest)
                }
            };
            let req = new XMLHttpRequest();
            req.open("POST", path, true);
            req.setRequestHeader("Content-Type", "application/json");
            req.send(JSON.stringify(to_send));
            req.onreadystatechange = async () =>{
                if(req.readyState != XMLHttpRequest.DONE) return;
                if(req.status !== 200) rej(new Error('Error ' + req.status.toString()));
                let res_obj = JSON.parse(req.response);
                if(res_obj.hasOwnProperty('encryptedObject')){
                    if(res_obj.idToken !== ajax_id_token)
                        throw new Error('Cannot decrypt response');
                    const decrypted_digest = crypto_box_seal_open(from_hex(res_obj.encryptedObject, ajax_c_pub_key, ajax_c_priv_key));
                    res_obj = JSON.parse(decrypted_digest);
                }
                if(res_obj.hasOwnProperty('authStatus')){
                    if(res_obj.authStatus !== true){
                        end_session();
                    }
                }
                if(res_obj.hasOwnProperty('keypairStatus')){
                    if(res_obj.keypairStatus !== true){
                        //technically can infinite loop here if there's an issue with the server
                        //possibly need to lock s_ajax_json_req function while this is occurring
                        let promise = ajax_json_req(req_obj, '/keypair_req');
                        let keypair = crypto_box_keypair();
                        ajax_c_priv_key = keypair.privateKey;
                        ajax_c_pub_key = keypair.publicKey;
                        let promise_rv;
                        try{
                            promise_rv = await promise;
                        }
                        catch(err){
                            return console.error(err.message);
                        }
                        ajax_s_pub_key = promise_rv.publicKey;
                        ajax_id_token = promise_rv.idToken;
                        return make_request();
                    }
                }
                if(res_obj.hasOwnProperty('error')) rej(new Error(res_obj.error));
                res(res_obj);
            };
        };
        make_request();
    });
};
let username;
let password;
const submit = async () =>{
    if(!sodium_set) return console.error('Sodium library not yet loaded');
    let req_obj = {
        action:'get',
        username:username
    };
    let req = s_ajax_json_req(req_obj, '/salts_req');
    let res_obj;
    try{
        res_obj = await req;
    }
    catch(err){
        return console.error(err.message);
    }
    let clientSalt = res_obj.clientSalt;
    let keygenSalt = res_obj.keygenSalt;
    const client_hash = new SHA3(256);
    client_hash.update(password + clientSalt);
    const keygen_hash = new SHA3(256);
    keygen_hash.update(password + keygenSalt);
    const key_pair = crypto_box_seed_keypair(keygen_hash.digest('ascii'));
    req_obj = {
        username:username,
        hash:client_hash.digest('hex'),
        publicKey:to_hex(key_pair.publicKey)
    };
    req = s_ajax_json_req(req_obj, '/auth_req');
    try{
        res_obj = await req;
    }
    catch(err){
        alert(err.message);
        return console.error(err.message);
    }
    localStorage.clear();
    localStorage.setItem('authToken', res_obj.authToken);
    //possibly rethink how private key is stored
    localStorage.setItem('privateKey', to_hex(key_pair.privateKey));
    localStorage.setItem('publicKey', to_hex(key_pair.publicKey));
    window.location.href = "/";
};
</script>
<h1>Login</h1>
<form on:submit|preventDefault={submit}>
Username:<input type="text" bind:value={username}><br>
Password:<input type="password" bind:value={password}><br>
<button type="submit">Log In</button>
</form>
<form action="/create_account">
    <input type="submit" value="Create Account">
</form>
