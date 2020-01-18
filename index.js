const express = require('express');
const app = express();
const http = require('http').createServer(app);
const bodyParser = require('body-parser');
const crypto = require('crypto');
const SHA3 = require('sha3').SHA3;
const cookieParser = require('cookie-parser');

//investigate verbose at a different time
//useful for long stack traces
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('db/central.db', sqlite3.OPEN_READWRITE, (err)=>{
    if(err){
        console.error(err.message);
        console.error('failed to open database, consider running initdb.js before starting the server');
        process.exit(1);
    }
    else{console.log('opened connection to sqlite database @db/central.db');}
});

//NEED TO ADD RATE LIMITER

//currently everything running through http
//however switching to https is intended and straightforward
//avoiding for now to forgo security warnings for self signed cert

//const secrets = require('./secrets.js')

const generate_salt = () =>{
    let char_buf = Buffer.alloc(1);
    crypto.randomFillSync(char_buf);
    //using modulo 4 is fine as 256 % 4 == 0
    let salt_length = 6 + (char_buf[0] % 4);
    let rv_buf = Buffer.alloc(salt_length);
    crypto.randomFillSync(rv_buf);
    return rv_buf.toString('ascii');
};

const generate_auth_token = () =>{
    let rv_buf = Buffer.alloc(32);
    crypto.randomFillSync(rv_buf);
    return rv_buf.toString('hex');
};

/*  Parameters:
        req: request object from post request
        attr_mapping: object with two attributes:
            key, type mapping of optional arguments
            key, type mapping of required arguments
            e.g. {
                optional:{
                    'publicKey':'string'
                },
                required:{
                    'username':'string',
                    'hash':'string'
                }
            }
 */

//TODO check for bad JSON here
const is_bad_request = (req, attr_mapping) =>{
    const req_attrs = Object.keys(attr_mapping.required);
    const opt_attrs = Object.keys(attr_mapping.optional);
    let found_attrs_len = 0;
    let i;
    for(i = 0; i < req_attrs.length; i++){
        if(!req.body.hasOwnProperty(req_attrs[i])){
            return true;
        }
        else if(typeof req.body[req_attrs[i]] != attr_mapping.required[req_attrs[i]]){
            return true;
        }
        found_attrs_len++;
    }
    for(i = 0; i < opt_attrs.length; i++){
        if(req.body.hasOwnProperty(opt_attrs[i])){
            if(typeof req.body[opt_attrs[i]] !== attr_mapping.optional[opt_attrs[i]]){
                return true;
            }
            found_attrs_len++;
        }
    }
    //check if any incorrect keys sent
    if(found_attrs_len != Object.keys(req.body).length){
        return true;
    }
    return false;
};

//global costants
const cookie_authToken = 'e2ee-im-gang-authToken';
const cookie_publicKey = 'e2ee-im-gang-publicKey';
const token_valid_seconds = 24*60*60;
const token_refresh_seconds = 60*60;

app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(cookieParser());

app.get('/', (req, res)=>{
    const cookies = Object.assign({},req.cookies);
    const login_redirect = ()=>{res.redirect('/login');};
    if(cookies.hasOwnProperty(cookie_authToken) && cookies.hasOwnProperty(cookie_publicKey)){
        db.get('select public_key from AuthTokens where token=?', cookies[cookie_authToken], (err, row)=>{
            if(err){console.error(err.message); return res.status(500).end();}
            if(!row){return login_redirect();}
            if(cookies[cookie_publicKey] !== row.public_key){return login_redirect();}
            res.sendFile(__dirname + '/pages/index.html');
        });
    }
    else{login_redirect();}
});

//later setup automatic login from this page also
app.get('/login', (req, res)=>{
    const cookies = Object.assign({},req.cookies);
    const send_login = () =>{res.sendFile(__dirname + '/pages/login.html');};
    if(cookies.hasOwnProperty(cookie_authToken) && cookies.hasOwnProperty(cookie_publicKey)){
        db.get('select public_key from AuthTokens where token=?', cookies[cookie_authToken], (err, row)=>{
            if(err){console.error(err.message); return res.status(500).end();}
            if(!row){return send_login();}
            if(cookies[cookie_publicKey] !== row.public_key){return send_login();}
            res.redirect('/');
        });
    }
    else{send_login();}
});

app.get('/create_account', (req, res)=>{
    res.sendFile(__dirname + '/pages/create_account.html');
});

/*  post request of type: json
    required attributes:
        action: (must have action 'new' or 'get')
    optional attributes:
        username: (must be included if action is 'get')
    outside of this response will be 400
*/
app.post('/salts_req', (req, res)=>{
    attr_mapping = {
        required:{
            'action':'string'
        },
        optional:{
            'username':'string'
        }
    };
    if(is_bad_request(req, attr_mapping)){return res.status(400).end();}
    if(req.body['action'] == 'get'){
        if(!req.body.hasOwnProperty('username')){
            return res.status(400).end();
        }
        db.get('select client_salt, keygen_salt from Users where username=?', [req.body.username], (err, row)=>{
            if(err){return res.status(500).end();}
            if(!row){return res.send({error:'user does not exist'});}
            res.send({clientSalt:row.client_salt, keygenSalt:row.keygen_salt});
        });
    }
    else if(req.body.action === 'new'){
        const client_salt = generate_salt();
        const keygen_salt = generate_salt();
        res.send({clientSalt:client_salt, keygenSalt:keygen_salt});
    }
    else{return res.status(400).end();}
});

app.post('/auth_req', (req, res)=>{
    const attr_mapping = {
        required:{
            'username':'string',
            'hash':'string',
            'publicKey':'string'
        },
        optional:{}
    };
    const inval_login = ()=>{res.send({error:"invalid login credentials"});}
    if(is_bad_request(req, attr_mapping)){return res.status(400).end();}
    db.get('select hash, server_salt, UserID, pw_public_key from Users where username=?', [req.body.username], (err, row)=>{
        if(err){console.error(err.message);return res.status(500).end();}
        if(!row){return inval_login();}
        const pw_hash = new SHA3(256);
        pw_hash.update(req.body.hash + row.server_salt);
        const hex_pw_hash = pw_hash.digest('hex');
        if(hex_pw_hash != row.hash){return inval_login();}
        let token = generate_auth_token();
        const expiration = (new Date()).getTime() + token_valid_seconds;
        const user_id = row.UserID;
        const public_key = row.pw_public_key;
        //technically has potential to be stuck infinitely
        //but probability is incredibly low and is secured with csprng
        const callback_y = (err, row) =>{
            if(err){console.error(err.message);return res.status(500).end();}
            if(row){
                token = generate_auth_token();
                db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
            }
            else{
                db.run('insert into AuthTokens(token, expiration, UserID, public_key) values(?,?,?,?)',
                    [token, expiration, user_id, public_key],(err)=>{
                        if(err){console.error(err.message);return res.status(500).end();}
                        res.cookie(cookie_publicKey, public_key);
                        res.cookie(cookie_authToken, token);
                        res.send({authToken:token});
                    });
            }
        };
        if(req.body.publicKey === public_key){
            db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
        }
        else{
            db.get('select DeviceID from Devices where UserID=? AND public_key=?',[
                row.UserID, req.body.publicKey], (err, row) =>{
                    if(err){console.error(err.message);return res.status(500).end();}
                    if(!row){return res.send({error:'unrecognised public key, please retry login'});}
                    db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
                });
        }
    });
});


//TODO
//add hex string checking for hash and publicKey
//especiallly publicKey
app.post('/create_account', (req, res)=>{
    const attr_mapping = {
        required:{
            'email':'string',
            'username':'string',
            'hash':'string',
            'clientSalt':'string',
            'keygenSalt':'string',
            'publicKey':'string'
        },
        optional:{
            'deviceName':'string',
            'devicePublicKey':'string'
        }
    };
    //device specific keys currently not implemented
    if(is_bad_request(req, attr_mapping)){return res.status(400).end();}
    db.get('select username from Users where username=?', [req.body['username']], (err, row) => {
        if(err){console.error(err.message);return res.status(500).end();}
        if(row){return res.send({error:'user already exists'});}
        db.get('select email from Users where email=?', req.body['email'], (err, row)=>{
            if(err){console.error(err.message);return res.status(500).end();}
            if(row){return res.send({error:'email already in use'});}
            const server_salt = generate_salt();
            const pw_hash = new SHA3(256);
            //ignoring non-conversion from hexstring to buffer for req hash
            //as long as it's kept consistent there's no issue
            pw_hash.update(req.body.hash + server_salt);
            const hex_pw_hash = pw_hash.digest('hex');
            db.run(`insert into Users(
                email, username, hash, client_salt,
                keygen_salt, server_salt, pw_public_key)
                values(?,?,?,?,?,?,?)`,[
                req.body.email,
                req.body.username,
                hex_pw_hash,
                req.body.clientSalt,
                req.body.keygenSalt,
                server_salt,
                req.body.publicKey], function(err){
                if(err){console.error(err.message);return res.send(500).end();}
                let token = generate_auth_token();
                const expiration = (new Date()).getTime() + token_valid_seconds;
                const user_id = this.lastID;
                //technically has potentially to be stuck infinitely
                //but probability is incredibly low
                const callback_y = (err, row)=>{
                    if(err){console.error(err.message);return res.status(500);}
                    if(row){
                        token = generate_auth_token();
                        db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
                    }
                    else{
                        //very low probability race condition, resulting in 500
                        db.run('insert into AuthTokens(token, expiration, UserID, public_key) values(?,?,?,?)',
                            [token, expiration, user_id, req.body.publicKey], (err)=>{
                                if(err){console.error(err.message);return res.status(500);}
                                res.cookie(cookie_authToken, token);
                                res.cookie(cookie_publicKey, req.body.publicKey);
                                res.send({authToken:token});
                            });
                    }
                };
                db.get('select AuthTokenID from AuthTokens where token=?', [token], callback_y);
            });
        });
    });
});

//for now assuming that the number of conversations is able to be completely loaded
//future may implement ajax method of loading more conversations
app.post('/convo_req', (req, res) =>{
    const attr_mapping = {
        required:{
            'authToken':'string',
        },
        optional:{
            'deviceID':'number'
        }
    };
    if(is_bad_request(attr_mapping)){return res.status(400).end();}
    db.get('select UserID, expiration from AuthTokens where token=?', [req.body.authToken], function(err, row){
        if(err){console.error(err.message); return res.status(500).end();}
        if(!row){return res.send({auth_status:false, error:'auth_token not valid'});}
        if(row.expiration < (new Date()).getTime()){
            return res.send({auth_status:false, error:'session has expired'});
        }
        const user_id = row.UserID;
        if(expiration < (new Date()).getTime() + token_valid_seconds - token_refresh_seconds){
            const new_expiration = (new Date()).getTime() + token_valid_seconds;
            db.run('update AuthTokens set expiration=? where token=?', [new_expiration, req.body.authToken], (err)=>{
                if(err){console.error(err.message);}
            });
        }
        let is_device = req.body.hasOwnProperty('deviceID');
        db.all(`select * from UserConversationMap
            LEFT JOIN Conversations on Conversations.ConversationID=UserConversationMap.ConversationID
            where UserID=?`, [req.body.userID], (err, rows)=>{
                if(err){console.error(err.message); return res.status(500).end();}
                let records = rows;
                const convo_obj_prototype = {
                    id:-1,
                    name:'default',
                    last_msg_digest:'deadd0d0'
                };
                let convo_list = [];
                const record_loop = ()=>{
                    if(records.length > 0){
                        let next_record = records.pop();
                        let next_convo = Object.create(convo_obj_prototype);
                        next_convo.id = next_record.ConversationID;
                        next_convo.name = (next_record.custom_name) ? next_record.custom_name : next_record.default_name;
                        db.get(`select MessageID, senttime, username from Messages
                            left join Users on Users.UserID=Messages.senderID where ConversationID=?`,
                            [next_record.ConversationID], (err, row)=>{
                                if(err){console.error(err.message);record_loop();}
                                if(!row){console.error('no corresponding message for device');}
                                db.get(`select contents from digests
                                    left join Messages ON Messages.MessageID=Digests.MessageID
                                    where MessageID=? order by senttime desc`, [row.MessageID], (err, row)=>{
                                        if(err){console.error(err.message);record_loop();}
                                        if(!row){next_convo.last_msg_digest = '';}
                                        else{next_convo.last_msg_digest = row.contents;}
                                        convo_list.unshift(next_convo);
                                        record_loop();
                                    });
                            });
                    }
                    else{
                        res.send({conversation_objs:convo_list});
                    }
                };
                record_loop();
        });
    });
});

app.post('/messages_req', (req, res)=>{
    const attr_mapping = {
        required:{
            'authToken':'string',
            'conversationID':'number'
        },
        optional:{
            'deviceID':'number'
        }
    };
    if(is_bad_request(attr_mapping)){return res.status(400).end();}
    db.get('select UserID, expiration from AuthTokens where token=?', [req.body.authToken], function(err, row){
        if(err){console.error(err.message); return res.status(500).end();}
        if(!row){return res.send({auth_status:false, error:'auth_token not valid'});}
        if(row.expiration < (new Date()).getTime()){
            return res.send({auth_status:false, error:'session has expired'});
        }
        const user_id = row.UserID;
        //refresh token if hasn't been refreshed for an hour
        if(expiration < (new Date()).getTime() + token_valid_seconds - token_refresh_seconds){
            const new_expiration = (new Date()).getTime() + token_valid_seconds;
            db.run('update AuthTokens set expiration=? where token=?', [new_expiration, req.body.authToken], (err)=>{
                if(err){console.error(err.message);}
            });
        }
        db.get('select * from UserConversationMap where UserID=? and ConversationID=?', [user_id, req.body.conversationID], (err, row)=>{
            if(err){console.error(err.message); return res.status(500).end();}
            //accessing illegal conversationid
            //technically could be 403 or 404 but no need to give unneccessary information
            if(!row){return res.status(403).end();}
            const digests_callback = (err, rows) =>{
                //imperitave that messages are ordered correctly in the message list
                let message_list = [];
                const message_obj_prototype = {
                    sender:'username',
                    digest:'deadd0d0',
                    time:0
                }
                for(let i = 0; i < rows.length; i++){
                    let next_msg = Object.create(message_obj_prototype);
                    next_msg.sender = rows[i].username;
                    next_msg.digest = rows[i].contents;
                    next_msg.time = rows[i].senttime;
                }
                res.send({message_objs:message_list});
            }
            if(req.body.hasOwnProperty('deviceID')){
                //can get other users digests for the same conversation
                //shouldn't be a security flaw as you can already calculate that with their
                //public keys and your decrypted digests
                //also digests aren't very useful
                db.all(`select contents, senttime, username from Digests
                    left join Messages on Messages.MessageID=Digests.MessageID
                    left join Users on Users.UserID=Messages.SenderID
                    where ConversationID=? and DeviceID=?
                    order by senttime desc`, [req.body.conversationID, req.body.DeviceID], digests_callback);
            }
            else{
                db.all(`select contents, senttime, username from Digests
                    left join Messages on Messages.MessageID=Digests.MessageID
                    left join Users on Users.UserID=Digests.UserID
                    where ConversationID=? and UserID=?
                    order by senttime desc`, [req.body.conversationID, user_id], digests_callback);
            }
        });
    });
});

app.post('/keys_req', (req, res)=>{
    const attr_mapping = {
        required:{
            'authToken':'string',
            'conversationID':'number'
        },
        optional:{}
    };
    if(is_bad_request(attr_mapping)){return res.status(400).end();}
    db.get('select UserID, expiration from AuthTokens where token=?', [req.body.authToken], function(err, row){
        if(err){console.error(err.message); return res.status(500).end();}
        if(!row){return res.send({auth_status:false, error:'auth_token not valid'});}
        if(row.expiration < (new Date()).getTime()){
            return res.send({auth_status:false, error:'session has expired'});
        }
        const user_id = row.UserID;
        //refresh token if hasn't been refreshsed for an hour
        if(expiration < (new Date()).getTime() + token_valid_seconds - token_refresh_seconds){
            const new_expiration = (new Date()).getTime() + token_valid_seconds;
            db.run('update AuthTokens set expiration=? where token=?', [new_expiration, req.body.authToken], (err)=>{
                if(err){console.error(err.message);}
            });
        }
        db.get('select * from UserConversationMap where UserID=? and ConversationID=?', [user_id, req.body.conversationID], (err, row)=>{
            if(err){console.error(err.message); return res.status(500).end();}
            //accessing illegal conversationid
            //technically could be 403 or 404 but no need to give unneccessary information
            if(!row){return res.status(403).end();}
            db.all(`select DeviceID, public_key from Devices
                left join UserConversationMap on UserConversationMap.UserID=Devices.DeviceID
                where ConversationID=?`, [req.body.conversationID], (err, rows)=>{
                    if(err){console.error(err.message); return res.status(500).end();}
                    let device_key_list = [];
                    const device_key_obj_prototype = {
                        id:-1,
                        key:'deadd0d0'
                    };
                    for(let i = 0; i < rows.length; i++){
                        const new_device = Object.create(device_key_obj_prototype);
                        new_device_key.id = rows[i].DeviceID;
                        new_device_key.key = rows[i].public_key;
                        device_key_list.push(new_device_key);
                    }
                    db.all(`select UserID, pw_public_key from UserConversationMap
                        left join Users on Users.UserID=UserConversationMap.UserID
                        where ConversationID=?`, [req.body.conversationID], (err, rows)=>{
                            if(err){console.error(err.message); return res.status(500).end();}
                            let user_key_list = [];
                            const user_key_obj_prototype = {
                                id:-1,
                                key:'deadd0d0'
                            };
                            for(let i = 0; i < rows.length; i++){
                                const new_user_key = Object.create(user_key_obj_prototype);
                                new_user_key.id = rows[i].UserID;
                                new_user_key.key = rwos[i].pw_public_key;
                                user_key_list.push(new_user_key);
                            }
                            res.send({
                                deviceKeys:device_key_list,
                                userKeys:user_key_list
                            });
                        });
                })
        });
    });
});

/*
 * digests object expected in form:
    {
        userDigests:[{id:<some_id>, digest:<some_digest>}, ...]
        deviceDigests:[{id:<some_id>, digest:<some_digest>}, ...]
    }
 */

app.post('/message_send', (req, res)=>{
    const req_time = new Date();
    const attr_mapping = {
        required:{
            'authToken':'string',
            'conversationID':'number',
            'digests':'object'
        },
        optional:{}
    };
    if(is_bad_request(attr_mapping)){return res.status(400).end();}
    if(!req.body.digests.hasOwnProperty('userDigests') || !req.body.digests.hasOwnProperty('deviceDigests')){
        return res.status(400).end();
    }
    if(typeof req.body.digests.userDigests != 'list' || typeof req.body.digests.deviceDigests != 'list'){
        return res.status(400).end();
    }
    const user_digests = req.body.digests.userDigests;
    const device_digests = req.body.digests.deviceDigests;
    for(let i = 0; i < user_digests.length; i++){
        if(typeof user_digests[i] != 'object'){return res.status(400).end();}
        if(!user_digests[i].hasOwnProperty('id') || !user_digests[i].hasOwnProperty('digest')){
            return res.status(400).end();
        }
        if(typeof user_digests[i].id != 'string' || typeof user_digests[i].digest != 'string'){
            return res.status(400).end();
        }
    }
    //finished typechecking json
    db.get('select UserID, expiration from AuthTokens where token=?', [req.body.authToken], function(err, row){
        if(err){console.error(err.message); return res.status(500).end();}
        if(!row){return res.send({auth_status:false, error:'auth_token not valid'});}
        if(row.expiration < (new Date()).getTime()){
            return res.send({auth_status:false, error:'session has expired'});
        }
        const user_id = row.UserID;
        //refresh token if hasn't been refreshsed for an hour
        if(expiration < (new Date()).getTime() + token_valid_seconds - token_refresh_seconds){
            const new_expiration = (new Date()).getTime() + token_valid_seconds;
            db.run('update AuthTokens set expiration=? where token=?', [new_expiration, req.body.authToken], (err)=>{
                if(err){console.error(err.message);}
            });
        }
        db.get('select * from UserConversationMap where UserID=? and ConversationID=?', [user_id, req.body.conversationID], (err, row)=>{
            if(err){console.error(err.message); return res.status(500).end();}
            //accessing illegal conversationid
            //technically could be 403 or 404 but no need to give unneccessary information
            if(!row){return res.status(403).end();}
            db.all('select UserID from UserConversationMap where ConversationID=?', [req.body.conversationID], (err, rows)=>{
                if(user_digests.length < rows.length){return res.send({error:'missing digests, refresh to send messages to new members'});}
                let req_user_ids = {};
                for(let i = 0; i < rows.length; i++){
                    req_user_ids[rows.UserID] = null;
                }
                for(let i = 0; i < user_digests.length; i++){
                    if(!req_user_ids.hasOwnProperty(user_digests[i].id)){
                        return res.status(400).end();
                    }
                }
                db.all(`select DeviceID from Devices
                    left join UserConversationMap UserConversationMap.UserID=Devices.UserID
                    where ConversationID=?`, [req.body.conversationID], (err, rows)=>{
                        if(device_digests.length != rows.length){return res.send({error:'missing digests, refresh to send messages to new members'});}
                        let req_device_ids = {};
                        for(let i  = 0; i < rows.length; i++){
                            req_device_ids[rows.DeviceID] = null;
                        }
                        for(let i = 0; i < device_digests.length; i++){
                            if(!device_user_ids.hasOwnProperty(device_digests[i].id)){
                                return res.status(400).end();
                            }
                        }
                        //at this point request is confirmed to be appropriate
                        //possibly look into how to revert inserts in case of errors with database inserts
                        db.run('insert into Messages(SenderID, ConversationID, senttime) values(?,?,?)',[user_id, req.body.ConversationID, req_time.getTime()], function(err){
                            if(err){console.error(err.message);return res.status(500).end();}
                            const message_id = this.lastID;
                            for(let i = 0; i < device_digests.length; i++){
                                //technically can insert junk digest but no way for server to verify that it isn't junk
                                //without knowing too much information
                                db.run('insert into Digests(contents, MessageID, UserID) values(?,?,?)',
                                    [device_digests[i].digest, message_id, device_digests[i].id], (err)=>{
                                        if(err){console.error(err.message);}
                                    });
                            }
                            for(let i = 0; i < user_digests.length; i++){
                                db.run('insert into Digests(contents, MessageID, DeviceID) values(?,?,?)',
                                    [device_digests[i].digest, message_id, device_digests[i].id], (err)=>{
                                        if(err){console.error(err.message);}
                                    });
                            }
                            //sending status not useful but do not want to send empty object
                            res.send({status:'success'});
                        });
                    });
            });
        });
    });
});

http.listen(3000, (err)=>{
    if(err){console.error(err.message);}
    else{console.log('http server started at localhost:3000');}
});
