const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const bodyParser = require('body-parser');
const crypto = require('crypto');
const SHA3 = require('sha3').SHA3;
const cookieParser = require('cookie-parser');
const sodium = require('sodium').api;

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

//global costants
const cookie_authToken = 'e2ee-im-gang-authToken';
const cookie_publicKey = 'e2ee-im-gang-publicKey';
const token_valid_ms = 24*60*60*1000;
const token_refresh_ms = 60*60*1000;
const keypair_valid_ms = 10*60*1000;

const generate_salt = () =>{
    let char_buf = Buffer.alloc(1);
    crypto.randomFillSync(char_buf);
    //using modulo 4 is fine as 256 % 4 == 0
    let salt_length = 6 + (char_buf[0] % 4);
    let rv_buf = Buffer.alloc(salt_length);
    crypto.randomFillSync(rv_buf);
    return rv_buf.toString('ascii');
};

const generate_hash_token = () =>{
    let rv_buf = Buffer.alloc(32);
    crypto.randomFillSync(rv_buf);
    return rv_buf.toString('hex');
};

const is_hex = (str) =>{
	if(typeof str != 'string') return false;
	for(let i = 0; i < str.length; i++){
		if(!('0' <= str[i] && str[i] <= '9') && !('a' <= str[i] && str[i] <= 'f')) return false;
	}
	return true;
};

const is_key = (str)=>{
	if(!is_hex(str)) return false;
	return str.length == 64;
};

//returns -1 for invalid auth token
//returns userID for valid token
const verify_auth_token = async (token)=>{
    let rv_promise = new Promise(async(res, rej)=>{
        let promise = new Promise((res, rej)=>{
            db.get('select UserID, expiration from AuthTokens where token=?', [token], (err, row)=>{
                if(err) throw err;
                if(!row){return res(-1);}
                if(row.expiration < (new Date()).getTime()){return res(-1);}
                if(row.expiration < (new Date()).getTime() + token_valid_ms - token_refresh_ms){
                    const new_expiration = (new Date()).getTime() + token_valid_ms;
                    db.run('update AuthTokens set expiration=? where token=?', [new_expiration, token], (err)=>{
                        if(err) console.error(err.message);
                    });
                }
                res(row.UserID);
            });
        });
        let rv;
        try{
            rv = await promise;
        }
        catch (err){
            console.error(err.message);
            rv = -1;
        }
        res(rv);
    });
    return rv_promise;
}

let user_socket_map = {};
let socket_user_map = {};

io.on('connection', (socket)=>{
	socket.is_secure_protocol = false;
	socket.use((packet, next)=>{
		if(!socket.is_secure_protocol) return next();
		let new_packet = [packet[0]];
		for(let i = 1; i < packet.length; i++){
			const decrypted = sodium.crypto_box_seal_open(Buffer.from(packet[i], 'hex'), socket.s_public_key, socket.s_private_key);
			new_packet.push(JSON.parse(decrypted.toString()));
		}
		packet.splice(0, packet.length, ...new_packet);
		next();
	});
	socket.on('secure_req', (public_key)=>{
		if(!is_key(public_key))
			return console.error('socket sent bad publicKey');
		const keypair = sodium.crypto_box_keypair();
		socket.s_public_key = keypair.publicKey;
		socket.s_private_key = keypair.secretKey;
		socket.c_public_key = Buffer.from(public_key, 'hex');
		socket.is_secure_protocol = true;
		socket.emit('secure_res', socket.s_public_key.toString('hex'));
	});
	//does nnot allow for callback function at this stage
	socket.s_emit = (...args)=>{
		if(!socket.is_secure_protocol) return socket.emit(...args);
		let digests = [args[0]];
		for(let i = 1; i < args.length; i++){
			console.log(socket.c_public_key);
			const digest = sodium.crypto_box_seal(Buffer.from(JSON.stringify(args[i])), socket.c_public_key).toString('hex');
			digests.push(digest);
		}
		socket.emit(...digests);
	};

	socket.s_emit('auth_req');
	socket.on('auth_res', async (token, device_id)=>{
		let verification_promise = verify_auth_token(token);
		let user_id = await verification_promise;
		if(user_id == -1){
			socket.s_emit('auth_status', 'rejected');
			return socket.disconnect(true);
		}
		//race condition here losing ~1 socket if simultaneous requests from same user
		//uncertain how to fix
		if(!user_socket_map.hasOwnProperty(user_id)){
			user_socket_map[user_id] = {};
		}
		user_socket_map[user_id][socket.id] = {socket:socket};
		if(device_id) user_socket_map[user_id][socket.id].device_id = device_id;
		socket_user_map[socket.id] = user_id;
	});
	socket.on('disconnect', ()=>{
		//have had strange behaviour with socket disconnects
		//causing socket point to undefined object before deletion
		//need to investigate
		const user_id = socket_user_map[socket.id];
		delete socket_user_map[socket.id];
		delete user_socket_map[user_id][socket.id];
	});
});


//below is a helper function for is_bad_request, parsing
//objects as mapped by attr mapping
//it may also be called without being wrapped with is_bad_request
const is_wrong_object = (obj, attr_mapping) =>{
	if(Array.isArray(obj)){
        if(!Array.isArray(attr_mapping)) return true;
        for(let i = 0; i < obj.length; i++){
            if(typeof obj[i] === 'object'){
                if(typeof attr_mapping[0] !== 'object') return true;
                if(is_wrong_object(obj[i], attr_mapping[0])) return true;
            }
        }
        return false;
    }
    const attrs = Object.keys(attr_mapping);
    let found_attrs_len = 0;
    for(let i = 0; i < attrs.length; i++){
        if(!obj.hasOwnProperty(attrs[i])) return true;
        const type = attr_mapping[attrs[i]];
        if(type === 'hex' || type === 'hash' || type === 'key'){
        	if(typeof obj[attrs[i]] !== 'string') return true;
        	if(type === 'key' || type === 'hash'){
        		if(obj[attrs[i]].length != 64) return true;
        	}
        	//char by char search because regex is awful
        	for(let j = 0; j < obj[attrs[i]].length; j++){
        		const c = obj[attrs[i]][j];
        		if(!('0' <= c && c <= '9') && !('a' <= c && c <= 'f')) return true;
        	}
        }
        else if(typeof obj[attrs[i]] === 'object'){
            if(typeof attr_mapping[attrs[i]] !== 'object') return true;
            if(is_wrong_object(obj[attrs[i]], attr_mapping[attrs[i]])) return true;
        }
        else if(typeof obj[attrs[i]] != attr_mapping[attrs[i]]){
            return true;
        }
        found_attrs_len++;
    }
    //check if any incorrect keys sent
    if(found_attrs_len != Object.keys(obj).length){
        return true;
    }
    return false;
}

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
    NOTE:
    adds special types:
    	"hex" for checking if string is hex string
    	"key" for checking if string is curv25519 public key
    	"hash" for checking is string is sha3-256 hash
    encryptedObject is a reserved key used in middleware
 */

//TODO check for bad JSON here
const is_bad_request = (req_obj, attr_mapping) =>{
    const req_attrs = Object.keys(attr_mapping.required);
    const opt_attrs = Object.keys(attr_mapping.optional);
    let found_attrs_len = 0;
    for(let i = 0; i < req_attrs.length; i++){
        if(!req_obj.hasOwnProperty(req_attrs[i])) return true;
        const type = attr_mapping.required[req_attrs[i]];
        if(type === 'hex' || type == 'hash' || type == 'key'){
        	if(typeof req_obj[req_attrs[i]] != 'string') return true;
        	if(type === 'key' || type === 'hash'){
        		if(req_obj[req_attrs[i]].length != 64) return true;
        	}
        	//char by char search because regex is awful
        	for(let j = 0; j < req_obj[req_attrs[i]].length; j++){
        		const c = req_obj[req_attrs[i]][j];
        		if(!('0' <= c && c <= '9') && !('a' <= c && c <= 'f')) return true;
        	}
        }
        else if(typeof req_obj[req_attrs[i]] === 'object'){
        	if(typeof attr_mapping.required[req_attrs[i]] !== 'object') return true;
        	if(is_wrong_object(req_obj[req_attrs[i]], attr_mapping.required[req_attrs[i]])) return true;
        }
        else if(typeof req_obj[req_attrs[i]] !== attr_mapping.required[req_attrs[i]]){
            return true;
        }
        found_attrs_len++;
    }
    for(let i = 0; i < opt_attrs.length; i++){
        if(req_obj.hasOwnProperty(opt_attrs[i])){
        	const type = attr_mapping.optional[opt_attrs[i]];
        	if(type === 'hex' || type === 'key' || type === 'hash'){
        		if(typeof req_obj[req_attrs[i]] != 'string') return true;
        		if(type === 'key' || type === 'hash'){
	        		if(req_obj[opt_attrs[i]].length != 64) return true;
	        	}
        		for(let j = 0; j < req_obj[opt_attrs[i]].length; j++){
        			const c = req_obj[opt_attrs[i]][j];
        			if(!('0' <= c && c <= '9') && !('a' <= c && c <= 'f')) return true;
        		}
        	}
        	else if(typeof req_obj[opt_attrs[i]] === 'object'){
        		if(typeof attr_mapping.optional[opt_attrs[i]] !== 'object') return true;
        		if(is_wrong_object(req_obj[req_attrs[i]], attr_mapping.optional[opt_attrs[i]])) return true;
        	}
            else if(typeof req_obj[opt_attrs[i]] !== type){
                return true;
            }
            found_attrs_len++;
        }
    }
    //check if any incorrect keys sent
    if(found_attrs_len != Object.keys(req_obj).length){
        return true;
    }
    return false;
};

/******************
 *** MIDDLEWARE ***
 ******************/

app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());
app.use(cookieParser());
//add secure json transimission protocol
//only use for post requests
app.use(async (req, res, next)=>{
	res.is_secure_protocol = false;
	res.s_send = (to_send)=>{
		if(!res.is_secure_protocol) return res.send(to_send);
		const digest = sodium.crypto_box_seal(Buffer.from(JSON.stringify(to_send)), res.res_pkey).toString('hex');
		const res_obj = {
			idToken:res.res_idToken,
			encryptedObject:digest
		};
		res.send(res_obj);
	};
	if(req.body == null) next();
	try{
		if(req.body.hasOwnProperty('encryptedObject')){
			const req_obj = req.body.encryptedObject;
			const attr_mapping = {
				idToken:'hash',
				digest:'hex'
			};
			if(is_wrong_object(req_obj, attr_mapping))
				throw new Error('bad encryptedObject');
			let promise = new Promise((res, rej)=>{
				db.get(`select server_public_key, server_private_key, client_public_key, expiration
					from KeyPair where id_token=?`, [req_obj.idToken], (err, row)=>{
						if(err) throw err;
						if(!row) throw new Error('no such object key');
						res(row);
					});
			});
			let keypair_inf = await promise;
			if(keypair_inf.expiration < (new Date()).getTime())
				return res.send({keypairStatus:false});
			let decrypted = sodium.crypto_box_seal_open(
				Buffer.from(req_obj.digest, 'hex'),
				keypair_inf.server_public_key,
				keypair_inf.server_private_key);
			//creating a seperate variable so that the json error can be caught
			//without adding an attribute to the request object
			let decrypted_obj = JSON.parse(decrypted);
			req.is_secure_protocol = true;
			req.decrypted_obj = decrypted_obj;
			res.res_pKey = keypair_inf.client_public_key;
			res.res_idToken = req_obj.idToken
		}
	}
	catch(err){
		console.error(err);
	}
	next();
});

/********************
 *** GET REQUESTS ***
 ********************/

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

/*********************
 *** POST REQUESTS ***
 *********************/

 app.post('/keypair_req', async (req, res)=>{
 	attr_mapping = {
 		required:{
 			publicKey:'key'
 		},
 		optional:{}
 	};
 	const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
 	if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
 	let promise = new Promise(async (res, rej)=>{
 		let new_token = generate_hash_token();
 		while(true){
 			let promise = new Promise((res, rej)=>{
 				db.get('select * from KeyPair where id_token=?', [new_token], (err, row)=>{
 					if(err) throw err;
 					if(!row) return res(true);
 					res(false);
 				})
 			});
 			let promise_result;
 			try{
 				promise_result = await promise;
 			}
 			catch (err) {
 				throw err;
 			}
 			if(promise_result){
 				break;
 			}
 			new_token = generate_hash_token();
 		}
 		let keypair = sodium.crypto_box_keypair();
 		res_obj = {
 			idToken:new_token,
 			publicKey:keypair.publicKey.toString('hex')
 		};
 		const expiration_time = (new Date()).getTime() + keypair_valid_ms;
 		//unbelievably unlikely race condition where token evaluates to the same hash
 		//before one of the records is inserted
 		db.run(`insert into KeyPair(id_token, server_public_key, server_private_key, client_public_key, expiration)
 			values(?,?,?,?,?)`, [new_token, keypair.publicKey, keypair.secretKey, body_obj.publicKey, expiration_time], (err)=>{
 				if(err) console.error(err.message);
 			});
 		res(res_obj);
 	});
 	let res_obj;
 	try{
 		res_obj = await promise;
 	}
 	catch(err){
 		console.error(err.message);
 		res.status(500).end();
 	}
 	res.s_send(res_obj);
});

app.post('/salts_req', (req, res)=>{
    attr_mapping = {
        required:{
            'action':'string'
        },
        optional:{
            'username':'string'
        }
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    if(body_obj['action'] == 'get'){
        if(!body_obj.hasOwnProperty('username')){
            return res.status(400).end();
        }
        const username = body_obj.username.toLowerCase();
        db.get('select client_salt, keygen_salt from Users where username=?', [username], (err, row)=>{
            if(err){return res.status(500).end();}
            if(!row){return res.s_send({error:'user does not exist'});}
            res.s_send({clientSalt:row.client_salt, keygenSalt:row.keygen_salt});
        });
    }
    else if(body_obj.action === 'new'){
        const client_salt = generate_salt();
        const keygen_salt = generate_salt();
        res.s_send({clientSalt:client_salt, keygenSalt:keygen_salt});
    }
    else{return res.status(400).end();}
});

app.post('/user_req', async (req, res)=>{
    const attr_mapping = {
        required:{
            'authToken':'hex'
        },
        optional:{}
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    let verification_promise = verify_auth_token(body_obj.authToken);
    const user_id = await verification_promise;
    if(user_id == -1) return res.s_send({authStatus:false, error:'auth_token not valid'});
    db.get('select username from Users where UserID=?', [user_id], (err, row) =>{
        if(err) return res.status(500).end();
        res.s_send({username:row.username});
    });
});

app.post('/auth_req', (req, res)=>{
    const attr_mapping = {
        required:{
            'username':'string',
            'hash':'hex',
            'publicKey':'hex'
        },
        optional:{}
    };
    const inval_login = ()=>{res.s_send({error:"invalid login credentials"});}
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    const username = body_obj.username.toLowerCase();
    db.get('select hash, server_salt, UserID, pw_public_key from Users where username=?', [username], (err, row)=>{
        if(err){console.error(err.message);return res.status(500).end();}
        if(!row){return inval_login();}
        const pw_hash = new SHA3(256);
        pw_hash.update(body_obj.hash + row.server_salt);
        const hex_pw_hash = pw_hash.digest('hex');
        if(hex_pw_hash != row.hash){return inval_login();}
        let token = generate_hash_token();
        const expiration = (new Date()).getTime() + token_valid_ms;
        const user_id = row.UserID;
        const public_key = row.pw_public_key;
        //technically has potential to be stuck infinitely
        //but probability is incredibly low and is secured with csprng
        const callback_y = (err, row) =>{
            if(err){console.error(err.message);return res.status(500).end();}
            if(row){
                token = generate_hash_token();
                db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
            }
            else{
                db.run('insert into AuthTokens(token, expiration, UserID, public_key) values(?,?,?,?)',
                    [token, expiration, user_id, public_key],(err)=>{
                        if(err){console.error(err.message);return res.status(500).end();}
                        res.cookie(cookie_publicKey, public_key);
                        res.cookie(cookie_authToken, token);
                        res.s_send({authToken:token});
                    });
            }
        };
        if(body_obj.publicKey === public_key){
            db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
        }
        else{
            db.get('select DeviceID from Devices where UserID=? AND public_key=?',[
                row.UserID, body_obj.publicKey], (err, row) =>{
                    if(err){console.error(err.message);return res.status(500).end();}
                    if(!row){return res.s_send({error:'unrecognised public key, please retry login'});}
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
            'hash':'hex',
            'clientSalt':'string',
            'keygenSalt':'string',
            'publicKey':'hex'
        },
        optional:{
            'deviceName':'string',
            'devicePublicKey':'string'
        }
    };
    //device specific keys currently not implemented
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    const username = body_obj.username.toLowerCase();
    let isalphanumeric = true;
    for(let i = 0; i < username.length; i++){
        if(!('a'<=username[i] && username[i]<='z') && !('0'<=username[i]&&username[i]<='9')){
            isalphanumeric = false;
            break;
        }
    }
    if(!isalphanumeric) return res.s_send({error:'only alphanumeric characters allowed in username'});
    db.get('select username from Users where username=?', [username], (err, row) => {
        if(err){console.error(err.message);return res.status(500).end();}
        if(row){return res.s_send({error:'user already exists'});}
        db.get('select email from Users where email=?', body_obj['email'], (err, row)=>{
            if(err){console.error(err.message);return res.status(500).end();}
            if(row){return res.s_send({error:'email already in use'});}
            const server_salt = generate_salt();
            const pw_hash = new SHA3(256);
            //ignoring non-conversion from hexstring to buffer for req hash
            //as long as it's kept consistent there's no issue
            pw_hash.update(body_obj.hash + server_salt);
            const hex_pw_hash = pw_hash.digest('hex');
            db.run(`insert into Users(
                email, username, hash, client_salt,
                keygen_salt, server_salt, pw_public_key)
                values(?,?,?,?,?,?,?)`,[
                body_obj.email,
                username,
                hex_pw_hash,
                body_obj.clientSalt,
                body_obj.keygenSalt,
                server_salt,
                body_obj.publicKey], function(err){
                if(err){console.error(err.message);return res.s_send(500).end();}
                let token = generate_hash_token();
                const expiration = (new Date()).getTime() + token_valid_ms;
                const user_id = this.lastID;
                //technically has potentially to be stuck infinitely
                //but probability is incredibly low
                const callback_y = (err, row)=>{
                    if(err){console.error(err.message);return res.status(500);}
                    if(row){
                        token = generate_hash_token();
                        db.get('select AuthTokenID from Authtokens where token=?', [token], callback_y);
                    }
                    else{
                        //very low probability race condition, resulting in 500
                        db.run('insert into AuthTokens(token, expiration, UserID, public_key) values(?,?,?,?)',
                            [token, expiration, user_id, body_obj.publicKey], (err)=>{
                                if(err){console.error(err.message);return res.status(500);}
                                res.cookie(cookie_authToken, token);
                                res.cookie(cookie_publicKey, body_obj.publicKey);
                                res.s_send({authToken:token});
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
app.post('/convo_req', async (req, res) =>{
    const attr_mapping = {
        required:{
            'authToken':'string',
        },
        optional:{
            'deviceID':'number'
            /*,
            'index_start':'number',
            'index_end'
            */
        }
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    let verification_promise = verify_auth_token(body_obj.authToken);
    const user_id = await verification_promise;
    if(user_id == -1) return res.s_send({authStatus:false, error:'auth_token not valid'});
    let conversations_promise = new Promise((res, rej)=>{
        db.all(`select Conversations.ConversationID, default_name, custom_name from UserConversationMap
            LEFT JOIN Conversations on Conversations.ConversationID=UserConversationMap.ConversationID
            where UserID=?`, [user_id], async (err, rows)=>{
                if(err) throw err;
                let records = rows;
                const convo_obj_prototype = {
                    id:-1,
                    name:'default',
                    last_msg_digest:'deadd0d0'
                };
                let convo_list = [];
                for(let i = 0; i < records.length; i++){
                    let next_convo = Object.create(convo_obj_prototype);
                    next_convo.id =  records[i].ConversationID;
                    next_convo.name = (records[i].custom_name) ? records[i].custom_name : records[i].default_name;
                    let last_digest_promise = new Promise((res, rej)=>{
                        const select_callback = (err, row)=>{
                            if(err) throw err;
                            if(!row) return res('');
                            res(row.contents);
                        };
                        if(body_obj.hasOwnProperty('deviceID')){
                            db.get(`select contents from Digests
                                left join Messages on Messages.MessageID=Digests.MessageID
                                left join on Conversations Conversations.ConversationID=Messages.ConversationID
                                where DeviceID=? and Conversations.ConversationID=? order by senttime desc`, [body_obj.deviceID, next_convo.id], select_callback)
                        }
                        else{
                            db.get(`select contents from Digests
                                left join Messages on Messages.MessageID=Digests.MessageID
                                left join Conversations on Conversations.ConversationID=Messages.ConversationID
                                where UserID=? and Conversations.ConversationID=? order by senttime desc`, [user_id, next_convo.id], select_callback)
                        };
                    });
                    try{
                        next_convo.last_msg_digest = await last_digest_promise;
                    }
                    catch(err){
                        throw err;
                    }
                    convo_list.push(next_convo);
                }
                res(convo_list);
        });
    });
    let conversation_obj_list;
    try{
        conversation_obj_list = await conversations_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(500).end();
    }
    return res.s_send({conversationObjects:conversation_obj_list});
});

app.post('/messages_req', async (req, res)=>{
    const attr_mapping = {
        required:{
            'authToken':'string',
            'conversationID':'number'
        },
        optional:{
            'deviceID':'number'
        }
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    let verification_promise = verify_auth_token(body_obj.authToken);
    const user_id = await verification_promise;
    if(user_id == -1) return res.s_send({authStatus:false, error:'auth_token not valid'});
    let permission_promise = new Promise((res, rej)=>{
        db.get('select UserID from UserConversationMap where UserID=? and ConversationID=?', [user_id, body_obj.conversationID], (err, row)=>{
            if(err) throw err;
            if(!row) return res(false);
            res(true);
        });
    });
    let has_permissions;
    try{
        has_permissions = await permission_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(500).end();
    }
    //accessing illegal conversationid
    //technically could be 403 or 404 but no need to give unneccessary information
    if(!has_permissions) return res.status(403).end();
    let messages_promise = new Promise((res, rej)=>{
        const digests_callback = (err, rows)=>{
            if(err) throw err;
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
                message_list.push(next_msg);
            }
            res(message_list);
        };
        if(body_obj.hasOwnProperty('deviceID')){
            //can get other users digests for the same conversation
            //shouldn't be a security flaw as you can already calculate that with their
            //public keys and your decrypted digests
            //also digests aren't very useful without keys
            db.all(`select contents, senttime, username from Digests
                left join Messages on Messages.MessageID=Digests.MessageID
                left join Users on Users.UserID=Messages.SenderID
                where ConversationID=? and DeviceID=?
                order by senttime asc`, [body_obj.conversationID, body_obj.deviceID], digests_callback);
        }
        else{
            db.all(`select contents, senttime, username from Digests
                left join Messages on Messages.MessageID=Digests.MessageID
                left join Users on Users.UserID=Messages.SenderID
                where ConversationID=? and Digests.UserID=?
                order by senttime asc`, [body_obj.conversationID, user_id], digests_callback);
        }
    });
    let message_objs;
    try{
        message_objs = await messages_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(500).end();
    }
    res.s_send({messageObjects:message_objs});
});

app.post('/keys_req', (req, res)=>{
    const attr_mapping = {
        required:{
            'authToken':'string',
            'conversationID':'number'
        },
        optional:{}
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    db.get('select UserID, expiration from AuthTokens where token=?', [body_obj.authToken], function(err, row){
        if(err){console.error(err.message); return res.status(500).end();}
        if(!row){return res.s_send({auth_status:false, error:'auth_token not valid'});}
        if(row.expiration < (new Date()).getTime()){
            return res.s_send({auth_status:false, error:'session has expired'});
        }
        const user_id = row.UserID;
        //refresh token if hasn't been refreshsed for an hour
        if(row.expiration < (new Date()).getTime() + token_valid_ms - token_refresh_ms){
            const new_expiration = (new Date()).getTime() + token_valid_ms;
            db.run('update AuthTokens set expiration=? where token=?', [new_expiration, body_obj.authToken], (err)=>{
                if(err){console.error(err.message);}
            });
        }
        db.get('select * from UserConversationMap where UserID=? and ConversationID=?', [user_id, body_obj.conversationID], (err, row)=>{
            if(err){console.error(err.message); return res.status(500).end();}
            //accessing illegal conversationid
            //technically could be 403 or 404 but no need to give unneccessary information
            if(!row){return res.status(403).end();}
            db.all(`select DeviceID, public_key from Devices
                left join UserConversationMap on UserConversationMap.UserID=Devices.DeviceID
                where ConversationID=?`, [body_obj.conversationID], (err, rows)=>{
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
                    db.all(`select Users.UserID, pw_public_key from UserConversationMap
                        left join Users on Users.UserID=UserConversationMap.UserID
                        where ConversationID=?`, [body_obj.conversationID], (err, rows)=>{
                            if(err){console.error(err.message); return res.status(500).end();}
                            let user_key_list = [];
                            const user_key_obj_prototype = {
                                id:-1,
                                key:'deadd0d0'
                            };
                            for(let i = 0; i < rows.length; i++){
                                const new_user_key = Object.create(user_key_obj_prototype);
                                new_user_key.id = rows[i].UserID;
                                new_user_key.key = rows[i].pw_public_key;
                                user_key_list.push(new_user_key);
                            }
                            res.s_send({
                                deviceKeys:device_key_list,
                                userKeys:user_key_list
                            });
                        });
                });
        });
    });
});

//possibly add device id verification here
app.post('/last_msg_req', async (req, res)=>{
    const attr_mapping = {
        required:{
            'authToken':'string',
            'conversationID':'number'
        },
        optional:{
            'deviceID':'number'
        }
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    let verification_promise = verify_auth_token(body_obj.authToken);
    const user_id = await verification_promise;
    if(user_id == -1) return res.s_send({authStatus:false, error:'auth_token not valid'});
    let permision_promise = new Promise((res, rej)=>{
        db.get('select * from UserConversationMap where UserID=? and ConversationID=?',
            [user_id, body_obj.conversationID], (err, row)=>{
                if(err) throw err;
                if(!row) return res(false);
                res(true);
            });
    });
    let is_convo = await permision_promise;
    if(!is_convo) return res.status(403).end();
    let last_digest_promise = new Promise((res, rej)=>{
        const select_callback = (err, row)=>{
            if(err) throw err;
            if(!row) return res('');
            res(row.contents);
        }
        if(body_obj.hasOwnProperty('deviceID')){
            db.get(`select contents from Digests
                left join Messages on Messages.MessageID=Digests.MessageID
                left join Conversations on Conversations.ConversationID=Messages.ConversationID
                where DeviceID=? and Conversations.ConversationID=? order by senttime desc`, [body_obj.deviceID, body_obj.conversationID], select_callback);
        }
        else{
            db.get(`select contents from Digests
                left join Messages on Messages.MessageID=Digests.MessageID
                left join Conversations on Conversations.ConversationID=Messages.ConversationID
                where UserID=? and Conversations.ConversationID=? order by senttime desc`, [user_id, body_obj.conversationID], select_callback);
        }
    });
    let digest;
    try{
        digest = await last_digest_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(400).end();
    }
    res.s_send({digest:digest});
});

/*  participants expected in form:
 *  participants[<username>,...]
 */

//must rate limit this
//bug where duplicate user conversation mapping entries can be created
//if a single user is enterred multiple times
app.post('/conversation_create', async (req, res)=>{
    req_time = new Date();
    const attr_mapping = {
        required:{
            'authToken':'string',
            'participants':['string']
        },
        optional:{
            'name':'string'
        }
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    let verification_promise = verify_auth_token(body_obj.authToken);
    const users = body_obj.participants;
    const user_id = await verification_promise;
    if(user_id == -1) return res.s_send({authStatus:false, error:'auth_token not valid'});
    let user_validation_arr = [];
    for(let i = 0; i < users.length; i++){
        let promise = new Promise((res, rej)=>{
            db.get('select UserID from Users where username=?', [users[i]], (err, row)=>{
                if(err) throw err;
                if(!row)  return res(-1);
                res(row.UserID);
            });
        });
        user_validation_arr.push(promise);
    }
    let user_ids = []
    let contains_user = false;
    for(let i = 0; i < user_validation_arr.length; i++){
        let id;
        try{
            id = await user_validation_arr[i];
        }
        catch (err){
            console.error(err.message);
            return res.status(500).end();
        }
        if (id == -1){
            return res.s_send({error:'some users not found'});
        }
        if(id == user_id) contains_user = true;
        user_ids.push(id);
    }
    const name = body_obj.hasOwnProperty('name') ? body_obj.name : body_obj.participants.join(' ');
    if(!contains_user) return res.s_send({error:'participants did not contain user'});
    insert_promise = new Promise((res, rej)=>{
        db.run('insert into Conversations(default_name, time_created) values(?,?)',
            [name, req_time.getTime()], function(err){
                if(err) throw err;
                const convo_id = this.lastID;
                //investigate how to roll back all inserts if error
                for(let i = 0; i < user_ids.length; i++){
                    if(user_id == user_ids[i] && body_obj.hasOwnProperty('name')){
                        db.run('insert into UserConversationMap(UserID, ConversationID, custom_name) values(?,?,?)',
                            [user_ids[i], convo_id, body_obj.name], (err)=>{
                                if(err) console.error(err);
                            });
                    }
                    else{
                        db.run('insert into UserConversationMap(UserID, ConversationID) values(?,?)',
                            [user_ids[i], convo_id], (err)=>{
                                if(err) console.error(err);
                            });
                    }
                }
                res(convo_id);
            });
    });
    let convo_id;
    try{
        convo_id = await insert_promise;
    }
    catch (err){
        console.error(err.message);
        return res.status(500).end();
    }
    let res_convo_obj = {
        conversationID:convo_id,
        name:name
    };
    for(let i = 0; i < user_ids.length; i++){
        if(!user_socket_map.hasOwnProperty(user_ids[i])) continue;
        const map = user_socket_map[user_ids[i]];
        let socket_ids = Object.keys(map);
        for(let j = 0; j < socket_ids.length; j++){
            console.log('emitting new convo to socket: ', socket_ids[j]);
            map[socket_ids[j]].socket.s_emit('new_convo', res_convo_obj);
        }
    }
    res.s_send(res_convo_obj);
});

/*  digests object expected in form:
    {
        userDigests:[{id:<some_id>, digest:<some_digest>}, ...]
        deviceDigests:[{id:<some_id>, digest:<some_digest>}, ...]
    }
 */

app.post('/msg_create', async (req, res)=>{
    const req_time = new Date();
    const attr_mapping = {
        required:{
            authToken:'string',
            conversationID:'number',
            digests:{
                userDigests:[{
                    id:'number',
                    //change to hex when adding encryption
                    digest:'hex'
                }],
                deviceDigests:[{
                    id:'number',
                    digest:'string'
                }]
            }
        },
        optional:{}
    };
    const body_obj = (req.hasOwnProperty('decrypted_obj')) ? req.decrypted_obj : req.body;
    if(is_bad_request(body_obj, attr_mapping)){return res.status(400).end();}
    let verification_promise = verify_auth_token(body_obj.authToken);
    const user_id = await verification_promise;
    if(user_id == -1) return res.s_send({authStatus:false, error:'auth_token not valid'});
    let permission_promise = new Promise((res, rej)=>{
        db.get('select * from UserConversationMap where UserID=? and ConversationID=?', [user_id, body_obj.conversationID], (err, row)=>{
            if(err) throw err;
            if(!row) return res(false);
            res(true);
        });
    });
    let has_permissions;
    try{
        has_permissions = await permission_promise;
    }
    catch(err){
        console.error(err);
        return;
    }
    //accessing illegal conversationid
    //technically could be 403 or 404 but no need to give unneccessary information
    if(!has_permissions) return res.status(403).end();
    let user_id_promise = new Promise((res, rej)=>{
        db.all('select UserID from UserConversationMap where ConversationID=?', [body_obj.conversationID], (err, rows)=>{
            if(err) throw err;
            let rv = [];
            for(let i = 0; i < rows.length; i++){
                rv.push(rows[i].UserID);
            }
            res(rv);
        });
    });
    let device_id_promise = new Promise((res, rej)=>{
        db.all(`select DeviceID from Devices
            left join UserConversationMap on UserConversationMap.UserID=Devices.UserID
            where ConversationID=?`, [body_obj.conversationID], (err, rows)=>{
                if(err) throw err;
                let rv = [];
                for(let i = 0; i < rows.length; i++){
                    rv.push(rows[i].DeviceID);
                }
                res(rv);
            });
    });
    let user_ids;
    let device_ids;
    try{
        user_ids = await user_id_promise;
        device_ids = await device_id_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(500).end();
    }
    const req_udigs = body_obj.digests.userDigests;
    const req_ddigs = body_obj.digests.deviceDigests;
    if(user_ids.length != req_udigs.length || device_ids.length != req_ddigs.length){
        return res.s_send({error:'missing digests, refresh to send messages to new members'});
    }
    let test_set = {};
    for(let i = 0; i < user_ids.length; i++){
        test_set[user_ids[i]] = null;
    }
    let found_all = true;
    for(let i = 0; i < req_udigs.length; i++){
        if(!test_set.hasOwnProperty(req_udigs[i].id)){
            found_all = false;
            break;
        }
    }
    if(!found_all) return res.status(400).end();
    test_set = {};
    for(let i = 0; i < device_ids.length; i++){
        test_set[device_ids[i]] = null;
    }
    for(let i = 0; i < req_ddigs.length; i++){
        if(!test_set.hasOwnProperty(req_ddigs[i].id)){
            found_all = false;
            break;
        }
    }
    if(!found_all) return res.status(400).end();
    //request has all correct ids, may insert digests now
    //possibly look into how to revert inserts in case of errors with database inserts
    let message_promise = new Promise((res, rej)=>{
        db.run('insert into Messages(SenderID, ConversationID, senttime) values(?,?,?)',
            [user_id, body_obj.conversationID, req_time.getTime()], function(err){
                if(err) throw err;
                res(this.lastID);
            });
    });
    let message_id;
    try{
        message_id = await message_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(500).end();
    }

    let username_promise = new Promise((res, rej)=>{
        db.get('select username from Users where UserID=?', [user_id], (err, row)=>{
            if(err) throw err;
            if(!row) throw new Error('unexpected missing user_id');
            res(row.username);
        });
    })
    let username;
    try{
        username = await username_promise;
    }
    catch(err){
        console.error(err.message);
        return res.status(500).end();
    }
    const message_obj_prototype = {
        sender:username,
        digest:'deadd0d0',
        time:req_time.getTime()
    };
    let digests_promise = new Promise(async (res, rej)=>{
        let promises = [];
        let d_sock_map = {};
        let u_sock_map = {};
        for (let i = 0; i < req_udigs.length; i++){
            if(!user_socket_map.hasOwnProperty(req_udigs[i].id)) continue;
            let curr_map = user_socket_map[req_udigs[i].id];
            let socket_ids = Object.keys(user_socket_map[req_udigs[i].id])
            for (let j = 0; j < socket_ids.length; j++){
                if(curr_map[socket_ids[j]].hasOwnProperty('device_id')){
                    if(!d_sock_map.hasOwnProperty(curr_map[socket_ids[j]].device_id)){
                        d_sock_map[curr_map[socket_ids[j]].device_id] = [];
                    }
                    d_sock_map[curr_map[socket_ids[j]].device_id].push(curr_map[socket_ids[j]].socket);
                }
                else{
                    if(!u_sock_map.hasOwnProperty(req_udigs[i].id)){
                        u_sock_map[req_udigs[i].id] = [];
                    }
                    u_sock_map[req_udigs[i].id].push(curr_map[socket_ids[j]].socket);
                }
            }
        }
        for(let i = 0; i < req_udigs.length; i++){
            if(u_sock_map.hasOwnProperty(req_udigs[i].id)){
                const msg_obj = Object.assign({},message_obj_prototype);
                msg_obj.digest = req_udigs[i].digest;
                const arr = u_sock_map[req_udigs[i].id];
                for(let j = 0; j < arr.length; j++){
                    console.log('emitting new message to socket: ', arr[j].id);
                    arr[j].s_emit('new_message', body_obj.conversationID, msg_obj);
                }
            }
            promises.push(new Promise((res, rej)=>{
                db.run('insert into Digests(contents, MessageID, UserID) values(?,?,?)',
                    [req_udigs[i].digest, message_id, req_udigs[i].id], function(err){
                        if(err) throw err;
                        //value unused for now but could be used for revert on error
                        res(this.lastID);
                    });
            }));
        }
        for(let i = 0; i < req_ddigs.length; i++){
            if(d_sock_map.hasOwnProperty(req_ddigs[i].id)){
                const msg_obj = Object.assign({},message_obj_prototype);
                msg_obj.digest = req_ddigs[i].digest;
                const arr = d_sock_map[req_ddigs[i].id];
                for(let j = 0; j < arr.length; j++){
                    console.log('emitting new message to socket: ', arr[j].id);
                    arr[j].s_emit('new_message', body_obj.conversationID, msg_obj);
                }
            }
            promises.push(new Promise((res, rej)=>{
                db.run('insert into Digests(contents, MessageID, DeviceID) values(?,?,?)',
                    [req_ddigs[i].digest, message_id, req_ddigs[i].id], function(err){
                        if(err) throw err;
                        //value unused for now but could be used for revert on error
                        res(this.lastID);
                    });
            }));
        }
        for(let i = 0; i < promises.length; i++){
            try{
                let digest_id = await promises[i];
            }
            catch(err){
                throw err;
            }
        }
        res({status:'success'});
    });
    let res_obj;
    try{
        res_obj = await digests_promise;
    }
    catch(err){
        console.error(err.message);
        res.status(500).end();
    }
    res.s_send(res_obj);
});

http.listen(3000, (err)=>{
    if(err){console.error(err.message);}
    else{console.log('http server started at localhost:3000');}
});
