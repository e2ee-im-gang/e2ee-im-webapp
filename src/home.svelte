<script>
	import io from 'socket.io-client';
	import Sodium from './sodium.js';
	import parser from 'socket.io-parser';
	const authToken = localStorage.getItem('authToken');
	let publicKey = localStorage.getItem('publicKey');
	let privateKey = localStorage.getItem('privateKey');
	let username = localStorage.getItem('username');

	//global prototypes
	const digest_obj_prototype = {
		id:-1,
		digest:'deadd0d0'
	};
	const conversation_obj_prototype = {
		id:-1,
		name:'default_name',
		last_msg_sender:'default_sender',
		last_msg:'default_msg',
		keys:{}
	};
	const message_obj_prototype = {
		sender:'username-here',
		contents:'contents of message goes here',
		time:'formatted time string goes here',
		from_you:false
	};

	//socket handling begin
	const socket = io('/');
	socket.s_emit = (...args)=>{
		if(!socket.is_secure_protocol) return socket.emit(...args);
		let digests = [];
		for(let i = 0; i < args.length; i++){
			const digest = crypto_box_seal(from_string(JSON.stringify(args[i])), socket.s_public_key).toString('hex');
			digests.push(digest);
		}
		socket.emit(...digests);
	};
	//in lieu of middleware
	//this is the most straightforward option
	socket.s_rec_parser = (...args)=>{
		if(!socket.is_secure_protocol) return args;
		let rv = [];
		for(let i = 0; i < args.length; i++){
			const decrypted = crypto_box_seal_open(from_hex(args[i]), socket.c_public_key, socket.c_private_key);
			rv.push(JSON.parse(to_string(decrypted)));
		}
		return rv;
	};
	socket.on('secure_res', (public_key)=>{
		socket.s_public_key = from_hex(public_key);
		socket.is_secure_protocol = true;
	});
	socket.on('auth_req', ()=>{
		socket.s_emit('auth_res', authToken);
	});
	socket.on('auth_status', (status)=>{
		if(status!=='accepted'){
			console.error('socket responded with status: ', status);
			socket.close();
		}
	})
	socket.on('new_message', (convo_id, message_obj)=>{
		let args = socket.s_rec_parser(convo_id, message_obj);
		convo_id = args[0];
		message_obj = args[1];
		let msg_obj = create_message_obj(message_obj);
		if(conversation_list[open_convo_val].id == convo_id){
			message_list.push(msg_obj);
			message_list = message_list;
			messages_ref.scrollTop = messages_ref.scrollHeight;
		}
		//possible race condition with conversation creating at the
		//same time as the first message is sent
		conversation_refs[convo_id].last_msg = msg_obj.contents;
		conversation_list = conversation_list;
	});
	socket.on('new_convo', async (convo_obj)=>{
		let args = socket.s_rec_parser(convo_obj);
		convo_obj = args[0];
		const new_convo_obj = Object.create(conversation_obj_prototype);
		new_convo_obj.id = convo_obj.conversationID;
		new_convo_obj.name = convo_obj.name;
		const req_obj = {
			authToken:authToken,
			conversationID:new_convo_obj.id
		};
		let promise = s_ajax_json_req(req_obj, '/keys_req');
		let keys_obj;
		try{
			keys_obj = await promise;
		}
		catch(err){
			return console.error(err.message);
		}
		new_convo_obj.keys = keys_obj;
		new_convo_obj.last_msg = '';
		conversation_refs[new_convo_obj.id] = new_convo_obj;
		conversation_list.push(new_convo_obj);
		conversation_list = conversation_list;
	});
	const secure_socket = () =>{
		const keypair = crypto_box_keypair();
		socket.c_public_key = keypair.publicKey;
		socket.c_private_key = keypair.privateKey;
		socket.emit('secure_req', to_hex(socket.c_public_key));
	}
	//investigate behaviour of server disconnects with socket
	//socket handling end

	//below snippet from:
	//https://stackoverflow.com/questions/179355/clearing-all-cookies-with-javascript
	function deleteAllCookies() {
		const cookies = document.cookie.split(";");
		for (var i = 0; i < cookies.length; i++) {
			const cookie = cookies[i];
			const eqPos = cookie.indexOf("=");
			const name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
			document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
		}
	}
	const end_session = () =>{
		localStorage.clear();
		deleteAllCookies();
		window.location.href = "/login";
	}
	if(privateKey == null){
		end_session();
	}
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
	};
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
	const populate_convos = async () =>{
		let req_obj = {
			authToken:authToken
		};
		let promise = s_ajax_json_req(req_obj, '/convo_req');
		let res_obj;
		try{
			res_obj = await promise;
		}
		catch (err){
			console.error(err.message);
			return;
		}
		for(let i = 0; i < res_obj.conversationObjects.length; i++){
			let new_convo_obj = Object.create(conversation_obj_prototype);
			new_convo_obj.id = res_obj.conversationObjects[i].id;
			new_convo_obj.name = res_obj.conversationObjects[i].name;
			if(res_obj.conversationObjects[i].last_msg_digest.length == 0)
				new_convo_obj.last_msg = '';
			else
				new_convo_obj.last_msg = to_string(crypto_box_seal_open(from_hex(res_obj.conversationObjects[i].last_msg_digest), publicKey, privateKey));
			req_obj = {
				authToken:authToken,
				conversationID:new_convo_obj.id
			};
			promise = s_ajax_json_req(req_obj, '/keys_req');
			let keys_obj;
			try{
				keys_obj = await promise;
			}
			catch(err){
				console.error(err.message);
				continue;
			}
			new_convo_obj.keys = keys_obj;
			conversation_refs[new_convo_obj.id] = new_convo_obj;
			conversation_list.push(new_convo_obj);
		}
		conversation_list = conversation_list;
	};
	const get_username = async () =>{
		let req_obj = {
			authToken:authToken
		};
		let promise = s_ajax_json_req(req_obj, '/user_req', true);
		let res_obj;
		try{
			res_obj = await promise;
		}
		catch(err){
			console.error(err.message);
		}
		username = res_obj.username;
		localStorage.setItem('username', username);
		console.log('username: ', username);
	};
	const secure_on_startup = ()=>{
		//imperative nothing using encryption runs before
		//libsodium is loaded
		publicKey = from_hex(publicKey);
		privateKey = from_hex(privateKey);
		if(username == null){
			get_username();
		}
		populate_convos();
		secure_socket();
	};
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
		secure_on_startup();
	});
	let conversation_list = [];
	let conversation_refs = {};

	let message_list = [];
	let messages_ref;
	let curr_message;
	let curr_convo_obj;
	const get_fmtted_time = (date_obj) =>{
		const year = (1900 + date_obj.getYear()).toString();
		const month = ('0' + (1 + date_obj.getMonth()).toString()).slice(-2);
		const day = date_obj.getDate().toString();
		const hours = ('0' + date_obj.getHours().toString()).slice(-2);
		const minutes = ('0' + date_obj.getMinutes().toString()).slice(-2);
		const seconds = ('0' + date_obj.getSeconds().toString()).slice(-2);
		return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
	};

	let display_add_account = false;
	const display_add = () =>{
		display_add_account = true;
	};
	const close_add = () =>{
		display_add_account = false;
	}

	let participants;
	let new_conversation_name;
	const create_convo = async () =>{
		let req_participants = participants.replace(/ /g,'').split(',');
		req_participants.push(username);
		let req_obj = {
			authToken:authToken,
			participants:req_participants
		};
		if(new_conversation_name.length > 0) req_obj.name=new_conversation_name;
		let promise = s_ajax_json_req(req_obj, '/conversation_create');
		let response_obj;
		try{
			response_obj = await promise;
		}
		catch(err){
			alert(err.message);
			return;
		}
		const convo_id = response_obj.conversationID;
		const name = response_obj.name;
		req_obj = {
			authToken:authToken,
			conversationID:convo_id
		};
		promise = s_ajax_json_req(req_obj, '/keys_req');
		try{
			response_obj = await promise;
		}
		catch(err){
			alert(err.message);
			return;
		}
		const keys = response_obj
		req_obj = {
			authToken:authToken,
			conversationID:convo_id
		};
		promise = s_ajax_json_req(req_obj, '/last_msg_req');
		try{
			response_obj = await promise;
		}
		catch(err){
			alert(err.message);
			return;
		}
		//for now not decrypting digests until everything is built
		//so build times aren't 15 seconds
		const digest = response_obj.digest;
		const new_convo_obj = Object.create(conversation_obj_prototype);
		new_convo_obj.id = convo_id;
		new_convo_obj.name = name;
		if(digest.length == 0) new_convo_obj.last_msg = '';
		else
			new_convo_obj.last_msg = to_string(crypto_box_seal_open(from_hex(digest), publicKey, privateKey));
		new_convo_obj.keys = keys;
		conversation_list.push(new_convo_obj);
		//updating because svelte
		conversation_list = conversation_list;
		display_add_account = false;
	};

	let open_convo_val = -1;

	//function expects res to be response from
	//server providing a message object
	const create_message_obj = (res)=>{
		let rv = Object.create(message_obj_prototype);
		rv.sender = res.sender;
		//add decryption here later
		if(res.digest.length == 0)
			rv.contents = '';
		else{
			rv.contents = to_string(crypto_box_seal_open(from_hex(res.digest), publicKey, privateKey));
		}
		rv.time = get_fmtted_time(new Date(res.time));
		rv.from_you = username === res.sender;
		return rv;
	};

	//race condition here from spam potentially
	const open_convo = async (id)=>{
		const req_obj = {
			authToken:authToken,
			conversationID:id
		};
		let promise = s_ajax_json_req(req_obj, '/messages_req');
		let res_obj;
		try{
			res_obj = await promise;
		}
		catch(err){
			alert(err.message);
			return;
		}
		message_list = [];
		let arr = res_obj.messageObjects;
		for(let i = 0; i < arr.length; i++){
			let new_message_obj = create_message_obj(arr[i]);
			message_list.push(new_message_obj);
		}
		message_list = message_list;
		messages_ref.scrollTop = messages_ref.scrollHeight;
	}

	const convo_change = (index) =>{
		if(index == -1) return;
		//update conversation with new colour
		conversation_list = conversation_list;
		open_convo(conversation_list[index].id);
	}
	$: convo_change(open_convo_val);

	const req_send_msg = async(convo_obj, msg) =>{
		const req_obj = {
			authToken:authToken,
			conversationID:convo_obj.id,
			digests:{
				userDigests:[],
				deviceDigests:[]
			}
		};
		const msg_buf = from_string(msg);
		for(let i = 0; i < convo_obj.keys.userKeys.length; i++){
			req_obj.digests.userDigests.push({
				id:convo_obj.keys.userKeys[i].id,
				digest:to_hex(crypto_box_seal(msg_buf, from_hex(convo_obj.keys.userKeys[i].key)))
			});
		}
		for(let i = 0; i < convo_obj.keys.deviceKeys.length; i++){
			req_obj.digests.deviceDigests.push({
				id:convo_obj.keys.deviceKeys[i].id,
				digest:to_hex(crypto_box_seal(msg_buf, from_hex(convo_obj.keys.deviceKeys[i].key)))
			});
		}
		let promise = s_ajax_json_req(req_obj, '/msg_create');
		let res_obj;
		try{
			res_obj = await promise;
		}
		catch(err){
			alert(err.message);
			return;
		}
	};

	const send_msg = () =>{
		if(open_convo_val == -1) return;
		let convo_obj = conversation_list[open_convo_val];
		if(curr_message.length == 0 || !curr_message) return;
		let new_message = Object.create(message_obj_prototype);
		req_send_msg(convo_obj, curr_message);
		curr_message = '';
	};

</script>

<style>
	:global(html){
		height:100%;
	}
	:global(body){
		height:100%;
		margin:0px;
		background-color:#000;
	}
	.add_convo_form_wrapper{
		visibility: hidden;
		z-index: 2;
		background-color: #fff;
		position:fixed;
		width:600px;
		height:400px;
		top: 50%;
		left: 50%;
		margin-top: -200px;
		margin-left: -300px;
	}
	.show{
		visibility: visible;
		-webkit-animation: fadeIn 0.5s;
		animation: fadeIn 0.5s;
	}
	@-webkit-keyframes fadeIn {
		from {opacity: 0;}
		to {opacity: 1;}
	}

	@keyframes fadeIn {
		from {opacity: 0;}
		to {opacity:1 ;}
	}
	.greyout_overlay{
		visibility:hidden;
		z-index:1;
		background-color:#000;
		position:fixed;
		width:100%;
		height:100%;
		opacity:0.3;
	}
	.grey_show{
		visibility: visible;
		-webkit-animation: fadeGrey 0.5s;
		animation: fadeGrey 0.5s;
	}
	@-webkit-keyframes fadeGrey {
		from {opacity: 0;}
		to {opacity: 0.3;}
	}

	@keyframes fadeGrey {
		from {opacity: 0;}
		to {opacity:0.3 ;}
	}

	.column{
		height:100%;
		float:left;
	}
	.left{
		background-color:#c8c8c8;
		width:25%;
	}
	.right{
		width:75%;
	}
	.row{
		height:100%;
	}
	.row:after{
		content:"";
		display: table;
		clear:both;
	}
	.conversation_wrapper{
		height:80%;
		overflow-y: scroll;
	}
	.convo_box{
		height:60px;
		white-space: nowrap;
		overflow: hidden;
		background-color:#aaa;
	}
	.convo_box .header{
		font-size:16px;
		font-weight: bold;
		text-overflow: ellipsis;
	}
	.convo_box .msg{
		font-size:13px;
		text-overflow: ellipsis;
	}
	.convo_box .alternate{
		background-color:#ddd;
	}
	.messages{
		color:#fff;
		height:80%;
		overflow-y: scroll;
	}
	.input_area{
		padding:5px;
		height:20%;
	}
	.message_input{
		font-size:16px;
		width:100%;
		height:80%;
		background-color:#444;
		color:#fff;
	}
	.add_convo_wrapper{
		width:100%;
		height:10%;
		text-align:center;
	}
	.add_convo_wrapper button{
		padding:5px, 5px, 5px, 5px;
		line-height: 100%;
		display:inline-block;
		height:100%;
		width:100%;
		font-size:30px;
	}
	.convo_radio_wrapper{
		appearance:none;
		-webkit-appearance: none;
		-moz-appearance: none;
		position:fixed;
	}
	.logout_wrapper{
		width:100%;
		height:10%;
		text-align:center;
	}
	.logout_wrapper button{
		padding:5px, 5px, 5px, 5px;
		line-height: 100%;
		display:inline-block;
		height:100%;
		width:100%;
		font-size:30px;
	}
</style>


<div class="greyout_overlay" class:grey_show={display_add_account} on:click={close_add}></div>
<div class="add_convo_form_wrapper" class:show={display_add_account}>
	<form on:submit|preventDefault={create_convo}>
		User(s):<input type="text" placeholder="steve85, joeseph42, ..." bind:value={participants}>
		Chat Name:<input type="text" placeholder="friday sesh" bind:value={new_conversation_name}>
		<button type="submit">Create Chat</button>
	</form>
</div>
<div class="row">
	<div class="column left">
		<div class="add_convo_wrapper">
			<button on:click={display_add}>+</button>
		</div>
		<div class="conversation_wrapper">
			{#each conversation_list as conversation, index}
			<label>
			<div class="convo_box" style={(index == open_convo_val) ? "background-color:#bde" : (index % 2 == 0) ? "background-color:#ddd" : ""}>
				<input type=radio class="convo_radio_wrapper" bind:group={open_convo_val} value={index}>
				<ul style="list-style-type:none;">
					<li class="header">{conversation.name}</li>
					<li class="msg">{conversation.last_msg}</li>
				</ul>
			</div>
			</label>
			{/each}
		</div>
		<div class="logout_wrapper">
			<button on:click={end_session}>logout</button>
		</div>
	</div>
	<div class="column right">
		<div class="messages" bind:this={messages_ref}>
			<ul style="list-style-type:none;">
			{#each message_list as message}
			<li style={(message.from_you) ? "color:#f55;" : ""}>{message.time}@{message.sender}&gt; {message.contents}</li>
			{/each}
			</ul>
		</div>
		<div class="input_area">
			<form style="height:100%;" on:submit|preventDefault={send_msg}>
			<input type="text" class="message_input" bind:value={curr_message}>
			<input type="submit" style="display:none;">
			</form>
		</div>
	</div>
</div>
