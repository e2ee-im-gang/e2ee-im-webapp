<script>
	const authToken = localStorage.getItem('authToken');
	const publicKey = localStorage.getItem('publicKey');
	const privateKey = localStorage.getItem('privateKey');

	const ajax_json_req = (req_obj, path) =>{
		console.log(path);
		console.log(req_obj);
		return new Promise((res, rej)=>{
			let req = new XMLHttpRequest();
			req.open("POST", path, true);
			req.setRequestHeader("Content-Type", "application/json");
			req.send(JSON.stringify(req_obj));
			req.onreadystatechange = () =>{
				if(req.readyState != XMLHttpRequest.DONE) return;
				if(req.status !== 200) rej(new Error('Error ' + req.status.toString()));
				console.log(req.response);
				let response_obj = JSON.parse(req.response);
				if(response_obj.hasOwnProperty('error')) rej(new Error(response_obj.error));
				res(response_obj);
			};
		}).catch((err)=>{
			//must investigate how to do this properly
			console.error(err.message);
		});
	}

	let username = localStorage.getItem('username');
	if(username == null){
		const get_username = async () =>{
			let req_obj = {
				authToken:authToken
			};
			let promise = ajax_json_req(req_obj, '/user_req', true);
			try{
				username = await promise;
			}
			catch(err){
				console.error(err.message);
			}
		};
		get_username();
	}
	let conversation_list = [];
	const conversation_obj_prototype = {
		id:-1,
		name:'default_name',
		last_msg:'default_msg',
		keys:{}
	};

	let message_list = [];
	const message_obj_prototype = {
		sender:'username-here',
		contents:'contents of message goes here',
		time:'formatted time string goes here',
		from_you:false
	};
	let messages_ref;
	let curr_message;
	let curr_convo_obj;
	const get_fmtted_time = () =>{
		const curr_date = new Date();
		const year = (1900 + curr_date.getYear()).toString();
		const month = ('0' + (1 + curr_date.getMonth()).toString()).slice(-2);
		const day = curr_date.getDate().toString();
		const hours = ('0' + curr_date.getHours().toString()).slice(-2);
		const minutes = ('0' + curr_date.getMinutes().toString()).slice(-2);
		const seconds = ('0' + curr_date.getSeconds().toString()).slice(-2);
		return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
	};
	const digest_obj_prototype = {
		id:-1,
		digest:'deadd0d0'
	};
	const populate_convos = async () =>{
		let req_obj = {
			authToken:authToken
		};
		let promise = ajax_json_req(req_obj, '/convo_req');
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
			//not decrypting digest for now
			new_convo_obj.last_msg = res_obj.conversationObjects[i].last_msg_digest;
			req_obj = {
				authToken:authToken,
				conversationID:new_convo_obj.id
			};
			promise = ajax_json_req(req_obj, '/keys_req');
			let keys_obj;
			try{
				keys_obj = await promise;
			}
			catch(err){
				console.error(err.message);
				continue;
			}
			new_convo_obj.keys = keys_obj;
			conversation_list.push(new_convo_obj);
		}
		conversation_list = conversation_list;
		console.log(conversation_list);
	};
	populate_convos();
	async function open_convo(){

	}

	/*
	async function send_msg(){
		let digests = []
		promise = new Promise((res, rej)=>{
			let message_send = new XMLHttpRequest();
			message_send.open('POST', '/message_send', true);
			message_send.setRequestHeader("Content-Type", "application/json");
			message_send.send(JSON.stringify({
				authToken:localStorage.getItem('authToken', response_obj),
				conversationID:curr_convo_obj.id,
			}));
		});
		let message_res;
		try{
			message_res = await promise;
		}
		catch (err){
			console
		}
	}*/
	const send_msg = () =>{
		let new_message = Object.create(message_obj_prototype);
		new_message.sender=username;
		new_message.contents=curr_message;
		new_message.time = get_fmtted_time();
		new_message.from_you = true;
		message_list.push(new_message);
		message_list=message_list;
		curr_message = '';
		messages_ref.scrollTop = messages_ref.scrollHeight;
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
		let promise = ajax_json_req(req_obj, '/conversation_create');
		let response_obj;
		try{
			response_obj = await promise;
		}
		catch(err){
			alert(err.message);
			return;
		}
		console.log('here');
		const convo_id = response_obj.conversationID;
		const name = response_obj.name;
		req_obj = {
			authToken:authToken,
			conversationID:convo_id
		};
		promise = ajax_json_req(req_obj, '/keys_req');
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
		promise = ajax_json_req(req_obj, '/last_msg_req');
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
		new_convo_obj.last_msg = digest;
		new_convo_obj.keys = keys;
		conversation_list.unshift(new_convo_obj);
		//updating because svelte
		conversation_list = conversation_list;
		display_add_account = false;
	};

	//dummy values
	let foo = Object.create(conversation_obj_prototype);
	foo.id = 0;
	foo.name = 'a better convo name';
	foo.last_msg = 'a cool message';
	conversation_list.push(foo);
	foo = Object.create(conversation_obj_prototype);
	foo.id = 1;
	foo.name = 'wayy better';
	foo.last_msg = 'a cooler message';
	conversation_list.push(foo);
	foo = Object.create(conversation_obj_prototype);
	foo.id = 1;
	foo.name = 'convo 3';
	foo.last_msg = 'message goes here';
	conversation_list.push(foo);
	foo = Object.create(conversation_obj_prototype);
	foo.id = 1;
	foo.name = 'convo 4';
	foo.last_msg = 'giberish';
	conversation_list.push(foo);
	foo = Object.create(message_obj_prototype);
	foo.sender='seamooo';
	foo.contents='wow awesome message you got there';
	foo.time='1997-03-11 11:20:24';
	foo.from_you=true;
	message_list.push(foo);
	foo = Object.create(message_obj_prototype);
	foo.sender='other';
	foo.contents='average message';
	foo.time='1997-03-11 11:20:30';
	foo.from_you=false;
	message_list.push(foo);
	foo = Object.create(message_obj_prototype);
	foo.sender='seamooo';
	foo.contents='ehh it was kinda cool I guess';
	foo.time='1997-03-11 11:20:40';
	foo.from_you=true;
	message_list.push(foo);
	foo = Object.create(message_obj_prototype);
	foo.sender='other';
	foo.contents='yeah whatever';
	foo.time='1997-03-11 11:20:50';
	foo.from_you=false;
	message_list.push(foo);
	conversation_list = conversation_list;
	message_list = message_list;
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
		height:90%;
		overflow-y: scroll;
	}
	.convo_box{
		height:60px;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
		background-color:#aaa;
	}
	.convo_box .header{
		font-size:16px;
		font-weight: bold;
	}
	.convo_box .msg{
		font-size:13px;
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
			<div class="convo_box" style={(index % 2 == 0) ? "background-color:#ddd" : ""}>
				<ul style="list-style-type:none;">
					<li class="header">{conversation.name}</li>
					<li class="msg">{conversation.last_msg}</li>
				</ul>
			</div>
			{/each}
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
