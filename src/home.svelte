<style>
	:global(html){
		height:100%;
	}
	:global(body){
		height:100%;
		margin:0px;
		background-color:#000;
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

</style>

<script>
	let conversation_list = [];
	const conversation_obj_prototype = {
		id:-1,
		conversation_name:'default_name',
		last_msg:'default_msg'
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
	const send_msg = () =>{
		let new_message = Object.create(message_obj_prototype);
		//add way to keep track of username later
		new_message.sender='seamooo';
		new_message.contents=curr_message;
		new_message.time = get_fmtted_time();
		new_message.from_you = true;
		message_list.push(new_message);
		message_list=message_list;
		curr_message = '';
		messages_ref.scrollTop = messages_ref.scrollHeight;
	};

	//dummy values
	let foo = Object.create(conversation_obj_prototype);
	foo.id = 0;
	foo.conversation_name = 'a better convo name';
	foo.last_msg = 'a cool message';
	conversation_list.push(foo);
	foo = Object.create(conversation_obj_prototype);
	foo.id = 1;
	foo.conversation_name = 'wayy better';
	foo.last_msg = 'a cooler message';
	conversation_list.push(foo);
	foo = Object.create(conversation_obj_prototype);
	foo.id = 1;
	foo.conversation_name = 'convo 3';
	foo.last_msg = 'message goes here';
	conversation_list.push(foo);
	foo = Object.create(conversation_obj_prototype);
	foo.id = 1;
	foo.conversation_name = 'convo 4';
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
<div class="row">
	<div class="column left">
		{#each conversation_list as conversation, index}
		<div class="convo_box" style={(index % 2 == 0) ? "background-color:#ddd" : ""}>
			<ul style="list-style-type:none;">
				<li class="header">{conversation.conversation_name}</li>
				<li class="msg">{conversation.last_msg}</li>
			</ul>
		</div>
		{/each}
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
