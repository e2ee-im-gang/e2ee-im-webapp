const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
if(fs.existsSync('./db/central.db')){
    fs.unlinkSync('./db/central.db');
}


let db = new sqlite3.Database('./db/central.db', sqlite3.OPEN_CREATE | sqlite3.OPEN_READWRITE, (err)=>{
    if(err){console.error(err.msg);}
    else{console.log('successfully opened database');}
});
db.serialize(function(){
    db.run('begin transaction');
    db.run(`
        create table IF NOT EXISTS Users
        (UserID INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        hash TEXT NOT NULL,
        client_salt TEXT NOT NULL,
        keygen_salt TEXT NOT NULL,
        server_salt TEXT NOT NULL,
        pw_public_key TEXT NOT NULL)
    `);
    //public key is here such that there's no ambiguity
    //which public key out of pw_public_key or device
    //public key there is
    db.run(`
        create table IF NOT EXISTS AuthTokens
        (AuthTokenID INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL UNIQUE,
        expiration INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        UserID INTEGER NOT NULL,
        FOREIGN KEY(UserID) REFERENCES Users(UserID))
        `)
    db.run(`
        create table IF NOT EXISTS PreviousPasswords
        (PreviousPasswordID,
        hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        date_removed INTEGER NOT NULL,
        UserID INTEGER NOT NULL,
        FOREIGN KEY(UserID) REFERENCES Users(UserID))
    `);
    db.run(`
        create table IF NOT EXISTS Devices
        (DeviceID INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        UserID INTEGER NOT NULL,
        FOREIGN KEY(UserID) REFERENCES Users(UserID))
    `);
    db.run(`
        create table IF NOT EXISTS Conversations
        (ConversationID INTEGER PRIMARY KEY AUTOINCREMENT,
        default_name TEXT NOT NULL,
        time_created INTEGER NOT NULL)
    `);
    db.run(`
        create table IF NOT EXISTS UserConversationMap
        (UserConversationMapID INTEGER PRIMARY KEY,
        UserID INTEGER NOT NULL,
        ConversationID INTEGER NOT NULL,
        custom_name TEXT,
        FOREIGN KEY(UserID) REFERENCES Users(UserID),
        FOREIGN KEY(ConversationID) REFERENCES Conversations(ConversationID))
    `);
    db.run(`
        create table IF NOT EXISTS Messages
        (MessageID INTEGER PRIMARY KEY AUTOINCREMENT,
        SenderID INTEGER NOT NULL,
        ConversationID INTEGER NOT NULL,
        senttime INTEGER NOT NULL CHECK(senttime > 0),
        FOREIGN KEY(SenderID) REFERENCES Users(USERID),
        FOREIGN KEY(ConversationID) REFERENCES Conversations(ConversationID))
    `);
    //only device id or user id may be set
    //user id set if digest uses public key of password
    //otherwise device id set
    db.run(`
        create table IF NOT EXISTS Digests
        (DigestID INTEGER PRIMARY KEY AUTOINCREMENT,
        contents TEXT NOT NULL,
        MessageID INTEGER NOT NULL,
        DeviceID INTEGER,
        UserID INTEGER,
        CHECK ((UserID is null or DeviceID is null) and not (UserID is null and DeviceID is null))
        FOREIGN KEY(MessageID) REFERENCES Messages(MessageID),
        FOREIGN KEY(DeviceID) REFERENCES Devices(DeviceID),
        FOREIGN KEY(UserID) REFERENCES Users(UserID))
    `);
    db.run('commit transaction');
});
db.close((err)=>{
    if(err){console.error(err.message);}
});
