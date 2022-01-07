"use strict";

import express from "express";
const app = express();
app.use('/', express.static('public'));
app.use(express.json());

import pgPromise from 'pg-promise'; 
const pgp = pgPromise();
const db = pgp({
        connectionString: process.env.DATABASE_URL,
        ssl: {
          rejectUnauthorized: false
        }
      });
async function initializeDatabase() {
    try {
        await db.none({text:"CREATE TABLE IF NOT EXISTS users (email text UNIQUE, display_name text, phone_number text, salt text NOT NULL, hash text NOT NULL)"});
    }
    catch(err) {
        console.error(err);
    }
    try {
        await db.none({text:"CREATE TABLE IF NOT EXISTS tasks (title text, description text, user_name text, location text, email text, phone_number text, req_status text, id serial UNIQUE)"});
    }
    catch(err) {
        console.error(err);
    }
    try {
        await db.none({text:"CREATE TABLE IF NOT EXISTS comments (task_id integer, user_name text, contents text)"});
    }
    catch(err) {
        console.error(err);
    }
}
initializeDatabase();

import expressSession from 'express-session';  
import passport from 'passport';               
import {Strategy as LocalStrategy} from 'passport-local'; 
import minicrypt from './miniCrypt.js';
const mc = new minicrypt();


const session = {
    secret : process.env.SECRET || 'SECRET', 
    resave : false,
    saveUninitialized: false
};



const strategy = new LocalStrategy(
    {
        usernameField: 'user_email',
        passwordField: 'password'
      },
    async (username, password, done) => {
        try {
            if (!(await findUser(username))) {
                // no such user
                await new Promise((r) => setTimeout(r, 2000));
                return done(null, false, { 'message' : 'Wrong username' });
            }
        } catch(err) {
            console.error(err);
        }
        try {
            if (!(await validatePassword(username, password))) {
                await new Promise((r) => setTimeout(r, 2000)); 
                return done(null, false, { 'message' : 'Wrong password' });
            }
        } catch(err) {
            console.error(err);
        }
	return done(null, username);
    });


app.use(expressSession(session));
passport.use(strategy);
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((uid, done) => {
    done(null, uid);
});


async function findUser(email) {
    try {
        const userData = await db.any({text:"SELECT email FROM users WHERE email = $1 LIMIT 1", values:[email]});
        if (userData.length <= 0) {
            return false;
        }
        return true
    }
    catch(err) {
        console.error(err);
        return false; 
    }
}


async function validatePassword(email, pwd) {

    try {
        const userData = await db.any({text:"SELECT email, salt, hash FROM users WHERE email = $1 LIMIT 1", values:[email]});
        if (userData.length <= 0) {
            return false;
        }
        const userSalt = userData[0].salt;
        const userHash = userData[0].hash;
        return mc.check(pwd, userSalt, userHash);
    } catch(err) {
        console.error(err);
        return false; 
    }
}

function checkLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        res.redirect('/index.html');
    }
}

app.post("/user/new", async (req, res) => {
    const email = req.body["user_email"];
    const password = req.body["password"];
    if (email === "" || password === "") {
        res.status(400)
        res.send("Empty parameters.")
    } else if (await findUser(email)) {
        res.status(304);
        res.send("Account already exists.")
    } else {
        const [salt, hash] = mc.hash(password);
        try {
            await db.none({text:"INSERT INTO users(email, salt, hash) VALUES ($1, $2, $3)", values:[email, salt, hash]});
            console.log(`Created account: ${email}`);
            res.status(201);
            res.send('Created account.');
        } catch(err)
        {
            console.error(err);
            res.status(500);
            res.send('Failed to add account.');
        }
    }
});

app.post("/user/login",
    passport.authenticate("local")
    , (req, res) => {
            res.status(200);
            res.send(JSON.stringify({
                "login_status": "valid"
            }));
    }
);
app.put("/user/edit", 
    checkLoggedIn, 
    async (req, res) => {
        const email = req.body["user_email"];
        const displayName = req.body["display_name"];
        const phoneNumber = req.body["phone_number"];
        if (email === req.user) {
            try {
                await db.none({text:"UPDATE users SET display_name = $2, phone_number = $3 WHERE email = $1", values:[email, displayName, phoneNumber]});
                console.log(`Updated account: ${email} ${displayName} ${phoneNumber}`);
                res.status(204);
                res.send('Updated account details.');
            } catch(err) {
                console.error(err);
                res.status(500);
                res.send('Failed to add account.');
            }
        } else {
            res.status(403);
            res.send('Invalid session.');
        }
        
    });

app.delete("/user/delete", 
    checkLoggedIn, //Authentication
    async (req, res) => {
        const email = req.body["user_email"];
        if (email === req.user) {
            try {
                await db.none({text:"DELETE FROM users WHERE email = $1", values:[email]});
                console.log(`Deleted account ${email}`);
                res.status(204);
                res.send('Deleted account.');
            } catch(err) {
                console.error(err);
                res.status(500);
                res.send('Failed to delete account.');
            }
        } else {
            res.status(403);
            res.send('Invalid session.');
        }
        
    });

app.get("/user/data", async (req, res) => {
    const email = req.query["target_email"];
    let details = null;
    try {
        const userData = await db.any({text:"SELECT email, display_name, phone_number FROM users WHERE email = $1 LIMIT 1", values:[email]});
        if (userData.length > 0) {
            details = userData[0];
        }
    } catch(err) {
        console.error(err);
        
    }
    if (details !== null) {
        let output = {};
        output.email = details.email;
        output.display_name = details.display_name || "";
        output.phone_number = details.phone_number || "";
        res.status(200);
        res.send(JSON.stringify(output));
    } else {
        res.status(404);
        res.send();
    }
});

app.get('/user/logout', (req, res) => {
    req.logout(); 
    res.redirect('/index.html'); 
});


app.post("/task", async (req, res) => {
    const requestTitle = req.body["title"];
    const requestDescription = req.body["description"];
    const name = req.body["user_name"]; 
    const req_location = req.body["location"];
    const email = req.body["email"];
    const phoneNumber = req.body["phone_number"];

    try {
        await db.query ("INSERT INTO tasks(title, description, user_name, location, email, phone_number, req_status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *", 
        [requestTitle, requestDescription, name, req_location, email, phoneNumber, "pending"]);
        console.log(`Created task: ${requestTitle}`);
        res.status(201);
        res.send('Created task.');
    }catch(err) {
        console.error(err);
        res.status(500);
        res.send('Failed to add request.');
    }
});

app.put("/task/:id", async (req, res) => {
        const id = req.params["id"];
        const requestTitle = req.body["title"];
        const requestDescription = req.body["description"];
        const name = req.body["user_name"]; 
        const req_location = req.body["location"];
        const email = req.body["email"];
        const phoneNumber = req.body["phone_number"];

        try {
                await db.query (
                    "UPDATE tasks SET email = $1, title = $2, description = $3, name = $4, location = $5, phone_number = $6 WHERE id = $7", 
                [email, requestTitle, requestDescription, name, req_location, phoneNumber, id]);
                res.status(204);
                res.send('Updated related task details.');
            } catch(err) {
                console.error(err);
                res.status(500);
                res.send('Failed to update task details.');
            }
  
        
        
    });

app.get("/task", async (req, res) => {
    
    try {
        const results = await db.query("SELECT * FROM tasks");
        res.json(results.rows);
    } catch (err) {
        console.error(err);
        res.status(500);
        res.send('Failed to get list of tasks.');
    }
});

app.delete("/task/:id", 

    async (req, res) => {
        const id = req.params["id"];
        try {
            await db.query ("DELETE FROM tasks WHERE id = $1", [id]);
            await db.query ("DELETE FROM comments WHERE task_id = $1", [id]); 
            console.log(`Deleted task ${id}`);
            res.status(204);
            res.send('Deleted task.');
        } catch(err) {
            console.error(err);
            res.status(500);
            res.send('Failed to delete task.');
        }
    });



app.put("/markProgress/:id", 
    async (req, res) => {
        const id = req.params["id"];
        try {
            await db.query ("UPDATE tasks SET req_status = $1 WHERE id = $2", ["in progress", id]);
                res.status(204);
                res.send('submitted, you are all set!!!!');
        }catch(err) {
            console.error(err);
            res.status(500);
            res.send('Failed to update request status.');
        }
});

app.post("/comment", 
    checkLoggedIn,
    async (req, res) => {
    const task_id = req.body["task_id"];
    const user_name = req.body["user_name"];
    const contents = req.body["contents"]; 
    try {
       await db.none ({text:"INSERT INTO comments(task_id, user_name, contents) VALUES ($1, $2, $3)", values:[task_id, user_name, contents]});
       console.log(`Created comment for ${task_id}`);
       res.status(201);
       res.send('Created comment.');
    }
    catch(err) {
       console.error(err);
       res.status(500);
       res.send('Failed to add comment.');
    }
});

app.get("/comment", async (req, res) => {
    const task_id = req.body["task_id"];
    try {
        const comms = await db.query("SELECT * FROM comments WHERE task_id = $1", [task_id]);
        res.status(200);
        res.json(comms.rows);
    }
    catch (err) {
        console.error(err);
        res.status(500);
        res.send('Failed to load comments.');
    }
});


const port = process.env.PORT || 3000;
app.listen(port, (err) => {
    if (err) {
        console.log("problem!!", err);
        return;
    }
    console.log("listening to port 3000");
});