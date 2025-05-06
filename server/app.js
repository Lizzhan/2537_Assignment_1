require('dotenv').config({
    path:'../.env'
});
const express = require('express');
const path = require("path");
const {database} = require('./db');
const MongoStore = require('connect-mongo');
const session = require('express-session');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const app = express();

app.use(express.static(path.join(__dirname, "../public")));

const Joi = require("joi");

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const port = process.env.PORT || 3000;

const userCollection = database.db(mongodb_database).collection('auth');

app.use(express.urlencoded({extended: false}));

let mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions?retryWrites=true&w=majority`,
	crypto: {
		secret: mongodb_session_secret
	},
	mongoOptions:{
		autoSelectFamily: false,
		tls: true
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false, 
	resave: false,
	cookie: {
		httpOnly: true,
		// secure: process.env.NODE_ENV === 'production' // Enable in production
	  }
}
));

app.get("/", (req, res) => {
	console.log("authenticated " + req.session.authenticated)
	if(req.session.authenticated === true){
		const html = 		
		`<h3>Hello ${req.session.username}<h3>
		<form action="members" method="get" class="form">
		<button type="submit">Go to memebrs area</button>
		</form>
		<form action="logout" method="post" class="form">
		<button type="submit">Log Out</button>
		</form>`;
		res.send(html);
	}else{
		const html = 
		`<form action="login" method="get" class="form">
		<button type="submit">log in</button>
		</form>
		<form action="signup" method="get" class="form">
		<button type="submit">sign up</button>
		</form>`;
		res.send(html)
	}
})

app.get("/members", (req, res) => {
    if (req.session.authenticated === true) {
        const rand = Math.floor(Math.random() * 3) + 1;
        const imageSrc = `/${rand}.gif`; 

        const html = `
            <h3>Hello, ${req.session.username}</h3><br>
            <img src="${imageSrc}" alt="Random Image" width="300"><br>
            <form action="/logout" method="post">
                <button type="submit">Log Out</button>
            </form>
        `;

        res.send(html);
	}else{
		res.redirect("/");
	}
})

app.get("/signup", (req, res) => {
		const html = 
		`<h3>FUNEMPLOYEDMAXXING</h3>
		<form action="signupSubmit" method="post" class="form">
			<input type="text" name="username" placeholder="name"/>
			<input type="email" name="email" id="" placeholder="email" />
			<input type="password" name="password" id="" placeholder="password" />
			<button type="submit">Sign Up</button>
		</form>`
		res.send(html);
})

app.post("/signupSubmit", async (req, res) => {
	let username = req.body.username;
	let email = req.body.email;
	let password = req.body.password;
	if(!username){
		let html = `
		<p>username is required</p>
		<a href="/signup">try again</a>
		`;
		res.send(html);
	}
	if(!email){
		let html = `
		<p>email is required</p>
		<a href="/signup">try again</a>
		`;
		res.send(html);
	}
	if(!password){
		let html = `
		<p>password is required</p>
		<a href="/signup">try again</a>
		`;
		res.send(html);
	}
	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			email: Joi.string().email({ tlds: { allow: false } }).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup");
	   return;
   }

    let hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	req.session.authenticated = true;
	req.session.username = username;
	req.session.cookie.maxAge = expireTime;
   	res.redirect('/members')
	console.log("Redirecting")
  

})

app.get("/login", (req, res) => {
		const html = 
		`<h3>FUNEMPLOYEDMAXXING</h3>
		<form action="loginSubmit" method="post" class="form">
			<input type="email" name="email" id="" placeholder="email" />
			<input type="password" name="password" id="" placeholder="password" />
			<button type="submit">login</button>
		</form>`
		res.send(html);

})

app.post("/loginSubmit", async (req, res)=>{
	let email = req.body.email;
	let password = req.body.password;
	
	const schema = Joi.string().email({ tlds: { allow: false } }).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
		console.log(validationResult.error);
		res.redirect("/login");
		return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1}).toArray();

	if (result.length != 1) {
		let html = `
		<p>user not found</p>
		<a href="/login">try again</a>
		`;
		res.send(html);
	}
	if (await bcrypt.compare(password, result[0].password)) {
		req.session.authenticated = true;
		req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/');
		return;
	}
	else {
		let html = `
		<p>invalid email/password combination</p>
		<a href="/login">try again</a>
		`;
		res.send(html);
	}
})

app.post("/logout", (req, res) => {
	req.session.destroy();
	res.redirect("/");
})

app.get("*dummy", (req,res) => {
    res.status(404);
    res.send("Page not found - 404");
});


app.listen(port, ()=>{
    console.log(`Server Running on Port ${port}`)
})



