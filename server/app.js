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
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'))

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

app.use(express.urlencoded({extended: true}));

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
	  }
}
));

const validateSessionMember = (req, res, next) => {
	if(req.session.authenticated != true){
	res.redirect('/');
	}else{
		next();
	}
}

const validateSessionAdmin = (req, res, next) => {
	if(req.session.authenticated != true){
		res.redirect('/login');
	}else{
		next();
	}
}
const validateAdmin = (req, res, next) => {
	if(req.session.user_type != 'admin'){
		let html = `
		<p>403 - You do not have the right authroization</p>
		<a href="/">Go Back</a>
		`;
		res.status(403).send(html);
		return;
	}else{
		next();
	}
}


app.get("/", (req, res) => {
	const authenticated = req.session.authenticated;
	const username = req.session.username;
	res.status(200).render('index', {
		pageTitle: 'Hello',
		authenticated: authenticated,
		username: username
	})
})

app.get("/members", (req, res) => {
    if (req.session.authenticated === true) {
        res.render('member', {
			pageTitle: "Members Area",
			username: req.session.username,
		});
	}else{
		res.redirect("/");
	}
})

app.get("/signup", (req, res) => {
	res.render('signup', {
		pageTitle: 'Signup',
	})
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
		return;
	}else if(!email){
		let html = `
		<p>email is required</p>
		<a href="/signup">try again</a>
		`;
		res.send(html);
		return;
	}else if(!password){
		let html = `
		<p>password is required</p>
		<a href="/signup">try again</a>
		`;
		res.send(html);
		return;
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
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type:"user"});
	req.session.authenticated = true;
	req.session.username = username;
	req.session.cookie.maxAge = expireTime;
	req.session.user_type = "user";
   	res.redirect('/members')
	console.log("Redirecting")
  

})

app.get("/login", (req, res) => {
	res.render('login', {
		pageTitle: 'Login',
	})
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

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, username: 1, user_type: 1}).toArray();

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
		req.session.user_type = result[0].user_type;
		console.log(req.session.username);
		console.log(req.session.user_type)
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

app.get("/admin", validateSessionAdmin, validateAdmin, async (req, res) => {
	let users = await userCollection.find({}).toArray();
	res.status(200).render('admin', {
		users: users,
		pageTitle: 'Admin'
	})
})

app.post("/makeAdmin/:username", async (req, res) => {
	let username = req.params.username;
	await userCollection.updateOne(
	{ username: username },
	{ $set: { user_type: "admin" } }
	);
	res.status(200).redirect('/admin');
})

app.post("/makeUser/:username", async (req, res) => {
	let username = req.params.username;
	await userCollection.updateOne(
	{ username: username },
	{ $set: { user_type: "user" } }
	);
	res.status(200).redirect('/admin');
})

app.post("/logout/", (req, res) => {
	req.session.destroy();
	res.redirect("/");
})

app.get("*dummy", (req, res) => {
    res.status(404);
    res.render('404', {
		pageTitle: '404 Not Found',
	});
});


app.listen(port, ()=>{
    console.log(`Server Running on Port ${port}`)
})



