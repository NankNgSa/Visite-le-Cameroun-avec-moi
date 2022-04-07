const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./modeles/User");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const app = express();
const PORT = process.env.PORT || 4000;
const dotenv = require("dotenv");
require("cors");
dotenv.config();

mongoose
	.connect("mongodb://127.0.0.1/tbdatabase")
	.then(() => {
		console.log("server connecté !");
	})
	.catch((e) => {
		console.log("erreur de connection à la BD!");
		console.log(e);
	});

app.use((req, res, next) => {
	res.setHeader("Access-Control-Allow-Origin", "*");
	res.setHeader(
		"Access-Control-Allow-Headers",
		"Origin, X-Requested-With, Content, Accept, Content-Type, Authorization",
		"Access-Control-Allow-Methods",
		"GET, POST, PUT, DELETE, PATCH, OPTIONS"
	);
	next();
});

app.use(
	bodyParser.urlencoded({
		parameterLimit: 10000,
		limit: "50mb",
		extended: true,
	})
);
app.use(bodyParser.json({ parameterLimit: 10000, limit: "50mb" }));

// pour generer mon TOKEN_SECRET
// const generatedToken = require("crypto").randomBytes(64).toString("hex");
// console.log(generatedToken);

// -------------------------------------------------------------------------------------------------------------

// ok
// enregistrement d'un nouvel utilisateur dans la BD
app.post("/api/register", (req, res) => {
	try {
		// recuperer les données entrées par l'utilisateur
		const { mail, password } = req.body;

		// verifier si y'a des données dans le body de la requete
		if (!mail) res.status(400).json({ message: "les champs sont vide !" });

		// hasher le mot de passe
		const cryptedPassword = bcrypt.hashSync(password, 10);

		// creer un nouvel utilisateur
		const user = new User({
			mail: mail,
			password: cryptedPassword,
		});

		// generer le token à l'aide de l'id et du mail
		const token = jwt.sign(
			{ user_id: user._id, mail },
			process.env.TOKEN_SECRET,
			{
				expiresIn: "2d",
			}
		);

		user
			// enregistrer l'utilisateur dans la BD
			.save()
			// reponse du serveur pour confirmer la creation d'un nouvel utilisateur
			.then(() => {
				res.status(200).json({
					user: user,
					token: token,
				});
				console.log(user);
			})
			.catch((error) => res.status(400).json({ error }));
	} catch (error) {
		console.log(error);
		res.status(400).json("impossible de creer un compte");
	}
});

// -------------------------------------------------------------------------------------------------------------

// connexion (login) d'un utilisateur
app.get("/api/login", (req, res, next) => {
	try {
		// verifier si y'a des données dans le body de la requete
		if (!req.body) res.status(400).json({ message: "Body vide !" });

		// recuperer les données entrées par l'utilisateur
		const { mail, password } = req.body;

		// hasher le mot de passe que l'utilisateur entre pour se logger
		const cryptedPassword = bcrypt.hashSync(password, 10);

		console.log(req.body); // il y a une valeur
		console.log(mail); // il y a une valeur

		// rechercher un utilisateur grace à son mail
		const user = User.findOne({ mail: req.body.mail });

		console.log("password in BD : " + User.password); // il y a pas de valeur
		console.log("mail in BD : " + User.mail);

		// verifier si l'utilisateur et son mot de passe correspondant existent dans la BD
		if (bcrypt.compareSync(cryptedPassword, user.password)) {
			// user && password == user.password
			const token = jwt.sign(
				{ user_id: user._id, mail },
				process.env.TOKEN_SECRET,
				{
					expiresIn: "2d",
				}
			);

			user.token = token;
			user
				// .save()
				.then(() =>
					res.status(201).json({
						user: user,
						token: token,
					})
				);
		} else {
			return res.status(400).json({ message: "cet utilisateur n'existe pas" });
		}
	} catch (error) {
		console.log(error);
	}
});

// -------------------------------------------------------------------------------------------------------------

// ok
// verification du token
// pourquoi on ne fait pas la verification dans le login ?
app.get("/api/verify-token", (req, res, next) => {
	//Vérifier si dans le header authorization il y a des éléments
	if (req.headers.authorization) {
		const token = req.headers.authorization.split(" ")[1];

		// verifier si le token est valide
		try {
			jwt.verify(token, process.env.TOKEN_SECRET);
			res.status(201).json({ message: "c'est le bon token !" });
		} catch (error) {
			res.status(400).json(error);
		}
	}
});

// -------------------------------------------------------------------------------------------------------------

// ok
// recuperer tous les utilisateurs de la BD
app.get("/api/get-all-users", (req, res, next) => {
	User.find()
		.then((user) => {
			res.status(200).json(user);
		})
		.catch((error) => {
			res.status(400).json({ error });
		});
});

// -------------------------------------------------------------------------------------------------------------

// connexion (login) d'un utilisateur grace à son mail
app.get("/api/login2", (req, res, next) => {
	try {
		// verifier si y'a des données dans le body de la requete
		if (!req.body) res.status(400).json({ message: "Body vide !" });

		// recuperer les données entrées par l'utilisateur
		const { mail, password } = req.body;

		// hasher le mot de passe que l'utilisateur entre pour se logger
		const cryptedPassword = bcrypt.hashSync(password, 10);

		// verifier si l'utilisateur et son mot de passe correspondant existent dans la BD		
			User.findOne({ mail: mail }, (err, User) => {
				if (err) {
					res.json({
						status: 0,
						message: err,
					});
				}
				if (!User) {
					res.json({
						status: 0,
						message: "not found",
					});
				}

				bcrypt.compare(cryptedPassword, User.password, (err, res) => {
					console.log(err, res);
					if (!res) {
						console.log("je suis ici");
						// return res.status(401).json({message:"information incorrecte"})
						// throw "information incorrecte";
						return { status: 401, message: "mauvais mot de passe" }
					}					
				});

				const token = jwt.sign(
					{ user_id: User._id, mail },
					process.env.TOKEN_SECRET,
					{
						expiresIn: "2d",
					}
				);

				User.token = token;
				User.save();

				return {
					status: 201,
					user: User,
					token: token,
				};
			})
		
		res.send('http://google.com');
		
	} catch (error) {
		console.log(error);
	}
});

// -------------------------------------------------------------------------------------------------------------
// connexion (login) d'un utilisateur
app.post("/api/login3", (req, res) => {
	try {
		const { mail, password } = req.body;
		const cryptedPassword = bcrypt.hashSync(password, 10);

		if (mail && password) {
			User.find({ mail: mail }, (err, data) => {
				if (data.length > 0) {
					if (bcrypt.compareSync(data[0].password, cryptedPassword)) {
						checkUserAndGenerateToken(data[0], req, res);
					} else {
						res.status(400).json({
							errorMessage: "Username or password is incorrect!",
							status: false,
						});
					}
				} else {
					res.status(400).json({
						errorMessage: "Username or password is incorrect!",
						status: false,
					});
				}
			});
		} else {
			res.status(400).json({
				errorMessage: "Add proper parameter first!",
				status: false,
			});
		}
	} catch (e) {
		res.status(400).json({
			errorMessage: "Something went wrong!",
			status: false,
		});
	}
});

// -----------------------------------------------------------------------------------------
app.get("/api/login4", (req, res, next) => {
	try {
		// verifier si y'a des données dans le body de la requete
		if (!req.body) res.status(400).json({ message: "Body vide !" });

		// recuperer les données entrées par l'utilisateur
		const { mail, password } = req.body;

		// hasher le mot de passe que l'utilisateur entre pour se logger
		const cryptedPassword = bcrypt.hashSync(password, 10);

		// verifier si l'utilisateur et son mot de passe correspondant existent dans la BD
		User.findOne({ mail: mail }, (err, User) => {
			console.log(" ");
			console.log("password in BD : " + User.password); // il y a une valeur
			console.log("mail in BD : " + User.mail);

			if (err) {
				res.json({
					status: 0,
					message: err,
				});
			}
			if (!User) {
				res.json({
					status: 0,
					message: "not found",
				});
			}

			console.log(" ");
			console.log("userpassword = password in BD: " + User.password);
			console.log("cryptedPassword : " + cryptedPassword);

			if (bcrypt.compareSync(cryptedPassword, User.password)) {
				// user && password == user.password
				const token = jwt.sign(
					{ user_id: User._id, mail },
					process.env.TOKEN_SECRET,
					{
						expiresIn: "2d",
					}
				);

				User.token = token;
				User
					// .save()
					.then(() =>
						res.status(201).json({
							user: User,
							token: token,
						})
					);
			} else {
				return res
					.status(400)
					.json({ message: "cet utilisateur n'existe pas" });
			}
		});
	} catch (error) {
		console.log(error);
	}
});

// -----------------------------------------------------------------------------------------
app.get("/api/login5", (req, res, next) => {
	try {
		// verifier si y'a des données dans le body de la requete
		if (!req.body) res.status(400).json({ message: "Body vide !" });

		// recuperer les données entrées par l'utilisateur
		const { mail, password } = req.body;

		// hasher le mot de passe que l'utilisateur entre pour se logger
		const cryptedPassword = bcrypt.hashSync(password, 10);

		// verifier si l'utilisateur et son mot de passe correspondant existent dans la BD
		
			User.findOne({ mail: mail }, (err, User) => {
				console.log(" ");
				console.log("password in BD : " + User.password); // il y a une valeur
				console.log("mail in BD : " + User.mail); // il y a une valeur

				if (err) {
					res.json({
						status: 0,
						message: err,
					});
				}
				if (!User) {
					res.json({
						status: 0,
						message: "not found",
					});
				}

				console.log(" ");
				console.log("userpassword = password in BD: " + User.password); // il y a une valeur
				console.log("cryptedPassword : " + cryptedPassword); // il y a une valeur

				bcrypt.compare(cryptedPassword, User.password, (err, res) => {
					console.log(err, res);
					if (!res) {
						console.log("je suis ici");
						// return res.status(401).json({message:"information incorrecte"})
						// throw "information incorrecte";
						return { status: 401, message: "mauvais mot de passe" }
					}					
				});

				const token = jwt.sign(
					{ user_id: User._id, mail },
					process.env.TOKEN_SECRET,
					{
						expiresIn: "2d",
					}
				);

				User.token = token;

				User.save();

				res.status(201).json({
					user: User,
					token: token,
				});

				console.log(" ");
				console.log("token :  " + User.token);
				console.log(" ");

				// res.redirect('http://localhost:3000/dashboard');
			})
		
		// res.send('http://google.com');
		
	} catch (error) {
		console.log(error);
	}
});

app.listen(PORT, () => {
	// debug
	console.log(`app.listen reussi on ${PORT}`);
});
