const mongoose = require("mongoose");
// const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
	mail: { type: String, unique : true},
	password: { type: String },
});



module.exports = mongoose.model("User", userSchema);
