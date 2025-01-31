const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  googleId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  profilePic: { type: String },
  googleAccessToken: { type: String }, 
  googleRefreshToken: { type: String }, 
  refreshToken: { type: String }, 
});

const User = mongoose.model("User", UserSchema);
module.exports = User;