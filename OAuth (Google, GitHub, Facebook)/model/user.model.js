const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      trim: true,
      minlength: 3
    },

    useremail: {
      type: String,
      required: false,      // ✅ not required for Google
      unique: true,
      lowercase: true,
      trim: true
    },

    userpassword: {
      type: String,
      required: false,      // ✅ not required for Google
      minlength: 6
    },

    googleId: {
      type: String
    },
    facebookId: {
      type: String
    },
    githubId: {
      type: String
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("User", userSchema);