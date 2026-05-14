require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const User = require("./model/user.model.js");

const app = express();

// ================= DATABASE =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch(err => console.log(err));

// ================= MIDDLEWARE =================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");

// ================= PASSPORT =================
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = await User.create({
          username: profile.displayName,
          googleId: profile.id,
          role: "user"
        });
      }

      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ================= CSRF =================
const csrfProtection = csrf({ cookie: true });

// Apply CSRF to all except Google auth routes
app.use((req, res, next) => {
  if (req.path.startsWith("/auth/google")) return next();
  csrfProtection(req, res, next);
});

app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken ? req.csrfToken() : null;
  next();
});

// ================= AUTH MIDDLEWARE =================
const ensureAuth = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  next();
};

const ensureRole = (role) => {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      return res.status(403).send("Access Denied");
    }
    next();
  };
};

// ================= ROUTES =================
app.get("/", (req, res) => res.redirect("/login"));

// ===== REGISTER =====
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    const { username, useremail, userpassword } = req.body;

    const exists = await User.findOne({ useremail });
    if (exists) return res.send("User already exists");

    const hashedPassword = await bcrypt.hash(userpassword, 10);

    await User.create({
      username,
      useremail,
      userpassword: hashedPassword,
      role: "user"
    });

    res.redirect("/login");
  } catch (err) {
    res.send("Server Error");
  }
});

// ===== LOGIN =====
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  try {
    const { useremail, userpassword } = req.body;

    const user = await User.findOne({ useremail });
    if (!user) return res.send("User not found");

    const isMatch = await bcrypt.compare(userpassword, user.userpassword);
    if (!isMatch) return res.send("Incorrect password");

    req.login(user, (err) => {
      if (err) return res.send("Login error");

      if (user.role === "admin") {
        return res.redirect("/admin");
      } else {
        return res.redirect("/home");
      }
    });

  } catch (err) {
    res.send("Server Error");
  }
});

// ===== GOOGLE AUTH =====
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    res.redirect("/home");
  }
);

// ===== USER HOME =====
app.get("/home", ensureAuth, (req, res) => {
  if (req.user.role === "admin") return res.redirect("/admin");
  res.render("home", { user: req.user });
});

// ===== ADMIN =====
app.get("/admin", ensureAuth, ensureRole("admin"), (req, res) => {
  res.render("admin", { user: req.user });
});

// ===== LOGOUT =====
app.post("/logout", ensureAuth, (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

// ================= SERVER =================
app.listen(process.env.PORT, () =>
  console.log(`🚀 Server running on http://localhost:${process.env.PORT}`)
);