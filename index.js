const express = require('express');  
const passport = require('passport');  
const dotenv = require('dotenv');  
const SamlStrategy = require('passport-saml').Strategy;  
const session = require('express-session');  
const bodyParser = require('body-parser');  
const fs = require('fs');  
const path = require('path');  
const cors = require('cors');  

dotenv.config();  

const app = express();  
const PORT = process.env.PORT || 3000;  
const SAML_CERT_PATH = path.join(__dirname, './assets/SelfSignedCert_07Oct2024_225813.crt');  

app.use(cors());  

app.use(bodyParser.urlencoded({ extended: true }));  

app.use(session({  
  secret: process.env.CLIENT_SECRET || 'secret',  
  resave: false,  
  saveUninitialized: true,  
  cookie: { secure: process.env.NODE_ENV === 'production' }  
}));  

app.use(passport.initialize());  
app.use(passport.session());  

let userProfile = null;
let originUrl = "";

try {  
  const salesforceCert = fs.readFileSync(SAML_CERT_PATH, 'utf-8');  

  passport.use(new SamlStrategy({  
      entryPoint: process.env.ENTRY_POINT,  
      issuer: process.env.ISSUER,  
      cert: salesforceCert,  
    },  
    (profile, done) => {  
      userProfile = {  
        id: profile.nameID || null,  
        email: profile.email || null,  
        userId: profile.userId || null,  
      };  
      done(null, userProfile);  
    }  
  ));  
} catch (error) {  
  console.error('Failed to load SAML certificate:', error);  
}  

passport.serializeUser((user, done) => done(null, user));  
passport.deserializeUser((user, done) => done(null, user));  

app.get('/login', (req, res, next) => {  
  originUrl = req.get('referer');
  next();  
}, passport.authenticate('saml', { failureRedirect: '/login/failure' }));  

app.post('/login/callback',  
  passport.authenticate('saml', { failureRedirect: '/login/failure' }),  
  (req, res) => res.redirect(`${originUrl}/home`)  // Redirect to your frontend home page  
);  

app.get('/logout', (req, res, next) => {  
  req.logout((err) => {
		err ? next(err) : res.redirect(`${originUrl}`)
		userProfile = null
	});    
});  

app.get('/', (req, res) => {  
  if (userProfile) {  
    const { email, id, userId } = userProfile;  
    res.json({  
      email: email,  
      id: id,  
      userId: userId,  
    });  
  } else {  
    res.status(401).json({ error: 'Not authenticated' });  
  }  
});  

app.listen(PORT, () => {  
  console.log(`Server started on http://localhost:${PORT}`);  
});