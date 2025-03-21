const express = require('express');
const logger = require('morgan');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const jwtSecret = crypto.randomBytes(16);

const fs = require('fs');

const { scrypt } = require('scrypt-pbkdf');
const derivedKeyLength = 32  // in bytes
const SCRYPT_FAST_PARAMS = { N: 2 ** 14, r: 8, p: 1 };  // Rápido (~50-100ms)
const SCRYPT_SECURE_PARAMS = { N: 2 ** 20, r: 16, p: 1 }; // Mucho más lento (~3-5s)
const USERS_FILE = 'users.json';

const app = express();
const port = 3000;


app.use(logger('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(passport.initialize());






passport.use('username-password-fast', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  async function (username, password, done) {
    try {
      const isValid = await verifyUserFast(username, password);
      if (isValid) {
        return done(null, { username });
      }
      return done(null, false);
    } catch (error) {
      return done(error);
    }
  }
));

passport.use('username-password-secure', new LocalStrategy(
  {
    usernameField: 'username',
    passwordField: 'password',
    session: false
  },
  async function (username, password, done) {
    try {
      const isValid = await verifyUserSecure(username, password);
      if (isValid) {
        return done(null, { username });
      }
      return done(null, false);
    } catch (error) {
      return done(error);
    }
  }
));





passport.use('jwtCookie', new JwtStrategy(
  {
    jwtFromRequest: (req) => req?.cookies?.jwt || null,
    secretOrKey: jwtSecret
  },
  function (jwtPayload, done) {

    const users = readUsers(); // Leer usuarios desde users.json
    const user = users.find(user => user.username === jwtPayload.sub);

    if (user) {
      return done(null, { username: user.username, role: jwtPayload.role || 'user' });
    }

    return done(null, false);
  }
));





app.get('/login', (req, res) => {
  res.sendFile('login.html', { root: __dirname });
});


app.post('/logout', (req, res) => {
  res.clearCookie('jwt'); // Elimina la cookie JWT
  res.redirect('/login'); // Redirige al login
});

app.get('/',
  passport.authenticate('jwtCookie', { session: false, failureRedirect: '/register' }),
  (req, res) => {
    res.send(`
      <html>
        <head><title>Private Page</title></head>
        <body>
          <h1>Welcome to your private page, ${req.user.username}!</h1>
          <form action="/logout" method="POST">
            <button type="submit">Logout</button>
          </form>
        </body>
      </html>
    `);
  }
);




app.get('/register', (req, res) => {
  res.send(`
    <html>
      <head><title>Register</title></head>
      <body>
        <h1>User Registration</h1>
        <form action="/register" method="POST">
          <div>
            <label>User:</label>
            <input type="text" name="username" required />
          </div>
          <div>
            <label>Password:</label>
            <input type="password" name="password" required />
          </div>
          <div>
            <input type="submit" value="Register" />
          </div>
        </form>
        </div>
        <p>Already have an account? <a href="/login">Log in</a></p>
      </body>
    </html>
  `);
});

app.post('/register', async (req, res) => {
  try {
    await registerUser(req.body.username, req.body.password);
    res.send('User successfully registered. <a href="/login">Log in</a>');

  } catch (error) {
    res.send(`Error: ${error.message} <a href="/register">Try again</a>`);
  }
});




app.post('/login-fast',
  passport.authenticate('username-password-fast', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: 'user'
    };

    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie('jwt', token, { httpOnly: true, secure: false });
    res.redirect('/');
  }
);

app.post('/login-secure',
  passport.authenticate('username-password-secure', { failureRedirect: '/login', session: false }),
  (req, res) => {
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800,
      role: 'user'
    };

    const token = jwt.sign(jwtClaims, jwtSecret);
    res.cookie('jwt', token, { httpOnly: true, secure: false });
    res.redirect('/');
  }
);








app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!'); // no deberia de pasar nunca
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});





// Leer usuarios desde el archivo JSON
function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE);
  return JSON.parse(data);
}

// Función para escribir los usuarios en el archivo JSON
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}


// Convertir Base64 a ArrayBuffer
function base64ToArrayBuffer(base64) {
  return Buffer.from(base64, 'base64');
}



// Convertir ArrayBuffer a Base64 para almacenamiento
function arrayBufferToBase64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

// Registrar usuario con scrypt-pbkdf
async function registerUser(username, password) {
  let users = readUsers();

  if (users.some(user => user.username === username)) {
    throw new Error('The user already exists.');
  }
  // Salts inicos para cada usuario
  const saltFast = crypto.randomBytes(16);    // Salt de 16 bytes para login-fast
  const saltSecure = crypto.randomBytes(16);  // Salt de 16 bytes para login-secure
  

  console.log("Generando hash rápido...");
  const hashFast = await scrypt(password, saltFast, derivedKeyLength, SCRYPT_FAST_PARAMS);
  
  console.log("Generando hash seguro... Esto tomará varios segundos.");
  const hashSecure = await scrypt(password, saltSecure, derivedKeyLength, SCRYPT_SECURE_PARAMS);

  users.push({
    username,
    salt_fast: saltFast.toString('base64'),
    salt_secure: saltSecure.toString('base64'),
    password_scrypt_fast: arrayBufferToBase64(hashFast),
    password_scrypt_secure: arrayBufferToBase64(hashSecure)
  });

  writeUsers(users);
}

// Verificar con scrypt rápido
async function verifyUserFast(username, password) {
  const users = readUsers();
  const user = users.find(user => user.username === username);

  if (!user || !user.password_scrypt_fast || !user.salt_fast) return false;

  const derivedHash = await scrypt(password, Buffer.from(user.salt_fast, 'base64'), derivedKeyLength, SCRYPT_FAST_PARAMS);
  return Buffer.compare(
    Buffer.from(derivedHash), 
    Buffer.from(base64ToArrayBuffer(user.password_scrypt_fast))
  ) === 0;
}

// Verificar con scrypt seguro
async function verifyUserSecure(username, password) {
  const users = readUsers();
  const user = users.find(user => user.username === username);

  if (!user || !user.password_scrypt_secure || !user.salt_secure) return false;

  console.log("⏳ Verificando contraseña segura... Esto debería tardar varios segundos.");
  const start = Date.now();

  const derivedHash = await scrypt(password, Buffer.from(user.salt_secure, 'base64'), derivedKeyLength, SCRYPT_SECURE_PARAMS);
  const isValid = Buffer.compare(Buffer.from(derivedHash), Buffer.from(base64ToArrayBuffer(user.password_scrypt_secure))) === 0;

  const end = Date.now();
  console.log(`✅ Tiempo de verificación: ${(end - start) / 1000} segundos`);
  
  return isValid;
}



