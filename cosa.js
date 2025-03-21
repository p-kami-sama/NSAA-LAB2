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
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

const USERS_FILE = 'users.json';

const { scrypt, verify } = require('scrypt-pbkdf');
const scryptPbkdf = require('scrypt-pbkdf');



const SCRYPT_FAST_PARAMS = { N: 2 ** 14, r: 8, p: 1 };  // Rápido (~50-100ms)
const SCRYPT_SECURE_PARAMS = { N: 2 ** 20, r: 8, p: 1 }; // Lento (~3s)

const salt = scryptPbkdf.salt()  // returns an ArrayBuffer filled with 16 random bytes
const derivedKeyLength = 32  // in bytes


const app = express();
const port = 3000;


app.use(logger('dev'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(passport.initialize());





// passport.use('username-password', new LocalStrategy(
//   {
//     usernameField: 'username',
//     passwordField: 'password',
//     session: false
//   },
//   async function (username, password, done) {
//     try {
//       console.log('- - LLEGA A TRY');

//       const isValid = await verifyUser(username, password);
//       console.log('- - is', isValid);
//       if (isValid) {
//         console.log('- - isValid');
//         const user = { username: username, description: 'the only user that deserves to get to this server' };
//         return done(null, user);
//         console.log('- - done');
//       }
//       return done(null, false);
//     } catch (error) {
//       console.log('ERROR: se ha liado seriamente');
//       return done(error);
//     }
//   }
// ));
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
    console.log('- - PASAPORTE', jwtPayload);

    const users = readUsers(); // Leer usuarios desde users.json
    const user = users.find(user => user.username === jwtPayload.sub);

    if (user) {
      console.log('- - PASAPORTE ok');
      return done(null, { username: user.username, role: jwtPayload.role || 'user' });
    }

    console.log('- - PASAPORTE fallo');
    return done(null, false);
  }
));








app.get('/login', (req, res) => {
  res.sendFile('login.html', { root: __dirname });
});

// app.post('/login',
//   passport.authenticate('username-password', { failureRedirect: '/login', session: false }),
//   (req, res) => {
//     const jwtClaims = {
//       sub: req.user.username,
//       iss: 'localhost:3000',
//       aud: 'localhost:3000',
//       exp: Math.floor(Date.now() / 1000) + 604800,
//       role: 'user'
//     };

//     const token = jwt.sign(jwtClaims, jwtSecret);
//     res.cookie('jwt', token, { httpOnly: true, secure: true });
//     console.log('TOKEN->', token);;
//     res.redirect('/');

//     console.log(`Token sent. Debug at https://jwt.io/?value=${token}`);
//   }
// );

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
      <head><title>Registro</title></head>
      <body>
        <h1>Registro de Usuario</h1>
        <form action="/register" method="POST">
          <div>
            <label>Usuario:</label>
            <input type="text" name="username" required />
          </div>
          <div>
            <label>Contraseña:</label>
            <input type="password" name="password" required />
          </div>
          <div>
            <input type="submit" value="Registrar" />
          </div>
        </form>
      </body>
    </html>
  `);
});

app.post('/register', async (req, res) => {
  try {
    console.log('esperando0')
    await registerUser(req.body.username, req.body.password);
    console.log('esperando1')
    res.send('Usuario registrado exitosamente. <a href="/login">Iniciar sesión rápido</a>');
    console.log('esperando2')

  } catch (error) {
    res.send(`Error POST: ${error.message} <a href="/register">Intentar de nuevo</a>`);
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
  res.status(500).send('Something broke!');
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



// Función para convertir ArrayBuffer a Base64
function arrayBufferToBase64(buffer) {
  return Buffer.from(buffer).toString('base64');
}

// Función para escribir los usuarios en el archivo JSON
function writeUsers(users) {
  console.log('users0', users);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  console.log('users1');
}



// Función para registrar un nuevo usuario con dos hashes en Base64
async function registerUser(username, password) {
  let users = readUsers();

  if (users.some(user => user.username === username)) {
    throw new Error('El usuario ya existe.');
  }

  console.log('readUsers5', typeof(password), typeof(SCRYPT_FAST_PARAMS), typeof(SCRYPT_SECURE_PARAMS));
  
  const hashFast = await scrypt(password, salt, derivedKeyLength, SCRYPT_FAST_PARAMS);
  const hashSecure = await scrypt(password, salt, derivedKeyLength, SCRYPT_SECURE_PARAMS);
  console.log('readUsers6');
  console.log('readUsers7', hashFast, hashSecure);

  users.push({
    username,
    password_scrypt_fast: arrayBufferToBase64(hashFast),
    password_scrypt_secure: arrayBufferToBase64(hashSecure)
  });

  writeUsers(users);
}

// Registrar un nuevo usuario con ambas KDF
// async function registerUser(username, password) {
//   let users = readUsers();

//   if (users.some(user => user.username === username)) {
//     throw new Error('El usuario ya existe.');
//   }
//   console.log('readUsers5', typeof(password), typeof(SCRYPT_FAST_PARAMS), typeof(SCRYPT_SECURE_PARAMS));
  
//   const hashFast = await scrypt(password, salt, derivedKeyLength, SCRYPT_FAST_PARAMS);
//   const hashSecure = await scrypt(password, salt, derivedKeyLength, SCRYPT_SECURE_PARAMS);
//   console.log('readUsers6');
//   console.log('readUsers7', hashFast, hashSecure);

//   users.push({
//     username,
//     password_scrypt_fast: hashFast,
//     password_scrypt_secure: hashSecure
//   });

//   writeUsers(users);
// }


// Función para verificar credenciales
// async function verifyUser(username, password) {
//   const users = readUsers();
//   const user = users.find(user => user.username === username);

//   if (!user) return false;
//   return await argon2.verify(user.password, password);
// }
// Función para convertir Base64 a ArrayBuffer
function base64ToArrayBuffer(base64) {
  return Buffer.from(base64, 'base64');
}

// Verificar con scrypt rápido
async function verifyUserFast(username, password) {
  const users = readUsers();
  const user = users.find(user => user.username === username);

  if (!user || !user.password_scrypt_fast) return false;

  return await verify(password, base64ToArrayBuffer(user.password_scrypt_fast));
}

// Verificar con scrypt seguro
async function verifyUserSecure(username, password) {
  const users = readUsers();
  const user = users.find(user => user.username === username);

  if (!user || !user.password_scrypt_secure) return false;

  return await verify(password, base64ToArrayBuffer(user.password_scrypt_secure));
}