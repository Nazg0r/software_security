require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const path = require('path');
const port = 3000;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = process.env.KEY;

app.use(verifyJwtToken);

app.get('/', (req, res) => {
    if (req.user) {
        return res.json({
            username: req.user.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    res.redirect('/');
});

const users = [
    {
        login: 'Login',
        password: 'Password',
        username: 'Username',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;

    const user = users.find((user) => {
        if (user.login == login && user.password == password) {
            return true;
        }
        return false
    });

    if (user) {
        const claims = {
            username: user.username,
            login: user.login
        };

        const jwt = createJwtToken(claims);

        res.json({ token: jwt });
    }

    res.status(401).send();
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})


function verifyJwtToken(req, res, next) {
    if (req.headers.authorization) {
        const tokenParts = req.headers.authorization
            .split('.');

        const signature = crypto
            .createHmac('SHA256', SECRET_KEY)
            .update(`${tokenParts[0]}.${tokenParts[1]}`)
            .digest('base64');

        if (signature === tokenParts[2])
            req.user = JSON.parse(
                Buffer.from(tokenParts[1], 'base64')
                    .toString('utf8')
            );

        next();
    }

    next();
}

function createJwtToken(claims) {
    const header = Buffer.from(
        JSON.stringify({ alg: 'HS256', typ: 'jwt' })
    ).toString('base64');

    const payload = Buffer.from(
        JSON.stringify(claims)
    ).toString('base64');

    const signature = crypto
        .createHmac('SHA256', SECRET_KEY)
        .update(`${header}.${payload}`)
        .digest('base64');

    return `${header}.${payload}.${signature}`;
}