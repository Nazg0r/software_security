require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require("node:fs");
const jwt = require('jsonwebtoken');
const jose = require('jose')
const jwksClient = require('jwks-rsa');

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUDIENCE = 'http://testapi.com'
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const AUTH_DOMAIN = process.env.AUTH_DOMAIN;
const CONNECTION = process.env.CONNECTION;

const client = jwksClient({
    jwksUri: `https://${AUTH_DOMAIN}/.well-known/jwks.json`
});

app.get('/', verifyJwtToken, async (req, res) => {
    const userInfo = await getUserInfoById(req.user.sub);

    return res.json({
        username: userInfo.name,
        logout: 'http://localhost:3000/logout'
    })
})

app.get('/logout', (req, res) => {
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    try{
        const authResult = await passwordGrantAuthorization(login, password);

        if (authResult) {
            res.json({
                access_token: authResult.access_token,
                refresh_token: authResult.refresh_token,
                expires_in: Math.round(new Date().getTime() / 1000) + authResult.expires_in
            });
        }
    }
    catch(err){
        res.status(401).send();
    }
});

app.post('/api/register', async (req, res) => {
    const {email, password} = req.body;

    try {
        const result = await registerNewUser(email, password);
        res.json(result);
    } catch (err) {
        res.status(400).send({error: err.message});
    }
})

app.post('/api/refresh', async (req, res) => {
    const refreshToken = req.body.refresh_token;

    try {
        const newTokens = await refreshAccessToken(refreshToken);

        res.json({
            access_token: newTokens.access_token,
            refresh_token: newTokens.refresh_token,
            expires_in: Math.round(new Date().getTime() / 1000) + newTokens.expires_in
        })
    } catch (err) {
        res.status(400).send({error: err.message});
    }
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

async function passwordGrantAuthorization(username, password) {
    const response = await fetch(`https://${AUTH_DOMAIN}/oauth/token`, {
        method: 'POST',
        body: JSON.stringify({
            grant_type: 'password',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            connection: CONNECTION,
            scope: 'openid offline_access',
            audience: AUDIENCE,
            username: username,
            password: password,
        }),
        headers: {
            "Content-type": 'application/json',
        }
    });
    return await response.json();
}

async function registerNewUser(email, password) {
    const username = email.split('@')[0];
    const accessToken = await getManagementToken();

    const response = await fetch(`https://${AUTH_DOMAIN}/api/v2/users`, {
        method: 'POST',
        body: JSON.stringify({
            email: email,
            password: password,
            connection: CONNECTION,
            name: username,
            nickname: username
        }),
        headers: {
            "Content-type": 'application/json',
            "Authorization": `Bearer ${accessToken}`,
        }
    })

    return await response.json();
}

async function refreshAccessToken(refreshToken) {
    const response = await fetch(`https://${AUTH_DOMAIN}/oauth/token`, {
        method: 'POST',
        body: JSON.stringify({
            grant_type: 'refresh_token',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            refresh_token: refreshToken,
        }),
        headers: {
            "Content-type": 'application/json',
        }
    });

    return await response.json();
}

async function getManagementToken(){
    const response = await fetch(`https://${AUTH_DOMAIN}/oauth/token`, {
        method: 'POST',
        body: JSON.stringify({
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            audience: 'https://dev-xshvj0rtrouqyi18.us.auth0.com/api/v2/',
            client_secret: CLIENT_SECRET,
        }),
        headers: {
            "Content-type": 'application/json',
        }
    })

    const resJson = await response.json();
    return resJson.access_token;
}

async function getUserInfoById(id) {
    const accessToken = await getManagementToken();

    const response = await fetch(`https://${AUTH_DOMAIN}/api/v2/users/${id}`, {
        method: 'GET',
        headers: {
            "Authorization": `Bearer ${accessToken}`,
        }
    })

    return await response.json();
}

async function verifyJwtToken(req, res, next) {
    try {
        const authHeader = req.get("Authorization");
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            res.status(401).sendFile(path.join(__dirname + '/index.html'));
            return;
        }

        const jwe = authHeader.split(" ")[1];
        const token = await decodeJweToken(jwe);

        jwt.verify(token, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
            if (err) {
                return res.status(401).sendFile(path.join(__dirname + '/index.html'));
            }
            req.user = decoded;
            next();
        });
    } catch (err) {
        next(err);
    }
}

function getKey(header, callback){
    client.getSigningKey(header.kid, function(err, key) {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
}

async function decodeJweToken(token) {
    const header = JSON.parse(
        Buffer.from(
            token.split('.')[0],
            "base64")
            .toString("utf8"));

    const alg = header.alg;
    const cert = fs.readFileSync(path.join(__dirname + '/certs/jwe.pem'), 'utf8');
    const privateKey = await jose.importPKCS8(cert, alg);
    const {plaintext} = await jose.compactDecrypt(token, privateKey);
    return Buffer.from(plaintext).toString('utf8');
}