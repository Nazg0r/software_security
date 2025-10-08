require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();
const port = 3000;
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

const AUDIENCE = 'http://testapi.com'
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const AUTH_DOMAIN = process.env.AUTH_DOMAIN;
const CONNECTION = process.env.CONNECTION;
const LOGIN_REDIRECT_URL = process.env.LOGIN_REDIRECT_URL;
const LOGOUT_REDIRECT_URL = process.env.LOGOUT_REDIRECT_URL;

const client = jwksClient({
    jwksUri: `https://${AUTH_DOMAIN}/.well-known/jwks.json`
});

const authLoginParams = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: LOGIN_REDIRECT_URL,
    scope: 'openid email profile offline_access',
    audience: AUDIENCE
});

const authLogoutParams = new URLSearchParams({
    client_id: CLIENT_ID,
    returnTo: LOGOUT_REDIRECT_URL
})

app.get('/', verifyJwtToken, async (req, res) => {
    res.format({
        html: ()=> res.status(200).sendFile(path.join(__dirname + '/index.html')),
        json: async () => {
            const userInfo = await getUserInfoById(req.user.sub);

            return res.json({
                username: userInfo.name,
                logout: 'http://localhost:3000/logout'
            })
        }
    });
})

app.get('/api/logout', (req, res) => {
    res.redirect(`https://${AUTH_DOMAIN}/v2/logout?${authLogoutParams.toString()}`);
});

app.get('/api/login', async (req, res) => {
    res.redirect(`https://${AUTH_DOMAIN}/authorize?${authLoginParams.toString()}`);
});

app.get('/api/login/callback', async (req, res) => {
    const code = req.query.code;
    const tokens = await exchangeCodeToTokens(code);
    res.render('preprocessor.ejs', tokens);
})

app.post('/api/refresh', async (req, res) => {
    const refreshToken = req.body.refresh_token;
    try {
        const newTokens = await refreshAccessToken(refreshToken);

        res.json({
            access_token: newTokens.access_token,
            refresh_token: newTokens.refresh_token
        })
    } catch (err) {
        res.status(400).send({error: err.message});
    }
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})

async function exchangeCodeToTokens(code) {
    const response = await fetch(`https://${AUTH_DOMAIN}/oauth/token`, {
        method: 'POST',
        body: JSON.stringify({
            grant_type: 'authorization_code',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            code: code,
            redirect_uri: LOGIN_REDIRECT_URL,
        }),
        headers: {
            "Content-type": 'application/json',
        }
    });
    return response.json();
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

async function verifyJwtToken(req, res, next) {
    try {
        let accessToken = req.query.access_token;
        if (!accessToken) {
            const authHeader = req.get("Authorization");

            if (!authHeader || !authHeader.startsWith("Bearer ")) {
                res.status(401).redirect('/api/login');
                return;
            }
            accessToken = authHeader.split(" ")[1];
        }

        jwt.verify(accessToken, getKey, { algorithms: ["RS256"] }, (err, decoded) => {
            if (err) {
                return res.status(401).redirect('/api/login');
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