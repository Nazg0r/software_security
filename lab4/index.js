require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const { auth, InvalidRequestError} = require('express-oauth2-jwt-bearer');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const AUDIENCE = 'http://testapi.com'
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CLIENT_ID = process.env.CLIENT_ID;
const AUTH_DOMAIN = process.env.AUTH_DOMAIN;
const CONNECTION = process.env.CONNECTION;

const checkJwt = auth({
    audience: AUDIENCE,
    issuerBaseURL: `https://${AUTH_DOMAIN}`,
});

app.get('/', checkJwt, async (req, res) => {
    const token = req.get('Authorization').split(' ')[1];
    const payload = getJsonPayloadFromToken(token);
    const userInfo = await getUserInfoById(payload.sub);

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
                refresh_token: authResult.refresh_token
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
            refresh_token: newTokens.refresh_token
        })
    } catch (err) {
        res.status(400).send({error: err.message});
    }
})


app.use((err, req, res, next) => {
    if (err instanceof InvalidRequestError) {
        res.status(401).sendFile(path.join(__dirname + '/index.html'));
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

function getJsonPayloadFromToken(token) {
    const parts = token.split('.');
    return JSON.parse(base64UrlDecode(parts[1]));
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    const decoded = atob(str);
    return decodeURIComponent(
        decoded.split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')
    );
}