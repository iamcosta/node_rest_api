const jwt = require('jsonwebtoken');
const authConfig = require('../config/auth');

module.exports = (req, res, next) => {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).send({ error: 'Token not provided' });
    }

    const tokenParts = authHeader.split(' ');

    if (!tokenParts.length === 2) {
        return res.status(401).send({ error: 'Token error' });
    }

    const [ scheme, token ] = tokenParts;

    if (!/^Bearer$/i.test(scheme)) {
        return res.status(401).send({ error: 'Token unformatted' });
    }

    jwt.verify(token, authConfig.secret, (err, decode) => {
        if (err) return res.status(401).send({ error: 'Invalid token' });

        req.userId = decode.id;
        return next();
    });

}