const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
  // Configuration CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Gestion du preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // Récupération du code depuis la requête
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    // Génération du client_secret
    const privateKey = process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n');
    const teamId = process.env.APPLE_TEAM_ID;
    const keyId = process.env.APPLE_KEY_ID;
    const clientId = process.env.APPLE_CLIENT_ID;

    const now = Math.floor(Date.now() / 1000);
    
    const claims = {
      iss: teamId,
      iat: now,
      exp: now + 3600,
      aud: 'https://appleid.apple.com',
      sub: clientId
    };

    const clientSecret = jwt.sign(claims, privateKey, {
      algorithm: 'ES256',
      header: {
        alg: 'ES256',
        kid: keyId
      }
    });

    // Appel à l'API Apple pour échanger le code
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: process.env.APPLE_REDIRECT_URI
    });

    const response = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: 'Apple token exchange failed',
        details: data
      });
    }

    // Décoder l'id_token pour extraire les informations utilisateur
    const idToken = data.id_token;
    const decoded = jwt.decode(idToken);

    // Retourner les données formatées
    res.status(200).json({
      access_token: data.access_token,
      token_type: data.token_type,
      expires_in: data.expires_in,
      refresh_token: data.refresh_token,
      id_token: data.id_token,
      email: decoded.email,
      apple_user_id: decoded.sub,
      email_verified: decoded.email_verified === 'true',
      is_private_email: decoded.is_private_email === 'true'
    });

  } catch (error) {
    console.error('Error exchanging code:', error);
    res.status(500).json({ 
      error: 'Failed to exchange code',
      message: error.message 
    });
  }
};
