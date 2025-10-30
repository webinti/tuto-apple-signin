const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

module.exports = async (req, res) => {
  // Configuration CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Gestion du preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // Récupération des variables d'environnement
    const privateKey = process.env.APPLE_PRIVATE_KEY.replace(/\\n/g, '\n');
    const teamId = process.env.APPLE_TEAM_ID;
    const keyId = process.env.APPLE_KEY_ID;
    const clientId = process.env.APPLE_CLIENT_ID;
    const redirectUri = process.env.APPLE_REDIRECT_URI;

    // Vérification de la configuration
    if (!privateKey || !teamId || !keyId || !clientId || !redirectUri) {
      return res.status(500).json({ 
        error: 'Missing configuration',
        details: {
          hasPrivateKey: !!privateKey,
          hasTeamId: !!teamId,
          hasKeyId: !!keyId,
          hasClientId: !!clientId,
          hasRedirectUri: !!redirectUri
        }
      });
    }

    // Récupération du code depuis le body
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ 
        error: 'Missing authorization code' 
      });
    }

    // 1. Génération du client_secret (JWT)
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

    // 2. Échange du code avec Apple
    const tokenResponse = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri
      })
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Apple token error:', errorText);
      return res.status(tokenResponse.status).json({ 
        error: 'Failed to exchange code with Apple',
        details: errorText
      });
    }

    const data = await tokenResponse.json();

    // 3. Décodage de l'id_token
    const decoded = jwt.decode(data.id_token);

    if (!decoded) {
      return res.status(500).json({ 
        error: 'Failed to decode id_token' 
      });
    }

    // 4. Retour des données formatées
    res.status(200).json({
      access_token: data.access_token,
      token_type: data.token_type,
      expires_in: data.expires_in,
      refresh_token: data.refresh_token,
      id_token: data.id_token,
      email: decoded.email || '',
      apple_user_id: decoded.sub,
      email_verified: decoded.email_verified === 'true',
      is_private_email: decoded.is_private_email === 'true'
    });

  } catch (error) {
    console.error('Error in exchange-code:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};
