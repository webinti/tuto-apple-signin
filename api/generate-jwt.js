const jwt = require('jsonwebtoken');

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

    // Vérification
    if (!privateKey || !teamId || !keyId || !clientId) {
      return res.status(500).json({ 
        error: 'Missing configuration',
        details: {
          hasPrivateKey: !!privateKey,
          hasTeamId: !!teamId,
          hasKeyId: !!keyId,
          hasClientId: !!clientId
        }
      });
    }

    // Création du JWT
    const now = Math.floor(Date.now() / 1000);
    
    const claims = {
      iss: teamId,
      iat: now,
      exp: now + 3600,
      aud: 'https://appleid.apple.com',
      sub: clientId
    };

    const token = jwt.sign(claims, privateKey, {
      algorithm: 'ES256',
      header: {
        alg: 'ES256',
        kid: keyId
      }
    });

    // Retour du token
    res.status(200).json({
      client_secret: token,
      expires_in: 3600
    });

  } catch (error) {
    console.error('Error generating JWT:', error);
    res.status(500).json({ 
      error: 'Failed to generate JWT',
      message: error.message 
    });
  }
};
