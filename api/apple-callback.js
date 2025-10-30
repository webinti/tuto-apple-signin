// api/apple-callback.js

export default async function handler(req, res) {
  // On n'accepte que les POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Apple envoie les données dans req.body
    const { code, id_token, state, user } = req.body;

    // Vérifier que le code est présent
    if (!code) {
      return res.status(400).json({ error: 'Missing authorization code' });
    }

    // Construire l'URL de redirection vers Bubble
    const bubbleCallbackUrl = 'https://tuto-apple-signin.bubbleapps.io/version-test/apple-callback';
    
    // Créer les paramètres à envoyer à Bubble
    const params = new URLSearchParams({
      code: code,
      state: state || '',
    });

    // Ajouter id_token s'il existe
    if (id_token) {
      params.append('id_token', id_token);
    }

    // Ajouter user s'il existe
    if (user) {
      params.append('user', user);
    }

    // Rediriger vers Bubble avec les données
    const redirectUrl = `${bubbleCallbackUrl}?${params.toString()}`;
    
    // Redirection HTML (plus fiable que res.redirect pour form_post)
    return res.status(200).send(`
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>Redirecting...</title>
        </head>
        <body>
          <p>Redirecting to your app...</p>
          <script>
            window.location.href = "${redirectUrl}";
          </script>
        </body>
      </html>
    `);

  } catch (error) {
    console.error('Error in Apple callback:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      details: error.message 
    });
  }
}
