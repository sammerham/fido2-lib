import fido2 from '../../lib/fido2';
import { setCookie } from '../../lib/cookies';
import { signJwtToken } from '../../lib/jwt';


function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    return Buffer.from(bytes).toString('base64');
}

export default async function handler(req, res) {
    try {
        // Step 1: Generate authentication options without user ID
        const authenticationOptions = await fido2.assertionOptions({
            userVerification: "required",
        });

        // Check if the challenge is present
        const challenge = authenticationOptions.challenge;
   
        if (!challenge || !(challenge instanceof ArrayBuffer)) {
            throw new Error("Challenge is missing or improperly formatted");
        }

        //convert to base64 before signing
        const base64Challenge = arrayBufferToBase64(challenge);
        authenticationOptions.challenge = base64Challenge;
        // Step 2: Store challenge in a JWT and set it in an HTTP-only cookie
        const token = signJwtToken({ challenge: base64Challenge }, { expiresIn: '1m' });
        
        setCookie(res, 'authToken', token, {
            maxAge: 60,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });

        // Step 3: Send options back to the client
        res.status(200).json(authenticationOptions);
    } catch (error) {
        console.error('Error generating authentication options:', error.message);
        res.status(500).json({ error: 'Failed to generate authentication options' });
    }
}
