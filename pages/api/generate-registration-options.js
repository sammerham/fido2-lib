import { setCookie } from '../../lib/cookies';
import { signJwtToken } from '../../lib/jwt';
import { nanoid } from 'nanoid';
import fido2 from '../../lib/fido2';
import base64url from 'base64url';


export default async function handler(req, res) {
    const userId = nanoid();

    // Generate WebAuthn registration options
    const registrationOptions = await fido2.attestationOptions();
    registrationOptions.challenge = base64url(Buffer.from(registrationOptions.challenge));
    const challenge = registrationOptions.challenge;
    registrationOptions.user = {
        id: base64url(Buffer.from(userId)),
        name: `Iden2User-${userId}`,
        displayName: `Iden2User-${userId}`,
    };

    // Create a JWT containing the userId with a 1-minute expiration
    const token = signJwtToken({ userId, challenge }, { expiresIn: '1m' });
    setCookie(res, 'authToken', token, { maxAge: 60 });

    res.status(200).json(registrationOptions);
}
