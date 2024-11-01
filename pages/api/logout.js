import { setCookie } from '../../lib/cookies';

export default function handler(req, res) {
    // Clear the authToken cookie
    setCookie(res, 'authToken', '', { maxAge: 0, httpOnly: true, secure: true, sameSite: 'strict' });
    res.status(200).json({ success: true, message: 'Logged out successfully' });
}