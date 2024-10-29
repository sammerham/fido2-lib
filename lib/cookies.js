// lib/cookies.js
import { serialize, parse } from 'cookie';

// Set a cookie
export function setCookie(res, name, value, options = {}) {
  const cookie = serialize(name, value, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: options.maxAge || 60 * 60 * 24, // 1 day by default
    path: '/',
    ...options,
  });

  res.setHeader('Set-Cookie', cookie);
}

// Parse cookies from request
export function getCookies(req) {
  return parse(req.headers.cookie || '');
}
