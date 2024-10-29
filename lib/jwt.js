// lib/jwt.js
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'iden2_jwt_secret'; 

// Sign a new JWT token
export function signJwtToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' }); // Token valid for 1 day
}

// Verify an existing JWT token
export function verifyJwtToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    console.error('JWT verification failed:', error);
    return null;
  }
}
