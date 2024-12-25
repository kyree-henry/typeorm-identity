import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

export function generateTimestampUUID() {
    const timestamp = Date.now().toString();  
    const randomUUID = uuidv4().replace(/-/g, ''); 
    return timestamp + randomUUID;  
  }

  export function generateSecurityStamp() {
    return crypto.randomBytes(32).toString('hex');  
  }