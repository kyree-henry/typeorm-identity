 
 export class PasswordOptions {
    requiredLength: number = 6;
    requireDigit: boolean = false;
    requireUppercase: boolean = false;
    requireLowercase: boolean = false;
  }
  
  export class LockoutOptions {
    maxFailedAccessAttempts: number = 5;
    defaultLockoutTimeSpan: number = 30; // In minutes
    allowedForNewUsers: boolean = true;
  }
  
  export class SignInOptions {
    requireConfirmedEmail: boolean = true;
    requireConfirmedPhoneNumber: boolean = false;
  }
  
  export class TokenOptions {
    tokenExpirationTime: number = 3600; // 1 hour in seconds
  }
  
  export class UserOptions {
    allowedUsernameCharacters: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@.-/_";
  }
  
  export class IdentityOptions {
    user: UserOptions = new UserOptions();
    password: PasswordOptions = new PasswordOptions();
    lockout: LockoutOptions = new LockoutOptions();
    signIn: SignInOptions = new SignInOptions();
    tokens: TokenOptions = new TokenOptions();
  }
  