import { BadRequestError } from "./app.error";

export class InvalidCredentialsError extends BadRequestError {
    constructor() {
        super('The provided credentials are incorrect.');
        this.name = 'InvalidCredentialsError';
    }
}

export class PasswordReuseError extends BadRequestError {
    constructor() {
        super('The new password must differ from the current password.');
        this.name = 'PasswordReuseError';
    }
}
