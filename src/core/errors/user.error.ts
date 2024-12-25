import { BadRequestError } from "./app.error";

export class UserAlreadyExistsError extends BadRequestError {
    constructor(email: string);
    constructor(id: string | number);
    constructor(emailOrId: string, id: string = '') {
        const message = emailOrId
            ? `A user with the email "${emailOrId}" already exists.`
            : `A user with the ID "${id}" already exists.`;
        super(message);
        this.name = 'UserAlreadyExistsError';
    }
}