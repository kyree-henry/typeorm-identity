export class AppError extends Error {

    statusCode: number;
    isOperational: boolean;
    errors: any;

    constructor(message: string, statusCode: number, error: any = {}) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;
        this.errors = error;
        Error.captureStackTrace(this, this.constructor);
    }
}

export class BadRequestError extends AppError {
    constructor(message: string, errors: any = {}) {
        super(message, 400, errors);
    }
 }

 export class NotFoundError extends AppError {
    constructor(message: string, errors: any = {}) {
        super(message, 404, errors);
    }
 }