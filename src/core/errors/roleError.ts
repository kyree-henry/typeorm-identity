import { BadRequestError, NotFoundError } from "./app.error";

  
export class RoleAlreadyExistsError extends BadRequestError {
    constructor(roleName: string) {
        super(`A role with the name "${roleName}" already exists.`);
        this.name = 'RoleAlreadyExistsError';
    }
}

export class RoleNotFoundError extends NotFoundError {
    constructor(name: string, id: string = '') {
        if (name) {
            super(`Role with name ${name} could not be found!`);
        } else {
            super(`Role with id ${id} could not be found!`);
        }

        this.name = 'RoleNotFoundError';
    }
}