
export class IdentityResult {
    succeeded: boolean = this.errors !== null ? true : false;
    errors?: IdentityError[];

    public ToString(): string {
        if (this.succeeded) {
            return "Succeeded";
        } else {
            const errorMessages = this.errors.map(error => `${error.code}: ${error.description}`).join(", ");
            return `Failed: ${errorMessages}`;
        }
    }

    public static Success(): IdentityResult {
        return new IdentityResult(true);
    }

    public static Failed(...errors: IdentityError[]): IdentityResult {
        return new IdentityResult(false, errors);
    }

    private constructor(succeeded: boolean, errors: IdentityError[] = []) {
        this.succeeded = succeeded;
        this.errors = errors;
    }
}

export class IdentityError {
    code: string;
    description: string;

    constructor(code: string, description: string) {
        this.code = code;
        this.description = description;
    }
}