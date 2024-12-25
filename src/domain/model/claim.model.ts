
export class Claim {
    claimValue: string;
    claimType: string;

    constructor(request: Partial<Claim> = {}) {
        Object.assign(this, request);
    }
}