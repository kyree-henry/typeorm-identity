
export class Claim {
    claimValue: string;
    claimType: string;

    constructor(type: string, value: string ) {
        this.claimType = type;
        this.claimValue = value;
     }
}