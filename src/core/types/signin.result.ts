export class SignInResult {

    public succeeded: boolean;
    public isLockedOut: boolean;
    public isNotAllowed: boolean;
    public requiresTwoFactor: boolean;

    private constructor(
        succeeded: boolean,
        isLockedOut: boolean,
        isNotAllowed: boolean,
        requiresTwoFactor: boolean
    ) {
        this.succeeded = succeeded;
        this.isLockedOut = isLockedOut;
        this.isNotAllowed = isNotAllowed;
        this.requiresTwoFactor = requiresTwoFactor;
    }

    public static Success = new SignInResult(true, false, false, false);

    public static Failed = new SignInResult(false, false, false, false);

    public static LockedOut = new SignInResult(false, true, false, false);

    public static NotAllowed = new SignInResult(false, false, true, false);

    public static TwoFactorRequired = new SignInResult(false, false, false, true);

    public toString(): string {
        return this.isLockedOut ? "LockedOut" :
            this.isNotAllowed ? "NotAllowed" :
                this.requiresTwoFactor ? "RequiresTwoFactor" :
                    this.succeeded ? "Succeeded" : "Failed";
    }
}