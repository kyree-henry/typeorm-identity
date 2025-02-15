import { IdentityUser } from 'typeorm-identity/domain';
export declare enum UserType {
    Admin = "Admin",
    User = "User",
    Guest = "Guest"
}
export declare class ApplicationUser extends IdentityUser<number> {
    gender?: string;
    type: UserType;
}
//# sourceMappingURL=user.entity.d.ts.map