import { IdentityRole } from "typeorm-identity/domain";
export declare enum RoleType {
    System = "System",
    Regular = "Regular"
}
export declare class ApplicationRole extends IdentityRole<string> {
    type: RoleType;
}
//# sourceMappingURL=role.entity.d.ts.map