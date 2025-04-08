import { Column, Entity } from "typeorm";
import { IdentityRole } from "typeorm-identity/domain";

export enum RoleType {
    System = 'System',
    Regular = 'Regular'
}

@Entity()
export class ApplicationRole extends IdentityRole<string>{
    
    @Column({
        type: 'enum',
        enum: RoleType,
        default: RoleType.Regular,
    })
    type: RoleType;
}