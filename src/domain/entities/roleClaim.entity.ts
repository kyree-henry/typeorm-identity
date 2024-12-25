import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";
import { IdentityRole } from "./role.entity"; 

@Entity()
export class IdentityRoleClaim {

    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column()
    roleId: string;

    @Column()
    claimType: string;

    @Column()
    claimValue: string;

    @ManyToOne(() => IdentityRole, role => role.roleClaims)
    role!: IdentityRole<number | string>[];

    constructor(request: Partial<IdentityRoleClaim> = {}) {
        Object.assign(this, request);
    }

}