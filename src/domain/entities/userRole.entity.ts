import { Entity, Column } from 'typeorm';

@Entity()
export class IdentityUserRole {

    @Column()
    userId: string;

    @Column()
    roleId: string;
 
    constructor(userId: string, roleId: string) {
        this.userId = userId;
        this.roleId = roleId; 
    }
}