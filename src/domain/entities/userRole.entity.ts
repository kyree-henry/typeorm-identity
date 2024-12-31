import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity({ name: 'UserRoles', schema: 'identity' })
export class IdentityUserRole {

    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    userId: string;

    @Column()
    roleId: string;

    constructor(userId: string, roleId: string) {
        this.userId = userId;
        this.roleId = roleId;
    }
}